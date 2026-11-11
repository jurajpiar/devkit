package dockerfilter

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sockDir is a short directory for Unix sockets: macOS limits their paths
// to 104 bytes, which t.TempDir often exceeds.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "df")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// received is one request as the fake daemon saw it.
type received struct {
	Method, URI string
	Header      http.Header
	Body        []byte
}

// fakeDaemon is a stand-in for the daemon's socket that records what it
// receives. It answers 101 to an upgrade on attach and exec start and
// then runs upgraded on the connection, and 201 with {} otherwise.
type fakeDaemon struct {
	sock     string
	mu       sync.Mutex
	got      []received
	upgraded func(c net.Conn, br *bufio.Reader)
	inspect  string // body for GET /containers/{id}/json
}

func newFakeDaemon(t *testing.T, dir string) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{sock: filepath.Join(dir, "daemon.sock")}
	ln, err := net.Listen("unix", d.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
	return d
}

func (d *fakeDaemon) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		d.mu.Lock()
		d.got = append(d.got, received{req.Method, req.RequestURI, req.Header, body})
		up, insp := d.upgraded, d.inspect
		d.mu.Unlock()
		if req.Header.Get("Upgrade") != "" && up != nil {
			fmt.Fprintf(c, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n", req.Header.Get("Upgrade"))
			up(c, br)
			return
		}
		if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/json") && strings.Contains(req.URL.Path, "/containers/") && insp != "" {
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(insp), insp)
			continue
		}
		if req.Method == "HEAD" {
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			continue
		}
		fmt.Fprintf(c, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}\n")
	}
}

func (d *fakeDaemon) requests() []received {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]received(nil), d.got...)
}

func (d *fakeDaemon) last(t *testing.T) received {
	t.Helper()
	r := d.requests()
	if len(r) == 0 {
		t.Fatal("the daemon received nothing")
	}
	return r[len(r)-1]
}

// harness is a filter on a socket of its own, in front of a fake daemon.
type harness struct {
	dir    string
	sock   string
	daemon *fakeDaemon
	logs   *bytes.Buffer
	cfg    *Config
	filter *Filter
}

// realDir is dir with its symlinks resolved, as provisioning writes the
// workspace's path (macOS's temporary directories are under a symlink).
func realDir(t *testing.T, dir string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testConfig(dir string) *Config {
	return &Config{
		DaemonSocket: filepath.Join(dir, "daemon.sock"),
		Workspace:    filepath.Join(dir, "ws"),
		Runtimes:     []string{"devkit-runc"},
		Capabilities: []string{"IPC_LOCK", "NET_BIND_SERVICE"},
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := sockDir(t)
	h := &harness{dir: dir, sock: filepath.Join(dir, "filter.sock"), logs: &bytes.Buffer{}, cfg: testConfig(dir)}
	h.cfg.Workspace = realDir(t, dir) + "/ws"
	if err := os.MkdirAll(h.cfg.Workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	h.daemon = newFakeDaemon(t, dir)
	h.filter = New(h.cfg, log.New(&syncWriter{w: h.logs}, "", 0))
	ln, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.filter, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return h
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// raw sends one request exactly as written, with the path as given, and
// returns the status and body.
func (h *harness) raw(t *testing.T, method, path, body string, headers ...string) (int, string) {
	t.Helper()
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: docker\r\n", method, path)
	for _, hd := range headers {
		b.WriteString(hd + "\r\n")
	}
	if body != "" && !strings.Contains(strings.Join(headers, "\n"), "Transfer-Encoding") {
		fmt.Fprintf(&b, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n" + body)
	// Written while the response is read: the filter may answer, and close,
	// before it has read a body it refuses.
	go io.WriteString(c, b.String())
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}
