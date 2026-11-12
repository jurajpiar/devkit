package dockerfilter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCanonicalPaths(t *testing.T) {
	for _, c := range []struct{ raw, prefix, rest string }{
		{"/_ping", "", "/_ping"},
		{"/v1.44/containers/create", "/v1.44", "/containers/create"},
		{"/v9.99/containers/create", "/v9.99", "/containers/create"},
		{"/v1.52/images/registry.example.com:5000/a/b:tag/json", "/v1.52", "/images/registry.example.com:5000/a/b:tag/json"},
		{"/images/busybox%3A1.36/json", "", "/images/busybox:1.36/json"},
		{"/images/a@sha256%3Aabc/json", "", "/images/a@sha256:abc/json"},
		{"/v1.44", "/v1.44", "/"},
		{"/v1/containers/json", "", "/v1/containers/json"}, // not a version the filter strips: matches nothing
	} {
		p, r, err := canonical(c.raw)
		if err != nil || p != c.prefix || r != c.rest {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q)", c.raw, p, r, err, c.prefix, c.rest)
		}
	}
	for _, raw := range []string{
		"", "containers/create", "//containers/create", "/containers/create/", "/v1.44//containers/create",
		"/v1.44/containers/../containers/create", "/v1.44/images/../containers/create", "/_ping/../containers/create",
		"/./containers/create", "/containers/.", "/%63ontainers/create", "/containers%2Fcreate", "/containers%2fcreate",
		"/v1.44/containers/%2e%2e/containers/create", "/%2e/containers", "/containers/create%00", "/containers/cr\x00eate",
		"/containers/caf\xc3\xa9/json", "/containers/a b/json", "/containers/a\\b/json", "/containers/a#b/json",
		"/containers/a%", "/containers/a%3", "/containers/a%zz/json", "/containers/a?b", "/containers/a;b/json",
		"http://docker/containers/create", "*",
	} {
		if p, r, err := canonical(raw); err == nil {
			t.Errorf("%q should be refused, got (%q, %q)", raw, p, r)
		}
	}
}

func TestEndpointTable(t *testing.T) {
	h := newHarness(t)
	// docker cp looks at the container first: one with no bind mount.
	h.daemon.inspect = `{"Id":"` + strings.Repeat("ab", 32) + `","HostConfig":{},"Mounts":[]}`
	allowed := []struct{ method, path string }{
		{"GET", "/_ping"}, {"HEAD", "/_ping"}, {"GET", "/v1.52/version"}, {"GET", "/info"}, {"GET", "/events"},
		{"GET", "/system/df"}, {"GET", "/containers/json"}, {"GET", "/containers/abc/json"}, {"GET", "/containers/abc/top"},
		{"GET", "/containers/abc/logs"}, {"GET", "/containers/abc/changes"}, {"GET", "/containers/abc/stats"},
		{"GET", "/containers/abc/export"}, {"GET", "/containers/abc/archive"}, {"HEAD", "/containers/abc/archive"},
		{"POST", "/containers/abc/stop"}, {"POST", "/containers/abc/kill"}, {"POST", "/containers/abc/pause"},
		{"POST", "/containers/abc/unpause"}, {"POST", "/containers/abc/wait"}, {"POST", "/containers/abc/rename"},
		{"POST", "/containers/abc/resize"}, {"POST", "/containers/abc/attach"}, {"DELETE", "/containers/abc"},
		{"POST", "/containers/prune"}, {"POST", "/exec/abc/resize"}, {"GET", "/exec/abc/json"},
		{"GET", "/images/json"}, {"GET", "/images/busybox/json"}, {"GET", "/images/reg.example:5000/a/b/c:1/json"},
		{"GET", "/images/a/b/history"}, {"GET", "/images/search"}, {"GET", "/images/get"}, {"GET", "/images/a/b/get"},
		{"POST", "/images/create"}, {"POST", "/images/a/b/tag"}, {"POST", "/images/a/b:1/push"},
		{"DELETE", "/images/a/b:1"}, {"DELETE", "/images/sha256:0123"}, {"POST", "/images/prune"},
		{"GET", "/distribution/docker.io/library/busybox:1.36/json"},
		{"POST", "/build/prune"}, {"POST", "/build/cancel"}, {"POST", "/session"}, {"POST", "/grpc"},
		{"GET", "/networks"}, {"GET", "/networks/abc"}, {"DELETE", "/networks/abc"}, {"POST", "/networks/prune"},
		{"GET", "/volumes"}, {"GET", "/volumes/v"}, {"DELETE", "/volumes/v"}, {"POST", "/volumes/prune"},
	}
	for _, c := range allowed {
		before := len(h.daemon.requests())
		if st, body := h.raw(t, c.method, c.path, ""); st == http.StatusForbidden {
			t.Errorf("%s %s should be allowed: %d %s", c.method, c.path, st, body)
		} else if r := h.daemon.requests(); len(r) <= before || r[len(r)-1].Method != c.method {
			t.Errorf("%s %s did not reach the daemon", c.method, c.path)
		}
	}
	refused := []struct{ method, path string }{
		{"GET", "/plugins"}, {"GET", "/v1.44/plugins"}, {"GET", "/plugins/privileges"}, {"POST", "/plugins/pull"},
		{"POST", "/swarm/init"}, {"GET", "/swarm"}, {"GET", "/services"}, {"GET", "/tasks"}, {"GET", "/nodes"},
		{"GET", "/secrets"}, {"GET", "/configs"}, {"POST", "/containers/abc/update"}, {"GET", "/containers/abc/attach/ws"},
		{"GET", "/containers/abc/checkpoints"}, {"POST", "/containers/abc/checkpoints"}, {"GET", "/no/such/endpoint"},
		{"PATCH", "/containers/json"}, {"CONNECT", "/"}, {"OPTIONS", "/_ping"}, {"TRACE", "/_ping"},
		{"POST", "/_ping"}, {"GET", "/images/busybox"}, {"POST", "/images/json"},
		{"GET", "/CONTAINERS/json"}, {"GET", "/Containers/json"}, {"GET", "/v1.44/v1.44/containers/json"},
		{"PUT", "/containers/abc/start"}, {"GET", "/containers/abc/start"}, {"GET", "/distribution/x"},
		{"POST", "/images/load/x"}, {"GET", "/session"}, {"POST", "/containers"}, {"GET", "/"},
	}
	for _, c := range refused {
		before := len(h.daemon.requests())
		st, body := h.raw(t, c.method, c.path, "")
		if st != http.StatusForbidden || !strings.Contains(body, `"message":"devkit: refused: `) {
			t.Errorf("%s %s should be refused by devkit: %d %s", c.method, c.path, st, body)
		}
		if len(h.daemon.requests()) != before {
			t.Errorf("%s %s reached the daemon", c.method, c.path)
		}
	}
}

func TestPathTricksNeverReachTheDaemon(t *testing.T) {
	h := newHarness(t)
	const priv = `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Privileged":true}}`
	for _, p := range []string{
		"/containers/create?name=x", "/v1.44/containers/create?name=x", "/v1.52/containers/create?name=x",
		"/v9.99/containers/create?name=x", "//containers/create?name=x", "/containers/create/?name=x",
		"/v1.44//containers/create?name=x", "/v1.44/containers/../containers/create?name=x",
		"/v1.44/images/../containers/create?name=x", "/_ping/../containers/create?name=x", "/%63ontainers/create?name=x",
		"/containers%2Fcreate?name=x", "/v1.44/containers/%2e%2e/containers/create?name=x", "/CONTAINERS/create?name=x",
		"/v1.44/containers/create?name=x&name=y", "/v1.44/containers/create?name=x;y",
	} {
		st, body := h.raw(t, "POST", p, priv)
		if st != http.StatusForbidden || !strings.Contains(body, "devkit") {
			t.Errorf("POST %s: %d %s", p, st, body)
		}
	}
	if n := len(h.daemon.requests()); n != 0 {
		t.Errorf("%d requests reached the daemon", n)
	}
}

func TestQueryParameters(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct {
		method, path string
		ok           bool
	}{
		{"GET", "/containers/json?all=1&filters=%7B%7D", true},
		{"GET", "/containers/json?all=1&all=0", false},
		{"GET", "/containers/json?frobnicate=1", false},
		{"GET", "/_ping?x=1", false},
		{"POST", "/images/create?fromImage=busybox&tag=1.36", true},
		{"GET", "/images/get?names=a&names=b", true},
		{"POST", "/build?t=a&t=b&extrahosts=x:1.2.3.4&extrahosts=y:1.2.3.5&networkmode=&cgroupparent=&rm=1&version=2", true},
		{"POST", "/build?networkmode=default", true},
		{"POST", "/build?networkmode=bridge", true},
		{"POST", "/build?networkmode=none", true},
		{"POST", "/build?networkmode=host", false},
		{"POST", "/build?networkmode=container:x", false},
		{"POST", "/build?cgroupparent=/x", false},
		{"POST", "/build?securityopt=seccomp%3Dunconfined", false},
		{"POST", "/build?isolation=hyperv", false},
		{"POST", "/build?dockerfile=a&dockerfile=b", false},
		{"POST", "/build?ulimits=%5B%5D&shmsize=0&memory=0&memswap=0&cpushares=0&cpusetcpus=&cpusetmems=&cpuperiod=0&cpuquota=0", true},
		{"POST", "/containers/abc/kill?signal=KILL&signal=TERM", false},
		{"POST", "/containers/abc/attach?stream=1&stdin=1&stdout=1&stderr=1&logs=0&detachKeys=ctrl-p", true},
		{"GET", "/system/df?type=image&type=container", true},
	} {
		st, body := h.raw(t, c.method, c.path, "")
		if (st != http.StatusForbidden) != c.ok {
			t.Errorf("%s %s: %d %s (want allowed=%v)", c.method, c.path, st, body, c.ok)
		}
	}
	// What reaches the daemon is the query as checked, re-encoded.
	h.raw(t, "GET", "/v1.52/containers/json?all=1&filters=%7B%22a%22%3A1%7D", "")
	if got := h.daemon.last(t).URI; got != "/v1.52/containers/json?all=1&filters=%7B%22a%22%3A1%7D" {
		t.Errorf("forwarded %q", got)
	}
}

func TestBodiesOnlyWhereTheyBelong(t *testing.T) {
	h := newHarness(t)
	if st, body := h.raw(t, "POST", "/containers/abc/stop", `{"x":1}`); st != http.StatusForbidden {
		t.Errorf("a body on stop: %d %s", st, body)
	}
	if st, body := h.raw(t, "POST", "/containers/abc/stop", "3\r\nabc\r\n0\r\n\r\n", "Transfer-Encoding: chunked"); st != http.StatusForbidden {
		t.Errorf("a chunked body on stop: %d %s", st, body)
	}
	if st, body := h.raw(t, "POST", "/containers/abc/stop", "", "Connection: Upgrade", "Upgrade: tcp"); st != http.StatusForbidden {
		t.Errorf("an upgrade on stop: %d %s", st, body)
	}
	if st, body := h.raw(t, "POST", "/commit?container=abc&repo=r", ""); st == http.StatusForbidden {
		t.Errorf("commit with no body: %d %s", st, body)
	}
	if st, body := h.raw(t, "POST", "/commit?container=abc", `{"Image":"x","Frobnicate":1}`); st != http.StatusForbidden {
		t.Errorf("commit with an unknown field: %d %s", st, body)
	}
	// A streamed body passes through as sent.
	h.raw(t, "POST", "/images/load", "not json at all")
	if got := h.daemon.last(t); string(got.Body) != "not json at all" {
		t.Errorf("load body: %q", got.Body)
	}
}

func TestHTTP10Refused(t *testing.T) {
	h := newHarness(t)
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /_ping HTTP/1.0\r\nHost: docker\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HTTP/1.0: %d", resp.StatusCode)
	}
}

func TestRefusalsAreLogged(t *testing.T) {
	h := newHarness(t)
	h.raw(t, "POST", "/v1.44/containers/create?name=x", `{"Image":"secret-image","HostConfig":{"Privileged":true}}`)
	h.raw(t, "GET", "/plugins", "")
	time.Sleep(50 * time.Millisecond)
	lines := strings.Split(strings.TrimSpace(h.logs.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line per refusal:\n%s", h.logs)
	}
	if !strings.HasPrefix(lines[0], "refused POST /v1.44/containers/create: ") || !strings.Contains(lines[0], "HostConfig.Privileged") {
		t.Errorf("log line: %q", lines[0])
	}
	if strings.Contains(h.logs.String(), "secret-image") {
		t.Error("a request body reached the log")
	}
}

func TestDaemonDownIs502(t *testing.T) {
	dir := sockDir(t)
	cfg := testConfig(dir) // no daemon listens there
	f := New(cfg, log.New(io.Discard, "", 0))
	sock := filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(ln)
	defer srv.Close()
	h := &harness{sock: sock}
	for _, c := range []struct{ method, path string }{{"GET", "/info"}, {"POST", "/containers/abc/attach?stream=1"}} {
		hd := []string{}
		if strings.Contains(c.path, "attach") {
			hd = []string{"Connection: Upgrade", "Upgrade: tcp"}
		}
		st, body := h.raw(t, c.method, c.path, "", hd...)
		if st != http.StatusBadGateway || !strings.Contains(body, "devkit: the Docker daemon is not answering") {
			t.Errorf("%s %s with no daemon: %d %s", c.method, c.path, st, body)
		}
	}
}

// A container stored with a runtime or a privilege the filter would refuse
// today (made before the filter, or under another setting) does not start;
// one that passes starts by its full ID.
func TestStartChecksTheStoredContainer(t *testing.T) {
	h := newHarness(t)
	id := strings.Repeat("ab", 32)
	for _, c := range []struct {
		inspect string
		ok      bool
	}{
		{`{"Id":"` + id + `","HostConfig":{"Runtime":"devkit-runc","Privileged":false}}`, true},
		{`{"Id":"` + id + `","HostConfig":{"Runtime":"runc"}}`, false},
		{`{"Id":"` + id + `","HostConfig":{"Runtime":"devkit-runc","Privileged":true}}`, false},
		{`{"Id":"../x","HostConfig":{}}`, false},
	} {
		h.daemon.mu.Lock()
		h.daemon.inspect = c.inspect
		h.daemon.mu.Unlock()
		st, body := h.raw(t, "POST", "/v1.52/containers/web/start", "")
		if (st != http.StatusForbidden) != c.ok {
			t.Errorf("%s: %d %s", c.inspect, st, body)
		}
		if c.ok {
			if got := h.daemon.last(t).URI; got != "/v1.52/containers/"+id+"/start" {
				t.Errorf("the start should go to the full ID: %s", got)
			}
		}
	}
}

// pipeline sends a request that upgrades with payload in the same write,
// half-closes, and returns what came back after the 101.
func pipeline(t *testing.T, sock, req string, payload []byte) (*http.Response, []byte) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	go func() {
		c.Write(append([]byte(req), payload...))
		c.(*net.UnixConn).CloseWrite()
	}()
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("after the upgrade: %v", err)
	}
	return resp, rest
}

// An upgraded stream carries bytes sent right behind the request headers,
// and the client's half-close reaches the daemon as end of input while the
// daemon's output still comes back: echo hi | docker run -i cat.
func TestUpgradeCarriesEarlyBytesAndHalfClose(t *testing.T) {
	h := newHarness(t)
	h.daemon.upgraded = func(c net.Conn, br *bufio.Reader) {
		in, _ := io.ReadAll(br) // until the client's half-close
		time.Sleep(20 * time.Millisecond)
		c.Write([]byte("echo:"))
		c.Write(in)
		c.Write([]byte(":end"))
	}
	large := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	for name, payload := range map[string][]byte{"small": []byte("piped-ok\n"), "large": large, "none": nil} {
		for _, path := range []string{"/v1.52/containers/abc/attach?stream=1&stdin=1&stdout=1", "/v1.52/session", "/grpc"} {
			up := "tcp"
			if !strings.Contains(path, "attach") {
				up = "h2c"
			}
			req := "POST " + path + " HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: " + up + "\r\n\r\n"
			resp, got := pipeline(t, h.sock, req, payload)
			if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != up {
				t.Fatalf("%s %s: %s %v", name, path, resp.Status, resp.Header)
			}
			want := append(append([]byte("echo:"), payload...), ":end"...)
			if !bytes.Equal(got, want) {
				t.Errorf("%s %s: got %d bytes, want %d", name, path, len(got), len(want))
			}
		}
	}
}

// The daemon may send its first stream bytes in the same write as the 101.
func TestUpgradeCarriesTheDaemonsEarlyBytes(t *testing.T) {
	h := newHarness(t)
	// A daemon that writes the 101 and its banner at once, then closes.
	ln, err := net.Listen("unix", filepath.Join(h.dir, "banner.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		http.ReadRequest(bufio.NewReader(c))
		io.WriteString(c, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nbanner-bytes")
	}()
	h.cfg.DaemonSocket = filepath.Join(h.dir, "banner.sock")
	resp, got := pipeline(t, h.sock, "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n", nil)
	if resp.StatusCode != 101 || string(got) != "banner-bytes" {
		t.Errorf("got %s %q", resp.Status, got)
	}
}

// A refused or failed attach comes back as an ordinary response.
func TestUpgradeAnsweredWithoutSwitching(t *testing.T) {
	h := newHarness(t)
	st, body := h.raw(t, "POST", "/containers/abc/attach?stream=1", "", "Connection: Upgrade", "Upgrade: tcp")
	if st != http.StatusCreated || strings.TrimSpace(body) != "{}" {
		t.Errorf("got %d %q", st, body)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, fmt.Sprintf("c%d.json", len(s)))
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	if _, err := LoadConfig(write(`{"daemon_socket":"/d.sock","workspace":"/home/u/workspace","runtimes":["devkit-runc"],"capabilities":["IPC_LOCK"]}`)); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{
		`{"daemon_socket":"d.sock","workspace":"/home/u/workspace"}`,
		`{"daemon_socket":"/d.sock","workspace":"/"}`,
		`{"daemon_socket":"/d.sock","workspace":"/home/u/../workspace"}`,
		`{"daemon_socket":"/d.sock","workspace":"/w","runtimes":["runc"]}`,
		`{"daemon_socket":"/d.sock","workspace":"/w","runtimes":["io.containerd.runc.v2"]}`,
		`{"daemon_socket":"/d.sock","workspace":"/w","capabilities":["ALL"]}`,
		`{"daemon_socket":"/d.sock","workspace":"/w","capabilities":["net_raw"]}`,
		`{"daemon_socket":"/d.sock","workspace":"/w","extra":1}`,
	} {
		if _, err := LoadConfig(write(bad)); err == nil {
			t.Errorf("%s should not load", bad)
		}
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing config should not load")
	}
}

func TestEmpty(t *testing.T) {
	f := false
	z := int64(0)
	for _, v := range []any{nil, false, 0, "", []string{}, []string(nil), map[string]string{}, &f, &z, (*bool)(nil), [2]uint{}, struct{ A []int }{}} {
		if !empty(reflect.ValueOf(v)) {
			t.Errorf("%#v should be empty", v)
		}
	}
	tr := true
	for _, v := range []any{true, 1, "x", []string{""}, map[string]string{"": ""}, &tr, [2]uint{0, 1}} {
		if empty(reflect.ValueOf(v)) {
			t.Errorf("%#v should not be empty", v)
		}
	}
}

func TestStrSlice(t *testing.T) {
	for in, want := range map[string]StrSlice{`"a"`: {"a"}, `["a","b"]`: {"a", "b"}, `[]`: {}, `null`: nil} {
		var s StrSlice
		if err := json.Unmarshal([]byte(in), &s); err != nil || !reflect.DeepEqual(s, want) || (s == nil) != (want == nil) {
			t.Errorf("%s: %#v %v", in, s, err)
		}
	}
	var s StrSlice
	if err := json.Unmarshal([]byte(`1`), &s); err == nil {
		t.Error("a number is not a StrSlice")
	}
}
