// Package dockerfilter is devkit's Docker API filter: an HTTP proxy on a
// Unix socket, the only Docker socket the sandbox user can reach. It
// forwards a call to the daemon's own socket only when the call is in its
// table and its body validates, and answers everything else itself with
// 403 and a message the Docker client prints.
package dockerfilter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Filter is the API filter as an http.Handler.
type Filter struct {
	cfg       *Config
	log       *log.Logger
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

// New returns a filter that forwards to cfg.DaemonSocket.
func New(cfg *Config, logger *log.Logger) *Filter {
	f := &Filter{cfg: cfg, log: logger}
	f.transport = &http.Transport{
		DialContext:        f.dial,
		DisableCompression: true,
		MaxIdleConns:       16,
		IdleConnTimeout:    90 * time.Second,
	}
	f.proxy = &httputil.ReverseProxy{
		// The outgoing request is built in full by ServeHTTP.
		Rewrite:       func(*httputil.ProxyRequest) {},
		Transport:     f.transport,
		FlushInterval: -1, // logs, events and stats stream
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.daemonDown(w, r, err)
		},
	}
	return f
}

func (f *Filter) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", f.cfg.DaemonSocket)
}

// refusal is a request the filter answers itself.
type refusal struct {
	status int
	reason string
}

func (r *refusal) Error() string { return r.reason }

func refuse(format string, a ...any) error {
	return &refusal{status: http.StatusForbidden, reason: fmt.Sprintf(format, a...)}
}

func writeMessage(w http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(map[string]string{"message": msg})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(status)
	w.Write(append(body, '\n'))
}

// logSafe keeps a client-chosen string to one printable journal line.
func logSafe(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

func (f *Filter) refuse(w http.ResponseWriter, r *http.Request, path string, err error) {
	status, reason := http.StatusForbidden, err.Error()
	var rf *refusal
	if errors.As(err, &rf) {
		status = rf.status
	}
	f.log.Printf("refused %s %s: %s", logSafe(r.Method), logSafe(path), logSafe(reason))
	writeMessage(w, status, "devkit: refused: "+reason)
}

func (f *Filter) daemonDown(w http.ResponseWriter, r *http.Request, err error) {
	f.log.Printf("daemon unreachable for %s %s: %v", logSafe(r.Method), logSafe(r.URL.Path), err)
	writeMessage(w, http.StatusBadGateway, "devkit: the Docker daemon is not answering on its socket: "+err.Error())
}

var idRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ServeHTTP checks one call and forwards it or refuses it.
func (f *Filter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	out, e, err := f.check(r, rawPath, rawQuery)
	if err != nil {
		f.refuse(w, r, rawPath, err)
		return
	}
	if e.startCheck {
		if err := f.checkStart(r.Context(), out); err != nil {
			var rf *refusal
			if errors.As(err, &rf) {
				f.refuse(w, r, rawPath, err)
			} else {
				f.daemonDown(w, r, err)
			}
			return
		}
	}
	if e.upgrade && isUpgrade(r.Header) {
		f.upgrade(w, out)
		return
	}
	f.proxy.ServeHTTP(w, out)
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func isUpgrade(h http.Header) bool {
	return headerHasToken(h, "Connection", "upgrade") || h.Get("Upgrade") != ""
}

// check refuses what the filter does not allow, and otherwise returns the
// request to forward: the path as received, the query re-encoded from the
// parameters checked, and for a JSON call the body re-encoded from the
// structure checked, never the client's bytes.
func (f *Filter) check(r *http.Request, rawPath, rawQuery string) (*http.Request, *endpoint, error) {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		return nil, nil, refuse("only HTTP/1.1 is accepted")
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "DELETE":
	default:
		return nil, nil, refuse("the method %s is not allowed", r.Method)
	}
	_, p, err := canonical(rawPath)
	if err != nil {
		return nil, nil, refuse("%v", err)
	}
	e := match(r.Method, p)
	if e == nil {
		return nil, nil, refuse("%s %s is not an allowed call", r.Method, p)
	}
	vals, err := e.checkQueryString(rawQuery)
	if err != nil {
		return nil, nil, refuse("%s %s: %v", r.Method, p, err)
	}
	if isUpgrade(r.Header) && !e.upgrade {
		return nil, nil, refuse("%s %s cannot switch protocols", r.Method, p)
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Host = "docker"
	decoded, _ := url.PathUnescape(rawPath)
	out.URL = &url.URL{Scheme: "http", Host: "docker", Path: decoded, RawPath: rawPath, RawQuery: vals.Encode()}
	out.Header.Del("Content-Length")
	switch e.body {
	case bodyNone:
		if r.ContentLength != 0 {
			return nil, nil, refuse("%s %s takes no body", r.Method, p)
		}
		out.Body, out.ContentLength, out.TransferEncoding = http.NoBody, 0, nil
	case bodyJSON:
		if r.ContentLength > MaxBody {
			return nil, nil, refuse("%s %s: the body is larger than %d bytes", r.Method, p, MaxBody)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil {
			return nil, nil, refuse("%s %s: the body could not be read: %v", r.Method, p, err)
		}
		if len(body) > MaxBody {
			return nil, nil, refuse("%s %s: the body is larger than %d bytes", r.Method, p, MaxBody)
		}
		if e.optional && len(bytes.TrimSpace(body)) == 0 {
			out.Body, out.ContentLength, out.TransferEncoding = http.NoBody, 0, nil
			break
		}
		nb, err := e.validate(f, body)
		if err != nil {
			return nil, nil, refuse("%s %s: %v", r.Method, p, err)
		}
		out.Body, out.ContentLength, out.TransferEncoding = io.NopCloser(bytes.NewReader(nb)), int64(len(nb)), nil
		out.GetBody = nil
		out.Header.Set("Content-Type", "application/json")
	case bodyStream:
		// Passed through unread: build contexts, image archives, files
		// for docker cp, credentials for /auth.
	}
	return out, e, nil
}

// checkStart looks at the stored container before a start: a container
// made before the filter existed, or under another runtime setting, may
// carry what the filter would refuse today. The call is then forwarded for
// the full ID read, so that a rename between the look and the start
// cannot swap the container.
func (f *Filter) checkStart(ctx context.Context, out *http.Request) error {
	segs := strings.Split(out.URL.Path, "/")
	// [..., "containers", "{id}", "start"]
	i := len(segs) - 2
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/containers/"+url.PathEscape(segs[i])+"/json", nil)
	if err != nil {
		return err
	}
	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // the daemon answers the start itself: no such container
	}
	var c struct {
		ID         string `json:"Id"`
		HostConfig struct {
			Runtime    string
			Privileged bool
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&c); err != nil {
		return fmt.Errorf("reading the container: %v", err)
	}
	if !idRe.MatchString(c.ID) {
		return refuse("the container's ID %q is not one the filter recognises", c.ID)
	}
	if c.HostConfig.Privileged {
		return refuse("the container is privileged")
	}
	if rt := c.HostConfig.Runtime; rt != "" {
		ok := false
		for _, a := range f.cfg.Runtimes {
			ok = ok || rt == a
		}
		if !ok {
			return refuse("the container runs under the runtime %q, which is not allowed", rt)
		}
	}
	segs[i] = c.ID
	out.URL.Path = strings.Join(segs, "/")
	out.URL.RawPath = ""
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// upgrade forwards a call that switches protocols (attach, exec, BuildKit)
// and then copies both ways. httputil.ReverseProxy does this too, but it
// drops bytes the client sent right behind the request, which the server
// has already buffered, and it tears both sides down when the client
// closes its half, which is how the Docker client says stdin has ended
// while output is still to come.
//
// The request's context is not used: the server cancels it when the client
// half-closes, which a client may do as soon as it has sent its input.
func (f *Filter) upgrade(w http.ResponseWriter, out *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(out.Context()), 30*time.Second)
	up, err := f.dial(ctx, "", "")
	cancel()
	if err != nil {
		f.daemonDown(w, out, err)
		return
	}
	if err := out.Write(up); err != nil {
		up.Close()
		f.daemonDown(w, out, err)
		return
	}
	br := bufio.NewReader(up)
	resp, err := http.ReadResponse(br, out)
	if err != nil {
		up.Close()
		f.daemonDown(w, out, err)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// An error, or the old raw-stream answer without an upgrade: passed
		// back as a plain response.
		defer up.Close()
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		rc := http.NewResponseController(w)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		up.Close()
		return
	}
	defer conn.Close()
	defer up.Close()
	fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\n")
	resp.Header.Write(brw)
	brw.WriteString("\r\n")
	if err := brw.Flush(); err != nil {
		return
	}

	toDaemon := make(chan error, 1)
	go func() {
		// The client's bytes the server read ahead with the request go
		// first.
		if n := brw.Reader.Buffered(); n > 0 {
			b, _ := brw.Reader.Peek(n)
			if _, err := up.Write(b); err != nil {
				toDaemon <- err
				return
			}
			brw.Reader.Discard(n)
		}
		_, err := io.Copy(up, conn)
		if err == nil {
			closeWrite(up) // stdin ended; output may still come
		}
		toDaemon <- err
	}()
	fromDaemon := make(chan struct{})
	go func() {
		io.Copy(conn, br) // includes what the response reader buffered
		closeWrite(conn)
		close(fromDaemon)
	}()
	select {
	case <-fromDaemon:
		// The daemon has finished: the stream is over whatever the client
		// still sends.
	case err := <-toDaemon:
		if err != nil {
			return
		}
		<-fromDaemon
	}
}
