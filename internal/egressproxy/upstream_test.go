package egressproxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingDNS is a UDP and TCP listener on one port that answers nothing and
// counts every query that reaches it.
func countingDNS(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			n.Add(1)
		}
	}()
	if ln, err := net.Listen("tcp", pc.LocalAddr().String()); err == nil {
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				n.Add(1)
				c.Close()
			}
		}()
	}
	return pc.LocalAddr().String(), &n
}

// serve runs p's handler on a local port and returns its address.
func serve(t *testing.T, p *Proxy) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func clientVia(proxyAddr string) *http.Client {
	u, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(u)},
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// With an upstream, the proxy is the inner layer of two: it decides by its
// own allowlist and logs, then hands every request to the parent, which
// resolves and dials. The inner proxy must not resolve anything itself: in
// the guest under host enforcement there is no resolver to ask, and a query
// it sent would be a DNS channel out. A name only the parent's resolver
// knows proves the request really went through the parent; a counting
// resolver configured on the inner proxy proves it asked nothing.
func TestUpstreamChainsConnectAndHTTPWithoutAnyDNS(t *testing.T) {
	parentDNS, stop := miniDNSAnswering(t, [4]byte{127, 0, 0, 1})
	defer stop()
	childDNS, queries := countingDNS(t)
	echo := echoServer(t)
	_, echoPort, _ := net.SplitHostPort(echo)
	up := newUpstream(t, nil)
	_, upPort, _ := net.SplitHostPort(up.hostPort())
	allow := []string{"only-here.test:" + echoPort, "only-here.test:" + upPort}

	parentLog, childLog := &syncLog{}, &syncLog{}
	parent := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(parentLog, "", 0), Resolvers: []string{parentDNS}}))
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(childLog, "", 0), Resolvers: []string{childDNS}, Upstream: parent}))

	status, conn, br := connect(t, child, "only-here.test:"+echoPort)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("CONNECT through the parent should succeed: %s\nchild:\n%s\nparent:\n%s", status, childLog, parentLog)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, msg := range []string{"first\n", "second\n"} {
		io.WriteString(conn, msg)
		if got, err := br.ReadString('\n'); err != nil || got != msg {
			t.Fatalf("the chained tunnel should carry bytes both ways: got %q, %v", got, err)
		}
	}

	resp, err := clientVia(child).Get("http://only-here.test:" + upPort + "/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream says hello" || up.hits.Load() != 1 {
		t.Fatalf("plain HTTP through the parent should arrive: %d %q, hits %d\nchild:\n%s\nparent:\n%s", resp.StatusCode, body, up.hits.Load(), childLog, parentLog)
	}
	if r := up.last(); r.URL.Path != "/path" || r.URL.RawQuery != "q=1" {
		t.Errorf("path and query must survive the chain, got %v", r.URL)
	}

	if n := queries.Load(); n != 0 {
		t.Errorf("the proxy sent %d DNS queries with an upstream set; it must send none", n)
	}
	for _, l := range []*syncLog{childLog, parentLog} {
		for _, want := range []string{"ALLOWED CONNECT only-here.test:" + echoPort, "ALLOWED GET only-here.test:" + upPort} {
			if !strings.Contains(l.String(), want) {
				t.Errorf("both layers must log %q:\n%s", want, l)
			}
		}
	}
}

// The inner proxy still enforces its own allowlist: a host it refuses never
// reaches the parent.
func TestUpstreamInnerAllowlistStillDecides(t *testing.T) {
	echo := echoServer(t)
	parentLog := &syncLog{}
	parent := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo}, AuditLog: true, Logger: log.New(parentLog, "", 0)}))
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{"elsewhere.test"}, AuditLog: true, Logger: log.New(io.Discard, "", 0), Upstream: parent}))
	if status, _, _ := connect(t, child, echo); !strings.HasPrefix(status, "403") {
		t.Errorf("the inner allowlist must refuse, got %s", status)
	}
	if parentLog.String() != "" {
		t.Errorf("a refused request must not reach the parent:\n%s", parentLog)
	}
}

// The parent allows more than the inner proxy (it also serves root's
// provisioning). If it followed redirects itself, an allowed origin could
// redirect to a host only the parent allows and the inner allowlist would
// never see it. With ReturnRedirects the parent hands the redirect back and
// the inner proxy decides.
func TestUpstreamRedirectsAreDecidedByTheInnerAllowlist(t *testing.T) {
	target := newUpstream(t, nil)
	origin := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/next", http.StatusFound)
	})
	parent := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{origin.hostPort(), target.hostPort()}, Logger: log.New(io.Discard, "", 0), ReturnRedirects: true}))
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{origin.hostPort()}, AuditLog: true, Logger: log.New(io.Discard, "", 0), Upstream: parent}))
	resp, err := clientVia(child).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || target.hits.Load() != 0 {
		t.Errorf("a redirect to a host only the parent allows must be refused: %d, target hits %d", resp.StatusCode, target.hits.Load())
	}
	// And the parent alone returns the redirect instead of following it.
	resp, err = clientVia(parent).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || target.hits.Load() != 0 {
		t.Errorf("ReturnRedirects: want the 302 back, got %d, target hits %d", resp.StatusCode, target.hits.Load())
	}
}

// A refusal by the parent looks to the client exactly like a refusal by the
// inner proxy, so tools report it as a policy decision, not a network fault.
func TestUpstreamRefusalLooksLikeALocalOne(t *testing.T) {
	echo := echoServer(t)
	up := newUpstream(t, nil)
	allow := []string{echo, up.hostPort()}
	parent := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{"nothing.test"}, AuditLog: true, Logger: log.New(io.Discard, "", 0)}))
	childLog := &syncLog{}
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(childLog, "", 0), Upstream: parent}))
	local := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{"nothing.test"}, Logger: log.New(io.Discard, "", 0)}))

	for _, target := range []string{echo} {
		want, _, _ := connect(t, local, target)
		got, _, _ := connect(t, child, target)
		if got != want || !strings.HasPrefix(got, "403") {
			t.Errorf("CONNECT refused by the parent: got %q, a local refusal is %q", got, want)
		}
	}
	get := func(proxy string) (int, string) {
		resp, err := clientVia(proxy).Get(up.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	wantCode, wantBody := get(local)
	gotCode, gotBody := get(child)
	if gotCode != wantCode || gotBody != wantBody || gotCode != http.StatusForbidden {
		t.Errorf("HTTP refused by the parent: got %d %q, a local refusal is %d %q", gotCode, gotBody, wantCode, wantBody)
	}
	if up.hits.Load() != 0 {
		t.Error("a request the parent refused must not reach the origin")
	}
	if strings.Count(childLog.String(), "refused by the upstream proxy") != 2 {
		t.Errorf("the inner log must record both of the parent's refusals:\n%s", childLog)
	}
}

// An unreachable parent fails the request; there is no fallback to dialling
// directly.
func TestUpstreamUnreachableFailsClosed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	echo := echoServer(t)
	up := newUpstream(t, nil)
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo, up.hostPort()}, Logger: log.New(io.Discard, "", 0), Upstream: dead}))
	if status, _, _ := connect(t, child, echo); !strings.HasPrefix(status, "502") {
		t.Errorf("CONNECT with a dead parent: want 502, got %s", status)
	}
	resp, err := clientVia(child).Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || up.hits.Load() != 0 {
		t.Errorf("HTTP with a dead parent: want 502 and no direct dial, got %d, hits %d", resp.StatusCode, up.hits.Load())
	}
}

// The upstream is an address, never a name: resolving it would be the one
// lookup the inner proxy makes.
func TestUpstreamMustBeAnIPAddress(t *testing.T) {
	for _, ok := range []string{"192.168.5.2:41234", "127.0.0.1:1", "[::1]:3128"} {
		if err := ValidateUpstream(ok); err != nil {
			t.Errorf("%s should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"host.lima.internal:3128", "192.168.5.2", "192.168.5.2:0", "192.168.5.2:x", ":3128"} {
		if err := ValidateUpstream(bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
	p := NewProxy(ProxyConfig{ListenAddr: "127.0.0.1:0", Upstream: "parent.example:3128"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Start(ctx); err == nil || !strings.Contains(err.Error(), "upstream") {
		t.Errorf("Start must refuse a named upstream, got %v", err)
	}
}

// On the Mac the proxy must not become a way into the Mac's own loopback: an
// allowed name that resolves to 127.0.0.1 (DNS the attacker controls, or a
// public name such as localtest.me in open mode) is refused at dial time.
func TestRefuseLoopbackBlocksTheMacsOwnServices(t *testing.T) {
	echo := echoServer(t)
	up := newUpstream(t, nil)
	logs := &syncLog{}
	p := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo, up.hostPort()}, AuditLog: true, Logger: log.New(logs, "", 0), RefuseLoopback: true}))
	if status, _, _ := connect(t, p, echo); !strings.HasPrefix(status, "403") {
		t.Errorf("CONNECT to loopback: want 403, got %s", status)
	}
	resp, err := clientVia(p).Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || up.hits.Load() != 0 {
		t.Errorf("HTTP to loopback: want 403 and no hit, got %d, hits %d", resp.StatusCode, up.hits.Load())
	}
	if !strings.Contains(logs.String(), "loopback") {
		t.Errorf("the refusal must be logged:\n%s", logs)
	}
	// Positive control: without the option the same targets are reached.
	q := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo}, Logger: log.New(io.Discard, "", 0)}))
	if status, _, _ := connect(t, q, echo); !strings.HasPrefix(status, "200") {
		t.Errorf("control: CONNECT should work without RefuseLoopback, got %s", status)
	}
}

func TestRefusedAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "127.8.9.1": true, "::1": true, "0.0.0.0": true, "::": true,
		"169.254.169.254": true, "fe80::1": true, "::ffff:127.0.0.1": true,
		"93.184.215.14": false, "192.168.5.2": false, "2606:4700::1111": false,
	} {
		if got := refusedAddress(net.ParseIP(addr)); got != want {
			t.Errorf("refusedAddress(%s) = %v, want %v", addr, got, want)
		}
	}
}
