package egressproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests drive the proxy's request handling with local listeners only:
// no DNS and no outside network, so they run the same on a laptop and in CI.
// Upstreams listen on 127.0.0.1 at random ports, which are not web ports, so
// each test allows them explicitly as "127.0.0.1:<port>", the way a user
// would allow a non-web port in network.allow.

// syncLog is a log destination tests can read while the proxy writes to it.
type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *syncLog) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// upstream is an HTTP server that records what reached it.
type upstream struct {
	*httptest.Server
	hits    atomic.Int64
	mu      sync.Mutex
	lastReq *http.Request
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.mu.Lock()
		u.lastReq = r.Clone(context.Background())
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "upstream says hello")
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) hostPort() string { return strings.TrimPrefix(u.URL, "http://") }

func (u *upstream) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastReq
}

// startProxy serves the proxy's handler on a local port and returns a client
// that sends every request through it, plus the audit log.
func startProxy(t *testing.T, allowed ...string) (*Proxy, *http.Client, *syncLog, string) {
	t.Helper()
	logs := &syncLog{}
	p := NewProxy(ProxyConfig{AllowedHosts: allowed, AuditLog: true, Logger: log.New(logs, "", 0)})
	srv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
		// The proxy itself follows redirects; the client must not, so the
		// tests see exactly what the proxy returned.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return p, client, logs, proxyURL.Host
}

func TestHTTPForwardsAnAllowedRequestAndLogsIt(t *testing.T) {
	up := newUpstream(t, nil)
	_, client, logs, _ := startProxy(t, up.hostPort())
	resp, err := client.Get(up.URL + "/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream says hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if r := up.last(); r == nil || r.URL.Path != "/path" || r.URL.RawQuery != "q=1" {
		t.Errorf("upstream should see the path and query intact, got %v", r)
	}
	if !strings.Contains(logs.String(), "[EGRESS] ALLOWED GET "+up.hostPort()) {
		t.Errorf("an allowed request must be logged:\n%s", logs)
	}
}

func TestHTTPBlocksAHostNotOnTheAllowlist(t *testing.T) {
	up := newUpstream(t, nil)
	_, client, logs, _ := startProxy(t, "allowed.example")
	resp, err := client.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("want 403, got %d", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Error("a blocked request must never reach the upstream")
	}
	if !strings.Contains(logs.String(), "[EGRESS] BLOCKED GET "+up.hostPort()) {
		t.Errorf("a blocked request must be logged:\n%s", logs)
	}
}

func TestHTTPAllowsOnlyWebPortsWithoutAPortEntry(t *testing.T) {
	up := newUpstream(t, nil)
	// "127.0.0.1" with no port allows 80 and 443 only; the upstream listens
	// on a random port, so it must be refused.
	_, client, _, _ := startProxy(t, "127.0.0.1")
	resp, err := client.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || up.hits.Load() != 0 {
		t.Errorf("a non-web port without an explicit entry must be refused before dialling: %d, hits %d", resp.StatusCode, up.hits.Load())
	}
}

func TestHTTPRedirectToAHostOffTheAllowlistIsRefused(t *testing.T) {
	target := newUpstream(t, nil)
	origin := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	})
	_, client, logs, _ := startProxy(t, origin.hostPort()) // target is not allowed
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("a redirect off the allowlist must fail with 502, got %d", resp.StatusCode)
	}
	if target.hits.Load() != 0 {
		t.Error("the proxy must not follow a redirect to a host off the allowlist")
	}
	if !strings.Contains(logs.String(), "redirect to "+target.hostPort()+" blocked by allowlist") {
		t.Errorf("the refused redirect must be logged:\n%s", logs)
	}
}

func TestHTTPRedirectWithinTheAllowlistIsFollowed(t *testing.T) {
	var origin *upstream
	origin = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, origin.URL+"/end", http.StatusFound)
			return
		}
		io.WriteString(w, "arrived at "+r.URL.Path)
	})
	_, client, _, _ := startProxy(t, origin.hostPort())
	resp, err := client.Get(origin.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "arrived at /end" {
		t.Errorf("a redirect within the allowlist should be followed: %d %q", resp.StatusCode, body)
	}
}

func TestHTTPStripsHopByHopHeadersAndProxyCredentials(t *testing.T) {
	up := newUpstream(t, nil)
	_, client, _, _ := startProxy(t, up.hostPort())
	req, _ := http.NewRequest(http.MethodGet, up.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Kept", "yes")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := up.last().Header
	for _, h := range []string{"Proxy-Authorization", "Keep-Alive", "Te", "Upgrade"} {
		if got.Get(h) != "" {
			t.Errorf("%s must not be forwarded, upstream saw %q", h, got.Get(h))
		}
	}
	if got.Get("X-Kept") != "yes" {
		t.Error("ordinary headers must be forwarded")
	}
}

// A request may name an allowed host in its URL and a different site in its
// Host header, hoping a shared front end routes it by the header (domain
// fronting). For absolute-form proxy requests Go's server takes the host from
// the URL and drops the header, which is what keeps this closed; this pins it.
func TestHTTPHostHeaderCannotRedirectTheRequest(t *testing.T) {
	up := newUpstream(t, nil)
	_, _, _, proxyAddr := startProxy(t, up.hostPort())
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n", up.URL)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if h := up.last().Host; h != up.hostPort() {
		t.Errorf("upstream saw Host %q; it must be the allowlisted %q", h, up.hostPort())
	}
}

func TestHTTPUnreachableUpstreamIs502AndLogged(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close() // nothing listens there now
	_, client, logs, _ := startProxy(t, dead)
	resp, err := client.Get("http://" + dead + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("want 502, got %d", resp.StatusCode)
	}
	if !strings.Contains(logs.String(), "[EGRESS] ERROR "+dead) {
		t.Errorf("the failed dial must be logged:\n%s", logs)
	}
}

// echoServer accepts TCP connections and echoes what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// connect opens a CONNECT tunnel through the proxy and returns the status
// line and, on 200, the tunnel.
func connect(t *testing.T, proxyAddr, target string) (string, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status, conn, br
}

func TestConnectTunnelsBothWaysToAnAllowedTarget(t *testing.T) {
	echo := echoServer(t)
	_, _, logs, proxyAddr := startProxy(t, echo)
	status, conn, br := connect(t, proxyAddr, echo)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("want 200, got %s", status)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, msg := range []string{"first\n", "second\n"} {
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatal(err)
		}
		got, err := br.ReadString('\n')
		if err != nil || got != msg {
			t.Fatalf("tunnel should carry bytes both ways: got %q, %v", got, err)
		}
	}
	if !strings.Contains(logs.String(), "[EGRESS] ALLOWED CONNECT "+echo) {
		t.Errorf("an allowed tunnel must be logged:\n%s", logs)
	}
}

func TestConnectWithoutAPortMeans443(t *testing.T) {
	// "localhost" with no port is a web-port entry. A CONNECT that names no
	// port must be decided and dialled as :443. The dial is intercepted, so
	// the result does not depend on whether this machine serves HTTPS.
	p, _, logs, proxyAddr := startProxy(t, "localhost")
	var dialled []string
	var mu sync.Mutex
	p.dialTunnel = func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		return nil, fmt.Errorf("dial intercepted by the test")
	}
	status, _, _ := connect(t, proxyAddr, "localhost")
	if !strings.HasPrefix(status, "502") {
		t.Errorf("want 502 from the intercepted dial, got %s", status)
	}
	mu.Lock()
	got := strings.Join(dialled, ",")
	mu.Unlock()
	if got != "localhost:443" {
		t.Errorf("a CONNECT without a port must dial :443, dialled %q", got)
	}
	if !strings.Contains(logs.String(), "ALLOWED CONNECT localhost:443") {
		t.Errorf("the default port should be in the decision:\n%s", logs)
	}
	status, _, _ = connect(t, proxyAddr, "localhost:22")
	if !strings.HasPrefix(status, "403") {
		t.Errorf("an explicit non-web port must be refused, got %s", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialled) != 1 {
		t.Errorf("a refused CONNECT must never be dialled: %q", dialled)
	}
}

func TestAllowlistUpdatesTakeEffectAndStatsCount(t *testing.T) {
	up := newUpstream(t, nil)
	p, client, _, _ := startProxy(t, "nothing.example")
	get := func() int {
		resp, err := client.Get(up.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("want 403 before the update, got %d", code)
	}
	p.UpdateAllowedHosts([]string{up.hostPort()})
	if code := get(); code != 200 {
		t.Fatalf("want 200 after the update, got %d", code)
	}
	st := p.GetStats()
	if st.TotalRequests != 2 || st.AllowedRequests != 1 || st.BlockedRequests != 1 {
		t.Errorf("stats should count one allowed and one blocked: %+v", st)
	}
}

func TestProxyStartsAndStopsOnContextCancel(t *testing.T) {
	p := NewProxy(ProxyConfig{ListenAddr: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start should return nil after a clean stop, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}
}

func TestUpstreamResolversReadsOnlyRealServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(path, []byte("# comment\nnameserver 127.0.0.53\nnameserver 192.168.5.2\nsearch .\nnameserver ::1\nnameserver 2001:db8::1\nnameserver not-an-ip\n"), 0o644)
	got := upstreamResolvers(path)
	if strings.Join(got, ",") != "192.168.5.2,2001:db8::1" {
		t.Errorf("want only non-loopback IPs, got %v", got)
	}
	if upstreamResolvers(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Error("a missing file should yield no servers, so the system resolver is used")
	}
}

func TestTransportIsSharedAndBounded(t *testing.T) {
	p := NewProxy(ProxyConfig{})
	var wg sync.WaitGroup
	got := make([]*http.Transport, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) { defer wg.Done(); got[i] = p.transport() }(i)
	}
	wg.Wait()
	for _, tr := range got[1:] {
		if tr != got[0] {
			t.Fatal("every caller must get the same transport")
		}
	}
	if got[0].IdleConnTimeout == 0 || got[0].MaxIdleConns == 0 {
		t.Error("the transport must bound its idle connections")
	}
	if got[0].Proxy != nil {
		t.Error("the proxy must not itself use a proxy")
	}
}

func TestSchemePort(t *testing.T) {
	for scheme, want := range map[string]string{"https": "443", "HTTPS": "443", "http": "80", "": "80"} {
		if got := schemePort(scheme); got != want {
			t.Errorf("schemePort(%q) = %q, want %q", scheme, got, want)
		}
	}
}
