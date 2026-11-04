package egressproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ProxyConfig holds configuration for the egress proxy
type ProxyConfig struct {
	// ListenAddr is the address to listen on (e.g., ":3128")
	ListenAddr string
	// AllowedHosts is the list of allowed domain patterns
	AllowedHosts []string
	// AuditLog enables logging of all requests
	AuditLog bool
	// Logger is the logger to use (nil for default)
	Logger *log.Logger
}

// Proxy is an HTTP/HTTPS proxy with domain filtering
type Proxy struct {
	dialOnce sync.Once
	dial     *net.Dialer
	trOnce   sync.Once
	tr       *http.Transport
	config   ProxyConfig
	filter   *Filter
	audit    *AuditLogger
	server   *http.Server
	mu       sync.Mutex
}

// NewProxy creates a new egress proxy
func NewProxy(config ProxyConfig) *Proxy {
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}

	return &Proxy{
		config: config,
		filter: NewFilter(config.AllowedHosts),
		audit:  NewAuditLogger(logger, config.AuditLog),
	}
}

// Start starts the proxy server
func (p *Proxy) Start(ctx context.Context) error {
	// Use the proxy directly as the handler - ServeMux doesn't properly route CONNECT requests
	p.server = &http.Server{
		Addr:    p.config.ListenAddr,
		Handler: http.HandlerFunc(p.handleRequest),
		// Timeouts for security
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return p.Stop()
	}
}

// Stop gracefully stops the proxy server
func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return p.server.Shutdown(ctx)
}

// handleRequest handles incoming proxy requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT requests (tunneling)
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := withDefaultPort(r.Host, "443")

	// Check if host is allowed
	result := p.filter.CheckWithDetails(host)
	p.audit.LogRequest(r.Method, host, result.Allowed, result.Pattern)

	if !result.Allowed {
		http.Error(w, fmt.Sprintf("Blocked: %s is not in the allowlist", host), http.StatusForbidden)
		return
	}

	// Establish connection to target
	targetConn, err := p.dialer().DialContext(r.Context(), "tcp", host)
	if err != nil {
		p.audit.LogError(host, err)
		http.Error(w, fmt.Sprintf("Failed to connect to %s: %v", host, err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Send 200 OK to client to indicate tunnel is established
	w.WriteHeader(http.StatusOK)

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Start bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		// Signal EOF to target
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		// Signal EOF to client
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// handleHTTP handles plain HTTP proxy requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract host from URL
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	host = withDefaultPort(host, schemePort(r.URL.Scheme))

	// Check if host is allowed
	result := p.filter.CheckWithDetails(host)
	p.audit.LogRequest(r.Method, host, result.Allowed, result.Pattern)

	if !result.Allowed {
		http.Error(w, fmt.Sprintf("Blocked: %s is not in the allowlist", host), http.StatusForbidden)
		return
	}

	// Create outgoing request
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	// Remove hop-by-hop headers
	removeHopByHopHeaders(outReq.Header)

	// Forward the request
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: p.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Check if redirect target is allowed
			target := withDefaultPort(req.URL.Host, schemePort(req.URL.Scheme))
			if !p.filter.IsAllowed(target) {
				return fmt.Errorf("redirect to %s blocked by allowlist", target)
			}
			return nil
		},
	}

	resp, err := client.Do(outReq)
	if err != nil {
		p.audit.LogError(host, err)
		http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status and body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// removeHopByHopHeaders removes headers that should not be forwarded
func removeHopByHopHeaders(h http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// UpdateAllowedHosts updates the filter's allowed hosts
func (p *Proxy) UpdateAllowedHosts(hosts []string) {
	p.filter.SetAllowedHosts(hosts)
}

// GetStats returns proxy statistics
func (p *Proxy) GetStats() AuditStats {
	return p.audit.GetStats()
}

// withDefaultPort returns hostport with port added when it names none, so
// the allowlist's port policy always sees the port that would be dialled.
func withDefaultPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), port)
}

// schemePort is the port a plain-HTTP proxy request implies by its scheme.
func schemePort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

// resolvConf is where systemd-resolved keeps the real upstream resolvers.
// /etc/resolv.conf points at the local stub, which cannot forward once the
// firewall allows DNS to the proxy's account only.
const resolvConf = "/run/systemd/resolve/resolv.conf"

// dialer resolves names against the upstream resolvers directly, as the
// proxy's own user, so that no other account in the VM needs DNS at all.
func (p *Proxy) dialer() *net.Dialer {
	p.dialOnce.Do(func() {
		p.dial = &net.Dialer{Timeout: 10 * time.Second}
		servers := upstreamResolvers(resolvConf)
		if len(servers) == 0 {
			return
		}
		addrs := make([]string, len(servers))
		for i, s := range servers {
			addrs[i] = net.JoinHostPort(s, "53")
		}
		// One Dial gives Go's resolver a connection that itself fails over:
		// it sends each query to the first upstream and, if that upstream is
		// silent for perUpstreamTimeout, resends to the next. Rotating
		// upstreams per Dial (the old approach) did not survive Go issuing
		// the A and AAAA queries at once: both took a turn, so each landed on
		// the same server every retry and a silent upstream was never left.
		p.dial.Resolver = &net.Resolver{
			PreferGo: true,
			// network is "udp" normally and "tcp" when Go retries a
			// truncated answer; honour it, or large/truncated responses
			// would never resolve.
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return newFailoverConn(ctx, network, addrs, perUpstreamTimeout)
			},
		}
	})
	return p.dial
}

// perUpstreamTimeout is how long one DNS upstream is given to answer a query
// before the failover connection resends it to the next.
const perUpstreamTimeout = 2500 * time.Millisecond

// failoverConn is a connected UDP DNS socket that moves to the next upstream
// when the current one does not answer within perUpstream. It keeps the last
// datagram written so it can resend it to each upstream in turn, which makes
// a silent primary resolver fail over to a working secondary within one
// query instead of relying on the resolver's own retry.
type failoverConn struct {
	ctx         context.Context
	network     string // "udp" or "tcp", as the resolver requested
	addrs       []string
	perUpstream time.Duration

	mu       sync.Mutex
	conn     net.Conn
	idx      int
	lastMsg  []byte
	deadline time.Time
}

// newFailoverConn returns a net.Conn for UDP (a PacketConn, so Go uses
// datagram framing) or TCP (a plain stream conn, so Go uses length-prefixed
// framing). Both fail over to the next upstream when the current one is
// silent or unreachable.
func newFailoverConn(ctx context.Context, network string, addrs []string, perUpstream time.Duration) (net.Conn, error) {
	if network == "" {
		network = "udp"
	}
	c := &failoverConn{ctx: ctx, network: network, addrs: addrs, perUpstream: perUpstream}
	if err := c.dialCurrent(); err != nil {
		return nil, err
	}
	if network == "udp" {
		return &udpFailoverConn{c}, nil
	}
	return c, nil
}

// udpFailoverConn adds ReadFrom/WriteTo so the UDP variant satisfies
// net.PacketConn; the resolver's type assertion on that selects datagram
// framing. A TCP conn must not satisfy it, hence the separate type.
type udpFailoverConn struct{ *failoverConn }

func (c *udpFailoverConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
func (c *udpFailoverConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c *failoverConn) dialCurrent() error {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c.ctx, c.network, c.addrs[c.idx])
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *failoverConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastMsg = append(c.lastMsg[:0], b...)
	return c.conn.Write(b)
}

func (c *failoverConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lastErr error
	for {
		hasDeadline := !c.deadline.IsZero()
		if hasDeadline && !time.Now().Before(c.deadline) {
			// A set deadline that has already passed: never clear the read
			// deadline (which would block forever); report the timeout.
			if lastErr == nil {
				lastErr = &net.OpError{Op: "read", Net: c.network, Err: errReadTimeout}
			}
			return 0, lastErr
		}
		// Give an upstream only perUpstream while another remains, so a silent
		// one fails over quickly; give the last (or only) upstream the full
		// remaining deadline, so a single slow-but-working resolver is not cut
		// off early. Absolute deadlines throughout, so "expired" is explicit.
		last := c.idx+1 >= len(c.addrs)
		if last {
			if hasDeadline {
				_ = c.conn.SetReadDeadline(c.deadline)
			} else {
				_ = c.conn.SetReadDeadline(time.Time{}) // no deadline: block
			}
		} else {
			cap := time.Now().Add(c.perUpstream)
			if hasDeadline && c.deadline.Before(cap) {
				cap = c.deadline
			}
			_ = c.conn.SetReadDeadline(cap)
		}
		n, err := c.conn.Read(b)
		if err == nil {
			return n, nil
		}
		lastErr = err
		// Only a timeout means "this upstream is silent"; a real error on a
		// connected UDP socket (e.g. ICMP port-unreachable) is also a reason
		// to try the next. Either way, move on if any upstream is left.
		if c.idx+1 >= len(c.addrs) {
			return 0, err
		}
		c.conn.Close()
		c.idx++
		if derr := c.dialCurrent(); derr != nil {
			return 0, derr
		}
		if len(c.lastMsg) > 0 {
			if _, werr := c.conn.Write(c.lastMsg); werr != nil {
				return 0, werr
			}
		}
	}
}

func (c *failoverConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *failoverConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.conn.SetDeadline(t)
}

func (c *failoverConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil // Read manages its own per-upstream deadline, bounded by this.
}

func (c *failoverConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *failoverConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *failoverConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }

var errReadTimeout = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dns upstreams did not answer in time" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// transport is the one http.Transport for forwarded plain-HTTP requests:
// bounded idle connections with a timeout, rather than a new Transport per
// request whose keep-alive sockets would never be closed.
func (p *Proxy) transport() *http.Transport {
	p.trOnce.Do(func() {
		p.tr = &http.Transport{
			Proxy:               nil,
			DialContext:         p.dialer().DialContext,
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		}
	})
	return p.tr
}

// upstreamResolvers reads the nameserver lines of a resolv.conf, skipping
// loopback stubs. Empty when the file is absent, in which case the system
// resolver is used.
func upstreamResolvers(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && !ip.IsLoopback() {
				out = append(out, f[1])
			}
		}
	}
	return out
}
