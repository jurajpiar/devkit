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
	// Resolvers, as "host:port", are the DNS servers the proxy resolves
	// through. Empty means the upstream servers systemd-resolved lists in
	// /run/systemd/resolve/resolv.conf, which is what the VM uses; tests set
	// it to local servers.
	Resolvers []string
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
	// dialTunnel, when set, replaces the dialer for CONNECT targets; tests
	// use it to observe the address chosen and to fail deterministically.
	dialTunnel func(ctx context.Context, network, addr string) (net.Conn, error)
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
	dial := p.dialer().DialContext
	if p.dialTunnel != nil {
		dial = p.dialTunnel
	}
	targetConn, err := dial(r.Context(), "tcp", host)
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
		addrs := p.config.Resolvers
		if len(addrs) == 0 {
			for _, s := range upstreamResolvers(resolvConf) {
				addrs = append(addrs, net.JoinHostPort(s, "53"))
			}
		}
		if len(addrs) == 0 {
			return
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

// failoverConn is a DNS socket that moves to the next upstream when the
// current one cannot be dialled or does not answer within perUpstream. It
// keeps the last datagram written so it can resend it to each upstream in
// turn, which makes a silent or refusing primary fail over to a working
// secondary within one query instead of relying on the resolver's own retry.
//
// For UDP a datagram is a whole answer. For TCP the answer is a length-prefixed
// frame that may arrive in pieces; the conn acquires the complete frame from
// one upstream before handing any of it to the caller, so a failover never
// splices two upstreams' bytes into one message.
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
	frame    []byte // tcp: the complete frame being served, if any
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
	if err := c.dialNext(); err != nil {
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

// dialNext dials the upstream at idx, advancing past any that refuse, so a
// primary that rejects TCP (or is unreachable) does not end the query while
// a secondary remains. Returns the last error when every upstream fails.
func (c *failoverConn) dialNext() error {
	var last error
	for c.idx < len(c.addrs) {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c.ctx, c.network, c.addrs[c.idx])
		if err == nil {
			c.conn = conn
			return nil
		}
		last = err
		c.idx++
	}
	c.idx = len(c.addrs) - 1
	return last
}

// advance closes the current upstream, moves to the next that can be dialled
// and resends the last query. false when no upstream remains.
func (c *failoverConn) advance() bool {
	if c.idx+1 >= len(c.addrs) {
		return false
	}
	c.conn.Close()
	c.idx++
	if err := c.dialNext(); err != nil {
		return false
	}
	if len(c.lastMsg) > 0 {
		if _, err := c.conn.Write(c.lastMsg); err != nil {
			return false
		}
	}
	return true
}

func (c *failoverConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastMsg = append(c.lastMsg[:0], b...)
	c.frame = nil // a new query: any buffered frame belongs to the old one
	return c.conn.Write(b)
}

// armDeadline sets the socket read deadline for the current attempt: a short
// cap while another upstream remains, the full remaining deadline for the
// last (or only) one. Returns false, having set nothing, when a set deadline
// has already passed, so an expired deadline never turns into "block forever".
func (c *failoverConn) armDeadline() bool {
	hasDeadline := !c.deadline.IsZero()
	if hasDeadline && !time.Now().Before(c.deadline) {
		return false
	}
	if c.idx+1 >= len(c.addrs) {
		if hasDeadline {
			_ = c.conn.SetReadDeadline(c.deadline)
		} else {
			_ = c.conn.SetReadDeadline(time.Time{})
		}
		return true
	}
	cap := time.Now().Add(c.perUpstream)
	if hasDeadline && c.deadline.Before(cap) {
		cap = c.deadline
	}
	_ = c.conn.SetReadDeadline(cap)
	return true
}

func (c *failoverConn) timeout() error {
	return &net.OpError{Op: "read", Net: c.network, Err: errReadTimeout}
}

func (c *failoverConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.network == "tcp" {
		return c.readTCP(b)
	}
	// UDP: one datagram is one answer; fail over between whole datagrams.
	var lastErr error
	for {
		if !c.armDeadline() {
			if lastErr == nil {
				lastErr = c.timeout()
			}
			return 0, lastErr
		}
		n, err := c.conn.Read(b)
		if err == nil {
			return n, nil
		}
		lastErr = err
		if !c.advance() {
			return 0, err
		}
	}
}

// readTCP serves the caller from a complete frame. When none is buffered it
// acquires one from the current upstream (length prefix, then exactly that
// many bytes) and fails over, resending the query, if any part of it does
// not arrive; the caller never sees a partial frame from one upstream
// followed by bytes from another.
func (c *failoverConn) readTCP(b []byte) (int, error) {
	if len(c.frame) == 0 {
		if err := c.acquireFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.frame)
	c.frame = c.frame[n:]
	return n, nil
}

func (c *failoverConn) acquireFrame() error {
	var lastErr error
	for {
		if !c.armDeadline() {
			if lastErr == nil {
				lastErr = c.timeout()
			}
			return lastErr
		}
		var prefix [2]byte
		_, err := io.ReadFull(c.conn, prefix[:])
		if err == nil {
			body := make([]byte, int(prefix[0])<<8|int(prefix[1]))
			_, err = io.ReadFull(c.conn, body)
			if err == nil {
				c.frame = append(prefix[:], body...)
				return nil
			}
		}
		lastErr = err
		if !c.advance() {
			return err
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
