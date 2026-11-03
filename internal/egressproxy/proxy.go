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
	"sync/atomic"
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
	tr       *http.Transport
	next     uint32 // round-robin index over the upstream resolvers
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
		// Go's resolver retries a query that gets no answer, calling Dial
		// again each time. UDP "dials" never fail, so the only way a dead
		// upstream is skipped is to hand each attempt the next server.
		p.dial.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				i := atomic.AddUint32(&p.next, 1) - 1
				s := servers[int(i)%len(servers)]
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(s, "53"))
			},
		}
	})
	return p.dial
}

// transport is the one http.Transport for forwarded plain-HTTP requests:
// bounded idle connections with a timeout, rather than a new Transport per
// request whose keep-alive sockets would never be closed.
func (p *Proxy) transport() *http.Transport {
	p.dialer()
	if p.tr == nil {
		p.tr = &http.Transport{
			Proxy:               nil,
			DialContext:         p.dial.DialContext,
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		}
	}
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
