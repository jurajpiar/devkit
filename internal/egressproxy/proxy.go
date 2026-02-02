package egressproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	config ProxyConfig
	filter *Filter
	audit  *AuditLogger
	server *http.Server
	mu     sync.Mutex
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	p.server = &http.Server{
		Addr:    p.config.ListenAddr,
		Handler: mux,
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
	host := r.Host

	// Check if host is allowed
	result := p.filter.CheckWithDetails(host)
	p.audit.LogRequest(r.Method, host, result.Allowed, result.Pattern)

	if !result.Allowed {
		http.Error(w, fmt.Sprintf("Blocked: %s is not in the allowlist", host), http.StatusForbidden)
		return
	}

	// Establish connection to target
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
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
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Check if redirect target is allowed
			if !p.filter.IsAllowed(req.URL.Host) {
				return fmt.Errorf("redirect to %s blocked by allowlist", req.URL.Host)
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
