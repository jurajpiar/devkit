package debugproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ProxyConfig holds configuration for the debug proxy
type ProxyConfig struct {
	// ListenAddr is the address to listen on (e.g., ":9229")
	ListenAddr string
	// TargetAddr is the address of the actual debug server (e.g., "devcontainer:9229")
	TargetAddr string
	// FilterLevel sets the filtering strictness
	FilterLevel FilterLevel
	// AuditLog enables audit logging
	AuditLog bool
}

// Proxy is a CDP WebSocket proxy with filtering capabilities
type Proxy struct {
	config   ProxyConfig
	filter   *Filter
	audit    *AuditLogger
	stats    *AuditStats
	upgrader websocket.Upgrader
	server   *http.Server
	mu       sync.Mutex
}

// NewProxy creates a new debug proxy
func NewProxy(config ProxyConfig) *Proxy {
	p := &Proxy{
		config: config,
		filter: NewFilter(config.FilterLevel),
		audit:  NewAuditLogger(nil),
		stats:  NewAuditStats(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local debugging
			},
		},
	}

	if !config.AuditLog {
		p.audit.SetEnabled(false)
	}

	return p
}

// Start starts the proxy server
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Handle WebSocket connections for debug
	mux.HandleFunc("/", p.handleConnection)

	// Handle /json endpoint (debugger discovery)
	mux.HandleFunc("/json", p.handleJSON)
	mux.HandleFunc("/json/list", p.handleJSON)
	mux.HandleFunc("/json/version", p.handleJSONVersion)

	// Stats endpoint
	mux.HandleFunc("/stats", p.handleStats)

	p.server = &http.Server{
		Addr:    p.config.ListenAddr,
		Handler: mux,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		log.Printf("Debug proxy listening on %s -> %s (filter: %v)",
			p.config.ListenAddr, p.config.TargetAddr, p.config.FilterLevel)
		if err := p.server.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return p.Shutdown()
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully shuts down the proxy
func (p *Proxy) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.server.Shutdown(ctx)
}

// handleConnection handles incoming WebSocket connections
func (p *Proxy) handleConnection(w http.ResponseWriter, r *http.Request) {
	clientAddr := r.RemoteAddr
	p.audit.LogConnect(clientAddr)

	// Upgrade client connection to WebSocket
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade client connection: %v", err)
		p.audit.LogError(clientAddr, err)
		return
	}
	defer clientConn.Close()

	// Connect to target debug server
	targetURL := url.URL{
		Scheme: "ws",
		Host:   p.config.TargetAddr,
		Path:   r.URL.Path,
	}

	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL.String(), nil)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		p.audit.LogError(clientAddr, fmt.Errorf("target connection failed: %w", err))
		return
	}
	defer targetConn.Close()

	// Create channels for coordination
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Proxy client -> target (with filtering)
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyClientToTarget(clientConn, targetConn, clientAddr, done)
	}()

	// Proxy target -> client (responses)
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyTargetToClient(targetConn, clientConn, clientAddr, done)
	}()

	// Wait for both directions to complete
	wg.Wait()
	p.audit.LogDisconnect(clientAddr)
}

// proxyClientToTarget proxies messages from client to target with filtering
func (p *Proxy) proxyClientToTarget(client, target *websocket.Conn, clientAddr string, done chan struct{}) {
	defer close(done)

	for {
		messageType, data, err := client.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			if err != io.EOF {
				p.audit.LogError(clientAddr, fmt.Errorf("client read error: %w", err))
			}
			return
		}

		// Parse CDP message
		msg, err := ParseMessage(data)
		if err != nil {
			// Forward non-JSON messages as-is
			if err := target.WriteMessage(messageType, data); err != nil {
				return
			}
			continue
		}

		p.stats.RecordRequest()
		p.audit.LogRequest(clientAddr, msg)

		// Filter the message
		result := p.filter.FilterMessage(msg)

		if !result.Allowed {
			p.stats.RecordBlocked(msg.Method, result.Reason)
			p.audit.LogBlocked(clientAddr, msg, result.Reason)

			// Send error response to client
			errResp := CreateErrorResponse(msg.ID, -32600, fmt.Sprintf("Blocked by security filter: %s", result.Reason))
			respData, _ := errResp.ToJSON()
			if err := client.WriteMessage(websocket.TextMessage, respData); err != nil {
				return
			}
			continue
		}

		// Forward to target
		forwardData := data
		if result.Message != nil {
			forwardData, _ = result.Message.ToJSON()
		}

		if err := target.WriteMessage(messageType, forwardData); err != nil {
			return
		}
	}
}

// proxyTargetToClient proxies messages from target to client
func (p *Proxy) proxyTargetToClient(target, client *websocket.Conn, clientAddr string, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}

		messageType, data, err := target.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			if err != io.EOF {
				p.audit.LogError(clientAddr, fmt.Errorf("target read error: %w", err))
			}
			return
		}

		// Parse for logging purposes
		if msg, err := ParseMessage(data); err == nil && msg.ID != 0 {
			p.audit.LogResponse(clientAddr, msg)
		}

		// Forward response to client
		if err := client.WriteMessage(messageType, data); err != nil {
			return
		}
	}
}

// handleJSON handles the /json endpoint for debugger discovery
func (p *Proxy) handleJSON(w http.ResponseWriter, r *http.Request) {
	// Forward to target
	targetURL := fmt.Sprintf("http://%s%s", p.config.TargetAddr, r.URL.Path)

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "Failed to reach debug target", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Copy body
	io.Copy(w, resp.Body)
}

// handleJSONVersion handles the /json/version endpoint
func (p *Proxy) handleJSONVersion(w http.ResponseWriter, r *http.Request) {
	p.handleJSON(w, r)
}

// handleStats returns proxy statistics
func (p *Proxy) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := p.stats.GetStats()

	// Add filter level
	stats["filter_level"] = p.config.FilterLevel

	data, _ := json.Marshal(stats)
	w.Write(data)
}

// SetFilterLevel changes the filter level at runtime
func (p *Proxy) SetFilterLevel(level FilterLevel) {
	p.filter.SetLevel(level)
}

// GetStats returns current statistics
func (p *Proxy) GetStats() map[string]interface{} {
	return p.stats.GetStats()
}

// MustParseFilterLevel parses a filter level string
func MustParseFilterLevel(s string) FilterLevel {
	switch s {
	case "strict":
		return FilterLevelStrict
	case "filtered":
		return FilterLevelFiltered
	case "audit":
		return FilterLevelAudit
	case "passthrough":
		return FilterLevelPassthrough
	default:
		return FilterLevelFiltered
	}
}

// TCPProxy provides a simple TCP proxy for non-WebSocket connections
type TCPProxy struct {
	listenAddr string
	targetAddr string
}

// NewTCPProxy creates a new TCP proxy
func NewTCPProxy(listenAddr, targetAddr string) *TCPProxy {
	return &TCPProxy{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
	}
}

// Start starts the TCP proxy
func (p *TCPProxy) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go p.handleTCPConnection(clientConn)
	}
}

func (p *TCPProxy) handleTCPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	targetConn, err := net.Dial("tcp", p.targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	done := make(chan struct{})

	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	<-done
}
