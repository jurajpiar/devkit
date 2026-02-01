package output

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// WebOutput provides a web dashboard with SSE for live updates
type WebOutput struct {
	port     int
	enabled  bool
	mu       sync.RWMutex
	server   *http.Server
	clients  map[chan monitor.Event]bool
	clientMu sync.Mutex
	events   []monitor.Event
	maxEvents int
}

// WebConfig holds web output configuration
type WebConfig struct {
	Port      int
	Enabled   bool
	MaxEvents int // Maximum events to keep in memory
}

// DefaultWebConfig returns default web configuration
func DefaultWebConfig() WebConfig {
	return WebConfig{
		Port:      8080,
		Enabled:   false,
		MaxEvents: 1000,
	}
}

// NewWeb creates a new web output
func NewWeb(cfg WebConfig) *WebOutput {
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = 1000
	}

	return &WebOutput{
		port:      cfg.Port,
		enabled:   cfg.Enabled,
		clients:   make(map[chan monitor.Event]bool),
		events:    make([]monitor.Event, 0, cfg.MaxEvents),
		maxEvents: cfg.MaxEvents,
	}
}

// Name returns the output's identifier
func (w *WebOutput) Name() string {
	return "web"
}

// Enabled returns whether this output is enabled
func (w *WebOutput) Enabled() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.enabled
}

// SetEnabled enables or disables the output
func (w *WebOutput) SetEnabled(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = enabled
}

// Start initializes and starts the web server
func (w *WebOutput) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", w.handleDashboard)
	mux.HandleFunc("/events", w.handleSSE)
	mux.HandleFunc("/api/events", w.handleAPIEvents)
	mux.HandleFunc("/api/stats", w.handleAPIStats)

	w.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", w.port),
		Handler: mux,
	}

	go func() {
		if err := w.server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Web server error: %v\n", err)
		}
	}()

	return nil
}

// Stop shuts down the web server
func (w *WebOutput) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Close all SSE clients
	w.clientMu.Lock()
	for ch := range w.clients {
		close(ch)
		delete(w.clients, ch)
	}
	w.clientMu.Unlock()

	return w.server.Shutdown(ctx)
}

// Write sends an event to all connected SSE clients
func (w *WebOutput) Write(event monitor.Event) error {
	w.mu.Lock()
	// Store event
	w.events = append(w.events, event)
	if len(w.events) > w.maxEvents {
		w.events = w.events[1:]
	}
	w.mu.Unlock()

	// Broadcast to all SSE clients
	w.clientMu.Lock()
	for ch := range w.clients {
		select {
		case ch <- event:
		default:
			// Client channel full, skip
		}
	}
	w.clientMu.Unlock()

	return nil
}

// handleDashboard serves the main dashboard HTML
func (w *WebOutput) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(rw, map[string]interface{}{
		"Port": w.port,
	})
}

// handleSSE handles Server-Sent Events connections
func (w *WebOutput) handleSSE(rw http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	// Create client channel
	clientCh := make(chan monitor.Event, 100)

	// Register client
	w.clientMu.Lock()
	w.clients[clientCh] = true
	w.clientMu.Unlock()

	// Cleanup on disconnect
	defer func() {
		w.clientMu.Lock()
		delete(w.clients, clientCh)
		w.clientMu.Unlock()
	}()

	// Send events
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "SSE not supported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case event, ok := <-clientCh:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(rw, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleAPIEvents returns events as JSON
func (w *WebOutput) handleAPIEvents(rw http.ResponseWriter, r *http.Request) {
	w.mu.RLock()
	events := make([]monitor.Event, len(w.events))
	copy(events, w.events)
	w.mu.RUnlock()

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(events)
}

// handleAPIStats returns current stats as JSON
func (w *WebOutput) handleAPIStats(rw http.ResponseWriter, r *http.Request) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Find most recent performance event
	var latestPerf *monitor.Event
	for i := len(w.events) - 1; i >= 0; i-- {
		if w.events[i].Type == monitor.EventTypePerformance {
			latestPerf = &w.events[i]
			break
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	if latestPerf != nil {
		json.NewEncoder(rw).Encode(latestPerf.Data)
	} else {
		json.NewEncoder(rw).Encode(map[string]interface{}{})
	}
}

// GetPort returns the server port
func (w *WebOutput) GetPort() int {
	return w.port
}

// Dashboard HTML template
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Devkit Monitor</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #00d9ff; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; }
        .card h2 { color: #00d9ff; font-size: 14px; text-transform: uppercase; margin-bottom: 15px; }
        .stat { font-size: 36px; font-weight: bold; }
        .stat-label { color: #888; font-size: 12px; }
        .progress { height: 8px; background: #0f3460; border-radius: 4px; overflow: hidden; margin: 10px 0; }
        .progress-bar { height: 100%; background: linear-gradient(90deg, #00d9ff, #00ff88); transition: width 0.3s; }
        .progress-bar.warning { background: linear-gradient(90deg, #ffaa00, #ff6600); }
        .progress-bar.critical { background: linear-gradient(90deg, #ff4444, #ff0000); }
        .events { max-height: 400px; overflow-y: auto; }
        .event { padding: 10px; border-bottom: 1px solid #0f3460; font-size: 13px; }
        .event:last-child { border-bottom: none; }
        .event-time { color: #888; }
        .event-type { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; margin: 0 5px; }
        .event-type.PERF { background: #00d9ff; color: #000; }
        .event-type.SEC, .event-type.NET, .event-type.PROC { background: #aa00ff; color: #fff; }
        .event-type.ALERT, .event-type.ANOM { background: #ff4444; color: #fff; }
        .severity-info { border-left: 3px solid #00d9ff; }
        .severity-warning { border-left: 3px solid #ffaa00; }
        .severity-critical { border-left: 3px solid #ff4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Devkit Monitor</h1>
        
        <div class="grid">
            <div class="card">
                <h2>CPU Usage</h2>
                <div class="stat" id="cpu">--</div>
                <div class="progress"><div class="progress-bar" id="cpu-bar" style="width: 0%"></div></div>
            </div>
            <div class="card">
                <h2>Memory Usage</h2>
                <div class="stat" id="mem">--</div>
                <div class="progress"><div class="progress-bar" id="mem-bar" style="width: 0%"></div></div>
                <div class="stat-label" id="mem-detail">-- / --</div>
            </div>
            <div class="card">
                <h2>Network I/O</h2>
                <div class="stat" id="net">--</div>
                <div class="stat-label">In / Out</div>
            </div>
            <div class="card">
                <h2>Processes</h2>
                <div class="stat" id="pids">--</div>
                <div class="stat-label">Active PIDs</div>
            </div>
        </div>

        <div class="card">
            <h2>Events</h2>
            <div class="events" id="events"></div>
        </div>
    </div>

    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KiB', 'MiB', 'GiB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function updateStats(data) {
            if (data.cpu_percent !== undefined) {
                document.getElementById('cpu').textContent = data.cpu_percent.toFixed(1) + '%';
                const cpuBar = document.getElementById('cpu-bar');
                cpuBar.style.width = Math.min(data.cpu_percent, 100) + '%';
                cpuBar.className = 'progress-bar' + (data.cpu_percent > 90 ? ' critical' : data.cpu_percent > 70 ? ' warning' : '');
            }
            if (data.mem_percent !== undefined) {
                document.getElementById('mem').textContent = data.mem_percent.toFixed(1) + '%';
                const memBar = document.getElementById('mem-bar');
                memBar.style.width = Math.min(data.mem_percent, 100) + '%';
                memBar.className = 'progress-bar' + (data.mem_percent > 90 ? ' critical' : data.mem_percent > 70 ? ' warning' : '');
            }
            if (data.mem_usage !== undefined && data.mem_limit !== undefined) {
                document.getElementById('mem-detail').textContent = formatBytes(data.mem_usage) + ' / ' + formatBytes(data.mem_limit);
            }
            if (data.net_input !== undefined && data.net_output !== undefined) {
                document.getElementById('net').textContent = formatBytes(data.net_input) + ' / ' + formatBytes(data.net_output);
            }
            if (data.pids !== undefined) {
                document.getElementById('pids').textContent = data.pids;
            }
        }

        function addEvent(event) {
            const events = document.getElementById('events');
            const el = document.createElement('div');
            el.className = 'event severity-' + event.severity;
            
            const time = new Date(event.timestamp).toLocaleTimeString();
            const typeClass = event.type.toUpperCase().replace('_', '');
            
            el.innerHTML = '<span class="event-time">' + time + '</span>' +
                '<span class="event-type ' + typeClass + '">' + typeClass + '</span>' +
                '<span>' + event.message + '</span>';
            
            events.insertBefore(el, events.firstChild);
            
            // Keep only last 100 events in DOM
            while (events.children.length > 100) {
                events.removeChild(events.lastChild);
            }
        }

        // Connect to SSE
        const evtSource = new EventSource('/events');
        evtSource.onmessage = function(e) {
            const event = JSON.parse(e.data);
            addEvent(event);
            
            if (event.type === 'performance' && event.data) {
                updateStats(event.data);
            }
        };
        evtSource.onerror = function() {
            console.log('SSE connection lost, reconnecting...');
        };

        // Initial load
        fetch('/api/events')
            .then(r => r.json())
            .then(events => {
                events.slice(-50).forEach(addEvent);
            });
        
        fetch('/api/stats')
            .then(r => r.json())
            .then(updateStats);
    </script>
</body>
</html>`
