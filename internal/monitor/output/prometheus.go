package output

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// PrometheusOutput exports metrics in Prometheus format
type PrometheusOutput struct {
	port    int
	enabled bool
	mu      sync.RWMutex
	server  *http.Server

	// Metrics storage
	metrics     map[string]float64
	metricsMu   sync.RWMutex
	counters    map[string]uint64
	countersMu  sync.RWMutex
	lastUpdate  time.Time
	container   string
}

// PrometheusConfig holds Prometheus output configuration
type PrometheusConfig struct {
	Port    int
	Enabled bool
}

// DefaultPrometheusConfig returns default Prometheus configuration
func DefaultPrometheusConfig() PrometheusConfig {
	return PrometheusConfig{
		Port:    9090,
		Enabled: false,
	}
}

// NewPrometheus creates a new Prometheus output
func NewPrometheus(cfg PrometheusConfig) *PrometheusOutput {
	if cfg.Port == 0 {
		cfg.Port = 9090
	}

	return &PrometheusOutput{
		port:     cfg.Port,
		enabled:  cfg.Enabled,
		metrics:  make(map[string]float64),
		counters: make(map[string]uint64),
	}
}

// Name returns the output's identifier
func (p *PrometheusOutput) Name() string {
	return "prometheus"
}

// Enabled returns whether this output is enabled
func (p *PrometheusOutput) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// SetEnabled enables or disables the output
func (p *PrometheusOutput) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

// Start initializes and starts the Prometheus metrics server
func (p *PrometheusOutput) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", p.handleMetrics)
	mux.HandleFunc("/health", p.handleHealth)

	p.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: mux,
	}

	go func() {
		if err := p.server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Prometheus server error: %v\n", err)
		}
	}()

	return nil
}

// Stop shuts down the metrics server
func (p *PrometheusOutput) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return p.server.Shutdown(ctx)
}

// Write processes an event and updates metrics
func (p *PrometheusOutput) Write(event monitor.Event) error {
	p.mu.RLock()
	if !p.enabled {
		p.mu.RUnlock()
		return nil
	}
	p.mu.RUnlock()

	// Update container name
	if event.Container != "" {
		p.container = event.Container
	}

	// Process based on event type
	switch event.Type {
	case monitor.EventTypePerformance:
		p.updatePerformanceMetrics(event)
	case monitor.EventTypeSecurity, monitor.EventTypeNetwork,
		monitor.EventTypeFileAccess, monitor.EventTypeProcess:
		p.incrementCounter("devkit_security_events_total")
	case monitor.EventTypeAlert, monitor.EventTypeAnomaly:
		p.incrementCounter("devkit_alerts_total")
		if event.Severity == monitor.SeverityCritical {
			p.incrementCounter("devkit_critical_alerts_total")
		}
	case monitor.EventTypeBlocked:
		p.incrementCounter("devkit_blocked_operations_total")
	}

	return nil
}

// updatePerformanceMetrics updates gauge metrics from performance data
func (p *PrometheusOutput) updatePerformanceMetrics(event monitor.Event) {
	p.metricsMu.Lock()
	defer p.metricsMu.Unlock()

	p.lastUpdate = time.Now()

	if cpu, ok := event.Data["cpu_percent"].(float64); ok {
		p.metrics["devkit_cpu_percent"] = cpu
	}
	if memPercent, ok := event.Data["mem_percent"].(float64); ok {
		p.metrics["devkit_memory_percent"] = memPercent
	}
	if memUsage, ok := event.Data["mem_usage"].(uint64); ok {
		p.metrics["devkit_memory_usage_bytes"] = float64(memUsage)
	}
	if memLimit, ok := event.Data["mem_limit"].(uint64); ok {
		p.metrics["devkit_memory_limit_bytes"] = float64(memLimit)
	}
	if netIn, ok := event.Data["net_input"].(uint64); ok {
		p.metrics["devkit_network_receive_bytes"] = float64(netIn)
	}
	if netOut, ok := event.Data["net_output"].(uint64); ok {
		p.metrics["devkit_network_transmit_bytes"] = float64(netOut)
	}
	if blockIn, ok := event.Data["block_input"].(uint64); ok {
		p.metrics["devkit_block_read_bytes"] = float64(blockIn)
	}
	if blockOut, ok := event.Data["block_output"].(uint64); ok {
		p.metrics["devkit_block_write_bytes"] = float64(blockOut)
	}
	if pids, ok := event.Data["pids"].(int); ok {
		p.metrics["devkit_pids"] = float64(pids)
	}
}

// incrementCounter increments a counter metric
func (p *PrometheusOutput) incrementCounter(name string) {
	p.countersMu.Lock()
	defer p.countersMu.Unlock()
	p.counters[name]++
}

// handleMetrics serves Prometheus metrics
func (p *PrometheusOutput) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	container := p.container
	if container == "" {
		container = "unknown"
	}

	// Write gauge metrics
	p.metricsMu.RLock()
	for name, value := range p.metrics {
		writeMetric(w, name, "gauge", container, value)
	}
	p.metricsMu.RUnlock()

	// Write counter metrics
	p.countersMu.RLock()
	for name, value := range p.counters {
		writeMetric(w, name, "counter", container, float64(value))
	}
	p.countersMu.RUnlock()

	// Write info metric
	fmt.Fprintf(w, "# HELP devkit_info Devkit container information\n")
	fmt.Fprintf(w, "# TYPE devkit_info gauge\n")
	fmt.Fprintf(w, "devkit_info{container=\"%s\"} 1\n", container)
}

// handleHealth serves a health check endpoint
func (p *PrometheusOutput) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	p.metricsMu.RLock()
	lastUpdate := p.lastUpdate
	p.metricsMu.RUnlock()

	status := "healthy"
	if time.Since(lastUpdate) > 30*time.Second && !lastUpdate.IsZero() {
		status = "stale"
	}

	fmt.Fprintf(w, `{"status":"%s","last_update":"%s"}`, status, lastUpdate.Format(time.RFC3339))
}

// writeMetric writes a single metric in Prometheus format
func writeMetric(w http.ResponseWriter, name, metricType, container string, value float64) {
	help := metricHelp[name]
	if help == "" {
		help = name
	}

	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, metricType)
	fmt.Fprintf(w, "%s{container=\"%s\"} %g\n", name, container, value)
}

// metricHelp provides help text for metrics
var metricHelp = map[string]string{
	"devkit_cpu_percent":            "Current CPU usage percentage",
	"devkit_memory_percent":         "Current memory usage percentage",
	"devkit_memory_usage_bytes":     "Current memory usage in bytes",
	"devkit_memory_limit_bytes":     "Memory limit in bytes",
	"devkit_network_receive_bytes":  "Total network bytes received",
	"devkit_network_transmit_bytes": "Total network bytes transmitted",
	"devkit_block_read_bytes":       "Total block I/O bytes read",
	"devkit_block_write_bytes":      "Total block I/O bytes written",
	"devkit_pids":                   "Current number of processes",
	"devkit_security_events_total":  "Total security events",
	"devkit_alerts_total":           "Total alerts",
	"devkit_critical_alerts_total":  "Total critical alerts",
	"devkit_blocked_operations_total": "Total blocked operations",
}

// GetPort returns the server port
func (p *PrometheusOutput) GetPort() int {
	return p.port
}

// GetMetrics returns current metrics (for testing)
func (p *PrometheusOutput) GetMetrics() map[string]float64 {
	p.metricsMu.RLock()
	defer p.metricsMu.RUnlock()

	result := make(map[string]float64, len(p.metrics))
	for k, v := range p.metrics {
		result[k] = v
	}
	return result
}

// GetCounters returns current counters (for testing)
func (p *PrometheusOutput) GetCounters() map[string]uint64 {
	p.countersMu.RLock()
	defer p.countersMu.RUnlock()

	result := make(map[string]uint64, len(p.counters))
	for k, v := range p.counters {
		result[k] = v
	}
	return result
}
