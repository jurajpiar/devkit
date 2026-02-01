// Package monitor provides a modular monitoring system for devkit containers.
// It supports multiple output backends (CLI, daemon, web, Prometheus) and
// collects both performance and security metrics.
package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventType represents the type of monitoring event
type EventType string

const (
	// Performance events
	EventTypePerformance EventType = "performance"
	EventTypeResource    EventType = "resource"

	// Security events
	EventTypeSecurity    EventType = "security"
	EventTypeNetwork     EventType = "network"
	EventTypeFileAccess  EventType = "file_access"
	EventTypeProcess     EventType = "process"
	EventTypeCapability  EventType = "capability"

	// Audit events (from debug proxy)
	EventTypeAudit   EventType = "audit"
	EventTypeCDP     EventType = "cdp"
	EventTypeBlocked EventType = "blocked"

	// Alert events
	EventTypeAlert   EventType = "alert"
	EventTypeAnomaly EventType = "anomaly"
)

// Severity represents the severity level of an event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event represents a single monitoring event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Container string                 `json:"container,omitempty"`
	Severity  Severity               `json:"severity"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// NewEvent creates a new event with a generated ID
func NewEvent(eventType EventType, source string, severity Severity, message string) Event {
	return Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:      eventType,
		Timestamp: time.Now(),
		Source:    source,
		Severity:  severity,
		Message:   message,
		Data:      make(map[string]interface{}),
	}
}

// WithData adds data to an event and returns it
func (e Event) WithData(key string, value interface{}) Event {
	if e.Data == nil {
		e.Data = make(map[string]interface{})
	}
	e.Data[key] = value
	return e
}

// WithContainer sets the container name and returns the event
func (e Event) WithContainer(container string) Event {
	e.Container = container
	return e
}

// Collector is the interface for data collectors
type Collector interface {
	// Name returns the collector's identifier
	Name() string

	// Collect gathers events from the data source
	Collect(ctx context.Context) ([]Event, error)

	// Interval returns how often the collector should run
	Interval() time.Duration

	// Start initializes the collector (optional setup)
	Start(ctx context.Context) error

	// Stop cleans up the collector
	Stop() error
}

// Output is the interface for output backends
type Output interface {
	// Name returns the output's identifier
	Name() string

	// Write sends an event to the output
	Write(event Event) error

	// Start initializes the output backend
	Start(ctx context.Context) error

	// Stop cleans up the output backend
	Stop() error

	// Enabled returns whether this output is enabled
	Enabled() bool
}

// AlertHandler handles alert events
type AlertHandler interface {
	// HandleAlert processes an alert event
	HandleAlert(event Event) error
}

// Monitor is the central monitoring coordinator
type Monitor struct {
	collectors    []Collector
	outputs       []Output
	alertHandlers []AlertHandler
	eventCh       chan Event
	stopCh        chan struct{}
	wg            sync.WaitGroup
	mu            sync.RWMutex
	running       bool
	config        *Config
}

// Config holds monitoring configuration
type Config struct {
	Enabled     bool
	Performance PerformanceConfig
	Security    SecurityConfig
	Outputs     OutputsConfig
}

// PerformanceConfig holds performance monitoring settings
type PerformanceConfig struct {
	Enabled  bool
	Interval time.Duration
}

// SecurityConfig holds security monitoring settings
type SecurityConfig struct {
	Enabled          bool
	AnomalyDetection bool
	AlertThreshold   Severity
}

// OutputsConfig holds output backend settings
type OutputsConfig struct {
	CLI        bool
	Daemon     bool
	DaemonPath string
	Web        bool
	WebPort    int
	Prometheus bool
	PromPort   int
}

// DefaultConfig returns a default monitoring configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		Performance: PerformanceConfig{
			Enabled:  true,
			Interval: 5 * time.Second,
		},
		Security: SecurityConfig{
			Enabled:          true,
			AnomalyDetection: false, // Feature-flagged, off by default
			AlertThreshold:   SeverityWarning,
		},
		Outputs: OutputsConfig{
			CLI:        true, // Default output
			Daemon:     false,
			DaemonPath: "",
			Web:        false,
			WebPort:    8080,
			Prometheus: false,
			PromPort:   9090,
		},
	}
}

// New creates a new Monitor instance
func New(cfg *Config) *Monitor {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Monitor{
		collectors:    make([]Collector, 0),
		outputs:       make([]Output, 0),
		alertHandlers: make([]AlertHandler, 0),
		eventCh:       make(chan Event, 1000),
		stopCh:        make(chan struct{}),
		config:        cfg,
	}
}

// AddCollector registers a collector
func (m *Monitor) AddCollector(c Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectors = append(m.collectors, c)
}

// AddOutput registers an output backend
func (m *Monitor) AddOutput(o Output) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outputs = append(m.outputs, o)
}

// AddAlertHandler registers an alert handler
func (m *Monitor) AddAlertHandler(h AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertHandlers = append(m.alertHandlers, h)
}

// Emit sends an event to all outputs
func (m *Monitor) Emit(event Event) {
	select {
	case m.eventCh <- event:
	default:
		// Channel full, drop event (could log this)
	}
}

// Start begins monitoring
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Start all outputs
	for _, o := range m.outputs {
		if o.Enabled() {
			if err := o.Start(ctx); err != nil {
				return fmt.Errorf("failed to start output %s: %w", o.Name(), err)
			}
		}
	}

	// Start all collectors
	for _, c := range m.collectors {
		if err := c.Start(ctx); err != nil {
			return fmt.Errorf("failed to start collector %s: %w", c.Name(), err)
		}
	}

	// Start event dispatcher
	m.wg.Add(1)
	go m.dispatchEvents(ctx)

	// Start collector loops
	for _, c := range m.collectors {
		m.wg.Add(1)
		go m.runCollector(ctx, c)
	}

	return nil
}

// Stop halts monitoring
func (m *Monitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	// Wait for goroutines to finish
	m.wg.Wait()

	// Stop all collectors
	for _, c := range m.collectors {
		c.Stop()
	}

	// Stop all outputs
	for _, o := range m.outputs {
		o.Stop()
	}

	return nil
}

// IsRunning returns whether the monitor is active
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// dispatchEvents routes events to outputs
func (m *Monitor) dispatchEvents(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event := <-m.eventCh:
			m.handleEvent(event)
		}
	}
}

// handleEvent processes a single event
func (m *Monitor) handleEvent(event Event) {
	// Send to all enabled outputs
	for _, o := range m.outputs {
		if o.Enabled() {
			o.Write(event)
		}
	}

	// Handle alerts
	if event.Type == EventTypeAlert || event.Type == EventTypeAnomaly {
		for _, h := range m.alertHandlers {
			h.HandleAlert(event)
		}
	}
}

// runCollector periodically runs a collector
func (m *Monitor) runCollector(ctx context.Context, c Collector) {
	defer m.wg.Done()

	ticker := time.NewTicker(c.Interval())
	defer ticker.Stop()

	// Run immediately once
	m.collectAndEmit(ctx, c)

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.collectAndEmit(ctx, c)
		}
	}
}

// collectAndEmit runs a collector and emits its events
func (m *Monitor) collectAndEmit(ctx context.Context, c Collector) {
	events, err := c.Collect(ctx)
	if err != nil {
		// Emit error event
		m.Emit(NewEvent(EventTypeAlert, c.Name(), SeverityWarning,
			fmt.Sprintf("collector error: %v", err)))
		return
	}

	for _, event := range events {
		m.Emit(event)
	}
}

// GetStats returns current monitoring statistics
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"running":         m.running,
		"collector_count": len(m.collectors),
		"output_count":    len(m.outputs),
		"event_queue_len": len(m.eventCh),
	}

	collectors := make([]string, 0, len(m.collectors))
	for _, c := range m.collectors {
		collectors = append(collectors, c.Name())
	}
	stats["collectors"] = collectors

	outputs := make([]string, 0, len(m.outputs))
	for _, o := range m.outputs {
		if o.Enabled() {
			outputs = append(outputs, o.Name())
		}
	}
	stats["outputs"] = outputs

	return stats
}
