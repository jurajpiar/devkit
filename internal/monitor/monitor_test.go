package monitor

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	event := NewEvent(EventTypePerformance, "test", SeverityInfo, "test message")

	if event.Type != EventTypePerformance {
		t.Errorf("Type = %v, want %v", event.Type, EventTypePerformance)
	}
	if event.Source != "test" {
		t.Errorf("Source = %v, want %v", event.Source, "test")
	}
	if event.Severity != SeverityInfo {
		t.Errorf("Severity = %v, want %v", event.Severity, SeverityInfo)
	}
	if event.Message != "test message" {
		t.Errorf("Message = %v, want %v", event.Message, "test message")
	}
	if event.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestEventWithData(t *testing.T) {
	event := NewEvent(EventTypePerformance, "test", SeverityInfo, "test").
		WithData("key1", "value1").
		WithData("key2", 123)

	if event.Data["key1"] != "value1" {
		t.Errorf("Data[key1] = %v, want value1", event.Data["key1"])
	}
	if event.Data["key2"] != 123 {
		t.Errorf("Data[key2] = %v, want 123", event.Data["key2"])
	}
}

func TestEventWithContainer(t *testing.T) {
	event := NewEvent(EventTypePerformance, "test", SeverityInfo, "test").
		WithContainer("test-container")

	if event.Container != "test-container" {
		t.Errorf("Container = %v, want test-container", event.Container)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
	if !cfg.Performance.Enabled {
		t.Error("Performance.Enabled should be true by default")
	}
	if cfg.Performance.Interval != 5*time.Second {
		t.Errorf("Performance.Interval = %v, want 5s", cfg.Performance.Interval)
	}
	if cfg.Security.AnomalyDetection {
		t.Error("Security.AnomalyDetection should be false by default")
	}
	if !cfg.Outputs.CLI {
		t.Error("Outputs.CLI should be true by default")
	}
}

// MockCollector for testing
type MockCollector struct {
	name     string
	interval time.Duration
	events   []Event
	started  bool
	stopped  bool
}

func NewMockCollector(name string, events []Event) *MockCollector {
	return &MockCollector{
		name:     name,
		interval: 100 * time.Millisecond,
		events:   events,
	}
}

func (m *MockCollector) Name() string                                 { return m.name }
func (m *MockCollector) Interval() time.Duration                      { return m.interval }
func (m *MockCollector) Start(ctx context.Context) error              { m.started = true; return nil }
func (m *MockCollector) Stop() error                                  { m.stopped = true; return nil }
func (m *MockCollector) Collect(ctx context.Context) ([]Event, error) { return m.events, nil }

// MockOutput for testing
type MockOutput struct {
	name    string
	enabled bool
	events  []Event
	mu      sync.Mutex
	started bool
	stopped bool
}

func NewMockOutput(name string) *MockOutput {
	return &MockOutput{
		name:    name,
		enabled: true,
		events:  make([]Event, 0),
	}
}

func (m *MockOutput) Name() string    { return m.name }
func (m *MockOutput) Enabled() bool   { return m.enabled }
func (m *MockOutput) Start(ctx context.Context) error { m.started = true; return nil }
func (m *MockOutput) Stop() error     { m.stopped = true; return nil }

func (m *MockOutput) Write(event Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *MockOutput) GetEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Event, len(m.events))
	copy(result, m.events)
	return result
}

func TestMonitorAddCollector(t *testing.T) {
	mon := New(nil)
	collector := NewMockCollector("test", nil)

	mon.AddCollector(collector)

	stats := mon.GetStats()
	if stats["collector_count"].(int) != 1 {
		t.Errorf("collector_count = %v, want 1", stats["collector_count"])
	}
}

func TestMonitorAddOutput(t *testing.T) {
	mon := New(nil)
	output := NewMockOutput("test")

	mon.AddOutput(output)

	stats := mon.GetStats()
	if stats["output_count"].(int) != 1 {
		t.Errorf("output_count = %v, want 1", stats["output_count"])
	}
}

func TestMonitorEmit(t *testing.T) {
	mon := New(nil)
	output := NewMockOutput("test")
	mon.AddOutput(output)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	if err := mon.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mon.Stop()

	// Emit event
	event := NewEvent(EventTypePerformance, "test", SeverityInfo, "test message")
	mon.Emit(event)

	// Wait for event to be processed
	time.Sleep(100 * time.Millisecond)

	events := output.GetEvents()
	if len(events) != 1 {
		t.Errorf("len(events) = %d, want 1", len(events))
	}
}

func TestMonitorStartStop(t *testing.T) {
	mon := New(nil)
	collector := NewMockCollector("test", []Event{
		NewEvent(EventTypePerformance, "test", SeverityInfo, "test"),
	})
	output := NewMockOutput("test")

	mon.AddCollector(collector)
	mon.AddOutput(output)

	ctx := context.Background()

	// Start
	if err := mon.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !mon.IsRunning() {
		t.Error("IsRunning should be true after Start")
	}

	if !collector.started {
		t.Error("Collector should be started")
	}

	if !output.started {
		t.Error("Output should be started")
	}

	// Stop
	if err := mon.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if mon.IsRunning() {
		t.Error("IsRunning should be false after Stop")
	}

	if !collector.stopped {
		t.Error("Collector should be stopped")
	}

	if !output.stopped {
		t.Error("Output should be stopped")
	}
}

func TestMonitorDoubleStart(t *testing.T) {
	mon := New(nil)
	ctx := context.Background()

	if err := mon.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mon.Stop()

	// Second start should fail
	if err := mon.Start(ctx); err == nil {
		t.Error("Second Start should return error")
	}
}

func TestMonitorCollectorLoop(t *testing.T) {
	mon := New(nil)
	
	events := []Event{
		NewEvent(EventTypePerformance, "test", SeverityInfo, "perf event"),
	}
	collector := NewMockCollector("test", events)
	collector.interval = 50 * time.Millisecond

	output := NewMockOutput("test")

	mon.AddCollector(collector)
	mon.AddOutput(output)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mon.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for a few collection cycles
	time.Sleep(200 * time.Millisecond)

	mon.Stop()

	// Should have collected multiple events
	outputEvents := output.GetEvents()
	if len(outputEvents) < 2 {
		t.Errorf("Expected at least 2 events, got %d", len(outputEvents))
	}
}
