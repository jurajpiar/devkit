package output

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

func TestNewCLI(t *testing.T) {
	cfg := DefaultCLIConfig()
	cli := NewCLI(cfg)

	if cli.Name() != "cli" {
		t.Errorf("Name() = %s, want cli", cli.Name())
	}

	if !cli.Enabled() {
		t.Error("Should be enabled by default")
	}
}

func TestCLISetEnabled(t *testing.T) {
	cli := NewCLI(DefaultCLIConfig())

	cli.SetEnabled(false)
	if cli.Enabled() {
		t.Error("Should be disabled")
	}

	cli.SetEnabled(true)
	if !cli.Enabled() {
		t.Error("Should be enabled")
	}
}

func TestCLIWrite(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:     &buf,
		Enabled:    true,
		ShowPerf:   true,
		ShowSec:    true,
		ShowAlerts: true,
	})

	event := monitor.NewEvent(monitor.EventTypePerformance, "test", monitor.SeverityInfo, "test message").
		WithContainer("test-container")

	if err := cli.Write(event); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	output := buf.String()

	// Check for components (may include ANSI codes)
	if !strings.Contains(output, "PERF") {
		t.Errorf("Output should contain event type PERF, got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Output should contain message, got: %s", output)
	}
	if !strings.Contains(output, "test-container") {
		t.Errorf("Output should contain container name, got: %s", output)
	}
}

func TestCLIWriteDisabled(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:  &buf,
		Enabled: false,
	})

	event := monitor.NewEvent(monitor.EventTypePerformance, "test", monitor.SeverityInfo, "test message")
	cli.Write(event)

	if buf.Len() != 0 {
		t.Error("Should not write when disabled")
	}
}

func TestCLIFilterByType(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:     &buf,
		Enabled:    true,
		ShowPerf:   false, // Disable performance
		ShowSec:    true,
		ShowAlerts: true,
	})

	perfEvent := monitor.NewEvent(monitor.EventTypePerformance, "test", monitor.SeverityInfo, "perf event")
	cli.Write(perfEvent)

	if buf.Len() != 0 {
		t.Error("Should not write performance events when ShowPerf=false")
	}

	secEvent := monitor.NewEvent(monitor.EventTypeSecurity, "test", monitor.SeverityInfo, "security event")
	cli.Write(secEvent)

	if buf.Len() == 0 {
		t.Error("Should write security events when ShowSec=true")
	}
}

func TestCLISeverityFormatting(t *testing.T) {
	tests := []struct {
		severity monitor.Severity
		expected string
	}{
		{monitor.SeverityInfo, "INFO"},
		{monitor.SeverityWarning, "WARN"},
		{monitor.SeverityCritical, "CRIT"},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		cli := NewCLI(CLIConfig{
			Writer:     &buf,
			Enabled:    true,
			ShowAlerts: true,
		})

		event := monitor.NewEvent(monitor.EventTypeAlert, "test", tt.severity, "test")
		cli.Write(event)

		// The output includes ANSI codes, so we just check the severity string is there
		output := buf.String()
		if !strings.Contains(output, tt.expected) {
			t.Errorf("Output for severity %s should contain %s, got: %s", tt.severity, tt.expected, output)
		}
	}
}

func TestCLIStartStop(t *testing.T) {
	cli := NewCLI(DefaultCLIConfig())

	if err := cli.Start(context.Background()); err != nil {
		t.Errorf("Start failed: %v", err)
	}

	if err := cli.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestCLIPrintStats(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:  &buf,
		Enabled: true,
	})

	stats := map[string]interface{}{
		"cpu_percent": 50.5,
		"mem_percent": 75.0,
		"mem_usage":   uint64(1024 * 1024 * 512),
		"mem_limit":   uint64(1024 * 1024 * 1024),
		"net_input":   uint64(1024 * 100),
		"net_output":  uint64(1024 * 50),
		"pids":        25,
	}

	cli.PrintStats(stats)

	output := buf.String()
	if !strings.Contains(output, "CPU") {
		t.Error("Output should contain CPU stats")
	}
	if !strings.Contains(output, "Memory") {
		t.Error("Output should contain Memory stats")
	}
}

func TestCLIPrintTable(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:  &buf,
		Enabled: true,
	})

	events := []monitor.Event{
		monitor.NewEvent(monitor.EventTypePerformance, "test", monitor.SeverityInfo, "event 1").
			WithContainer("container1"),
		monitor.NewEvent(monitor.EventTypeSecurity, "test", monitor.SeverityWarning, "event 2").
			WithContainer("container2"),
	}

	cli.PrintTable(events)

	output := buf.String()
	if !strings.Contains(output, "TIME") {
		t.Error("Output should contain table header")
	}
	if !strings.Contains(output, "event 1") {
		t.Error("Output should contain event 1")
	}
	if !strings.Contains(output, "event 2") {
		t.Error("Output should contain event 2")
	}
}

func TestCLIPrintTableEmpty(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:  &buf,
		Enabled: true,
	})

	cli.PrintTable([]monitor.Event{})

	if !strings.Contains(buf.String(), "No events") {
		t.Error("Should show 'No events' message for empty list")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
		{1536 * 1024, "1.5 MiB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestCLIVerboseMode(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:     &buf,
		Enabled:    true,
		Verbose:    true,
		ShowPerf:   true,
		ShowSec:    true,
		ShowAlerts: true,
	})

	event := monitor.NewEvent(monitor.EventTypePerformance, "test", monitor.SeverityInfo, "test").
		WithData("key1", "value1").
		WithData("key2", 123)

	cli.Write(event)

	output := buf.String()
	if !strings.Contains(output, "key1=value1") {
		t.Errorf("Verbose mode should include data, got: %s", output)
	}
}

func TestProgressBar(t *testing.T) {
	var buf bytes.Buffer
	cli := NewCLI(CLIConfig{
		Writer:  &buf,
		Enabled: true,
	})

	// Test progress bar colors through PrintStats
	stats := map[string]interface{}{
		"cpu_percent": 50.0,  // Should be green
		"mem_percent": 95.0,  // Should be red
	}

	cli.PrintStats(stats)
	
	output := buf.String()
	// Just verify it doesn't panic and produces output
	if len(output) == 0 {
		t.Error("PrintStats should produce output")
	}
}

func TestCLIStartStopContext(t *testing.T) {
	cli := NewCLI(DefaultCLIConfig())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := cli.Start(ctx); err != nil {
		t.Errorf("Start with context failed: %v", err)
	}

	if err := cli.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}
