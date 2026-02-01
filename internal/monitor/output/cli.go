package output

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// CLIOutput outputs events to the terminal
type CLIOutput struct {
	writer     io.Writer
	enabled    bool
	mu         sync.Mutex
	verbose    bool
	showPerf   bool
	showSec    bool
	showAlerts bool
}

// CLIConfig holds CLI output configuration
type CLIConfig struct {
	Writer     io.Writer
	Enabled    bool
	Verbose    bool
	ShowPerf   bool
	ShowSec    bool
	ShowAlerts bool
}

// DefaultCLIConfig returns default CLI configuration
func DefaultCLIConfig() CLIConfig {
	return CLIConfig{
		Writer:     os.Stdout,
		Enabled:    true,
		Verbose:    false,
		ShowPerf:   true,
		ShowSec:    true,
		ShowAlerts: true,
	}
}

// NewCLI creates a new CLI output
func NewCLI(cfg CLIConfig) *CLIOutput {
	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}
	return &CLIOutput{
		writer:     cfg.Writer,
		enabled:    cfg.Enabled,
		verbose:    cfg.Verbose,
		showPerf:   cfg.ShowPerf,
		showSec:    cfg.ShowSec,
		showAlerts: cfg.ShowAlerts,
	}
}

// Name returns the output's identifier
func (c *CLIOutput) Name() string {
	return "cli"
}

// Enabled returns whether this output is enabled
func (c *CLIOutput) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// SetEnabled enables or disables the output
func (c *CLIOutput) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// Start initializes the output
func (c *CLIOutput) Start(ctx context.Context) error {
	return nil
}

// Stop cleans up the output
func (c *CLIOutput) Stop() error {
	return nil
}

// Write sends an event to the terminal
func (c *CLIOutput) Write(event monitor.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return nil
	}

	// Filter by event type
	switch event.Type {
	case monitor.EventTypePerformance, monitor.EventTypeResource:
		if !c.showPerf {
			return nil
		}
	case monitor.EventTypeSecurity, monitor.EventTypeNetwork, 
		monitor.EventTypeFileAccess, monitor.EventTypeProcess,
		monitor.EventTypeCapability, monitor.EventTypeBlocked,
		monitor.EventTypeCDP, monitor.EventTypeAudit:
		if !c.showSec {
			return nil
		}
	case monitor.EventTypeAlert, monitor.EventTypeAnomaly:
		if !c.showAlerts {
			return nil
		}
	}

	// Format and print
	line := c.formatEvent(event)
	fmt.Fprintln(c.writer, line)
	return nil
}

// formatEvent formats an event for terminal display
func (c *CLIOutput) formatEvent(event monitor.Event) string {
	timestamp := event.Timestamp.Format("15:04:05")
	severity := c.formatSeverity(event.Severity)
	eventType := c.formatType(event.Type)

	// Basic format
	line := fmt.Sprintf("[%s] %s %s: %s", timestamp, severity, eventType, event.Message)

	// Add container name if present
	if event.Container != "" {
		line = fmt.Sprintf("[%s] %s %s [%s]: %s", 
			timestamp, severity, eventType, event.Container, event.Message)
	}

	// Add data in verbose mode
	if c.verbose && len(event.Data) > 0 {
		line += c.formatData(event.Data)
	}

	return line
}

// formatSeverity formats severity with colors (ANSI)
func (c *CLIOutput) formatSeverity(severity monitor.Severity) string {
	switch severity {
	case monitor.SeverityInfo:
		return "\033[34mINFO\033[0m"
	case monitor.SeverityWarning:
		return "\033[33mWARN\033[0m"
	case monitor.SeverityCritical:
		return "\033[31mCRIT\033[0m"
	default:
		return string(severity)
	}
}

// formatType formats event type
func (c *CLIOutput) formatType(eventType monitor.EventType) string {
	// Abbreviate common types
	abbrev := map[monitor.EventType]string{
		monitor.EventTypePerformance: "PERF",
		monitor.EventTypeResource:    "RSRC",
		monitor.EventTypeSecurity:    "SEC",
		monitor.EventTypeNetwork:     "NET",
		monitor.EventTypeFileAccess:  "FILE",
		monitor.EventTypeProcess:     "PROC",
		monitor.EventTypeCapability:  "CAP",
		monitor.EventTypeAudit:       "AUDIT",
		monitor.EventTypeCDP:         "CDP",
		monitor.EventTypeBlocked:     "BLOCK",
		monitor.EventTypeAlert:       "ALERT",
		monitor.EventTypeAnomaly:     "ANOM",
	}

	if abbr, ok := abbrev[eventType]; ok {
		return abbr
	}
	return strings.ToUpper(string(eventType))
}

// formatData formats event data for display
func (c *CLIOutput) formatData(data map[string]interface{}) string {
	if len(data) == 0 {
		return ""
	}

	parts := make([]string, 0, len(data))
	for k, v := range data {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return " {" + strings.Join(parts, ", ") + "}"
}

// PrintStats prints a formatted stats summary
func (c *CLIOutput) PrintStats(stats map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fmt.Fprintln(c.writer, "\n=== Container Stats ===")
	
	if cpu, ok := stats["cpu_percent"].(float64); ok {
		bar := c.progressBar(cpu, 100, 20)
		fmt.Fprintf(c.writer, "CPU:    %s %.1f%%\n", bar, cpu)
	}

	if mem, ok := stats["mem_percent"].(float64); ok {
		bar := c.progressBar(mem, 100, 20)
		fmt.Fprintf(c.writer, "Memory: %s %.1f%%\n", bar, mem)
	}

	if memUsage, ok := stats["mem_usage"].(uint64); ok {
		if memLimit, ok := stats["mem_limit"].(uint64); ok {
			fmt.Fprintf(c.writer, "        %s / %s\n", 
				formatBytes(memUsage), formatBytes(memLimit))
		}
	}

	if netIn, ok := stats["net_input"].(uint64); ok {
		if netOut, ok := stats["net_output"].(uint64); ok {
			fmt.Fprintf(c.writer, "Net:    %s / %s\n", 
				formatBytes(netIn), formatBytes(netOut))
		}
	}

	if pids, ok := stats["pids"].(int); ok {
		fmt.Fprintf(c.writer, "PIDs:   %d\n", pids)
	}

	fmt.Fprintln(c.writer)
}

// progressBar creates a text progress bar
func (c *CLIOutput) progressBar(value, max float64, width int) string {
	percent := value / max
	if percent > 1 {
		percent = 1
	}
	filled := int(percent * float64(width))
	empty := width - filled

	// Color based on percentage
	var color string
	switch {
	case percent > 0.9:
		color = "\033[31m" // Red
	case percent > 0.7:
		color = "\033[33m" // Yellow
	default:
		color = "\033[32m" // Green
	}

	return fmt.Sprintf("%s[%s%s]\033[0m",
		color,
		strings.Repeat("=", filled),
		strings.Repeat(" ", empty))
}

// PrintTable prints events in a table format
func (c *CLIOutput) PrintTable(events []monitor.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(events) == 0 {
		fmt.Fprintln(c.writer, "No events recorded")
		return
	}

	// Print header
	fmt.Fprintf(c.writer, "%-10s %-6s %-6s %-15s %s\n",
		"TIME", "SEV", "TYPE", "CONTAINER", "MESSAGE")
	fmt.Fprintln(c.writer, strings.Repeat("-", 80))

	// Print events
	for _, e := range events {
		ts := e.Timestamp.Format("15:04:05")
		container := e.Container
		if len(container) > 15 {
			container = container[:12] + "..."
		}
		message := e.Message
		if len(message) > 40 {
			message = message[:37] + "..."
		}
		fmt.Fprintf(c.writer, "%-10s %-6s %-6s %-15s %s\n",
			ts, e.Severity, c.formatType(e.Type), container, message)
	}
}

// WatchMode enables continuous output mode
func (c *CLIOutput) WatchMode(ctx context.Context, interval time.Duration, statsFn func() map[string]interface{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Clear screen and hide cursor
	fmt.Fprint(c.writer, "\033[2J\033[H\033[?25l")
	defer fmt.Fprint(c.writer, "\033[?25h") // Show cursor on exit

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Move cursor to top
			fmt.Fprint(c.writer, "\033[H")
			
			stats := statsFn()
			c.PrintStats(stats)
		}
	}
}

// formatBytes formats bytes to human-readable string
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
