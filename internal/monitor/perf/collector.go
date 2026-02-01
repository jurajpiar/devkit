// Package perf provides performance metrics collection for devkit containers.
package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// Stats represents container performance statistics
type Stats struct {
	ContainerID   string  `json:"container_id"`
	ContainerName string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemUsage      uint64  `json:"mem_usage"`
	MemLimit      uint64  `json:"mem_limit"`
	MemPercent    float64 `json:"mem_percent"`
	NetInput      uint64  `json:"net_input"`
	NetOutput     uint64  `json:"net_output"`
	BlockInput    uint64  `json:"block_input"`
	BlockOutput   uint64  `json:"block_output"`
	PIDs          int     `json:"pids"`
}

// PodmanStats represents the JSON output from podman stats
type PodmanStats struct {
	ContainerID  string `json:"ContainerID"`
	Name         string `json:"Name"`
	CPUPerc      string `json:"CPUPerc"`
	MemUsage     string `json:"MemUsage"`
	MemPerc      string `json:"MemPerc"`
	NetIO        string `json:"NetIO"`
	BlockIO      string `json:"BlockIO"`
	PIDs         string `json:"PIDs"`
}

// Collector collects performance metrics from podman containers
type Collector struct {
	containerName string
	interval      time.Duration
	lastStats     *Stats
}

// New creates a new performance collector
func New(containerName string, interval time.Duration) *Collector {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &Collector{
		containerName: containerName,
		interval:      interval,
	}
}

// Name returns the collector's identifier
func (c *Collector) Name() string {
	return "performance"
}

// Interval returns how often the collector should run
func (c *Collector) Interval() time.Duration {
	return c.interval
}

// Start initializes the collector
func (c *Collector) Start(ctx context.Context) error {
	return nil
}

// Stop cleans up the collector
func (c *Collector) Stop() error {
	return nil
}

// Collect gathers performance metrics
func (c *Collector) Collect(ctx context.Context) ([]monitor.Event, error) {
	stats, err := c.getStats(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]monitor.Event, 0, 2)

	// Create performance event
	perfEvent := monitor.NewEvent(
		monitor.EventTypePerformance,
		c.Name(),
		monitor.SeverityInfo,
		fmt.Sprintf("CPU: %.1f%%, Memory: %.1f%%, PIDs: %d", 
			stats.CPUPercent, stats.MemPercent, stats.PIDs),
	).WithContainer(stats.ContainerName).
		WithData("cpu_percent", stats.CPUPercent).
		WithData("mem_usage", stats.MemUsage).
		WithData("mem_limit", stats.MemLimit).
		WithData("mem_percent", stats.MemPercent).
		WithData("net_input", stats.NetInput).
		WithData("net_output", stats.NetOutput).
		WithData("block_input", stats.BlockInput).
		WithData("block_output", stats.BlockOutput).
		WithData("pids", stats.PIDs)

	events = append(events, perfEvent)

	// Check for resource warnings
	if stats.MemPercent > 90 {
		events = append(events, monitor.NewEvent(
			monitor.EventTypeAlert,
			c.Name(),
			monitor.SeverityWarning,
			fmt.Sprintf("High memory usage: %.1f%%", stats.MemPercent),
		).WithContainer(stats.ContainerName).
			WithData("mem_percent", stats.MemPercent))
	}

	if stats.CPUPercent > 95 {
		events = append(events, monitor.NewEvent(
			monitor.EventTypeAlert,
			c.Name(),
			monitor.SeverityWarning,
			fmt.Sprintf("High CPU usage: %.1f%%", stats.CPUPercent),
		).WithContainer(stats.ContainerName).
			WithData("cpu_percent", stats.CPUPercent))
	}

	c.lastStats = stats
	return events, nil
}

// getStats fetches current container stats from podman
func (c *Collector) getStats(ctx context.Context) (*Stats, error) {
	cmd := exec.CommandContext(ctx, "podman", "stats", "--no-stream", "--format", "json", c.containerName)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("podman stats failed: %w (%s)", err, stderr.String())
	}

	var podmanStats []PodmanStats
	if err := json.Unmarshal(stdout.Bytes(), &podmanStats); err != nil {
		return nil, fmt.Errorf("failed to parse podman stats: %w", err)
	}

	if len(podmanStats) == 0 {
		return nil, fmt.Errorf("no stats returned for container %s", c.containerName)
	}

	return parseStats(&podmanStats[0])
}

// parseStats converts PodmanStats to Stats
func parseStats(ps *PodmanStats) (*Stats, error) {
	stats := &Stats{
		ContainerID:   ps.ContainerID,
		ContainerName: ps.Name,
	}

	// Parse CPU percentage (e.g., "12.34%")
	stats.CPUPercent = parsePercent(ps.CPUPerc)

	// Parse memory usage (e.g., "123.4MiB / 4GiB")
	stats.MemUsage, stats.MemLimit = parseMemUsage(ps.MemUsage)
	stats.MemPercent = parsePercent(ps.MemPerc)

	// Parse network I/O (e.g., "1.23kB / 4.56kB")
	stats.NetInput, stats.NetOutput = parseIO(ps.NetIO)

	// Parse block I/O (e.g., "0B / 1.23MB")
	stats.BlockInput, stats.BlockOutput = parseIO(ps.BlockIO)

	// Parse PIDs
	pids, _ := strconv.Atoi(strings.TrimSpace(ps.PIDs))
	stats.PIDs = pids

	return stats, nil
}

// parsePercent parses a percentage string like "12.34%"
func parsePercent(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "%")
	val, _ := strconv.ParseFloat(s, 64)
	return val
}

// parseMemUsage parses memory usage like "123.4MiB / 4GiB"
func parseMemUsage(s string) (uint64, uint64) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	return parseBytes(strings.TrimSpace(parts[0])), parseBytes(strings.TrimSpace(parts[1]))
}

// parseIO parses I/O strings like "1.23kB / 4.56kB"
func parseIO(s string) (uint64, uint64) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	return parseBytes(strings.TrimSpace(parts[0])), parseBytes(strings.TrimSpace(parts[1]))
}

// parseBytes parses byte strings like "1.23kB", "4.56MiB", "7.89GiB"
func parseBytes(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "--" {
		return 0
	}

	// Define multipliers
	multipliers := map[string]uint64{
		"B":   1,
		"kB":  1000,
		"KB":  1000,
		"KiB": 1024,
		"MB":  1000 * 1000,
		"MiB": 1024 * 1024,
		"GB":  1000 * 1000 * 1000,
		"GiB": 1024 * 1024 * 1024,
		"TB":  1000 * 1000 * 1000 * 1000,
		"TiB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			val, _ := strconv.ParseFloat(numStr, 64)
			return uint64(val * float64(mult))
		}
	}

	// Try parsing as plain number
	val, _ := strconv.ParseUint(s, 10, 64)
	return val
}

// GetLastStats returns the most recent stats
func (c *Collector) GetLastStats() *Stats {
	return c.lastStats
}

// FormatBytes formats bytes to human-readable string
func FormatBytes(b uint64) string {
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
