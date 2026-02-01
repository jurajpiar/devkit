// Package security provides security event monitoring for devkit containers.
package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// SecurityEvent represents a security-relevant event
type SecurityEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Container string    `json:"container"`
	Details   string    `json:"details"`
	Blocked   bool      `json:"blocked"`
}

// Collector collects security events from containers
type Collector struct {
	containerName string
	interval      time.Duration
	events        []SecurityEvent
	mu            sync.Mutex
	
	// Track state for change detection
	lastProcesses map[int]string
	lastConnections []string
}

// New creates a new security collector
func New(containerName string, interval time.Duration) *Collector {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &Collector{
		containerName:   containerName,
		interval:        interval,
		events:          make([]SecurityEvent, 0),
		lastProcesses:   make(map[int]string),
		lastConnections: make([]string, 0),
	}
}

// Name returns the collector's identifier
func (c *Collector) Name() string {
	return "security"
}

// Interval returns how often the collector should run
func (c *Collector) Interval() time.Duration {
	return c.interval
}

// Start initializes the collector
func (c *Collector) Start(ctx context.Context) error {
	// Initialize baseline
	c.getProcessList(ctx)
	c.getNetworkConnections(ctx)
	return nil
}

// Stop cleans up the collector
func (c *Collector) Stop() error {
	return nil
}

// Collect gathers security events
func (c *Collector) Collect(ctx context.Context) ([]monitor.Event, error) {
	events := make([]monitor.Event, 0)

	// Check for new processes
	processEvents, err := c.checkProcesses(ctx)
	if err == nil {
		events = append(events, processEvents...)
	}

	// Check network connections
	networkEvents, err := c.checkNetwork(ctx)
	if err == nil {
		events = append(events, networkEvents...)
	}

	// Check for capability usage (via container inspect)
	capEvents, err := c.checkCapabilities(ctx)
	if err == nil {
		events = append(events, capEvents...)
	}

	// Check resource limits
	limitEvents, err := c.checkResourceLimits(ctx)
	if err == nil {
		events = append(events, limitEvents...)
	}

	return events, nil
}

// checkProcesses detects new process spawning
func (c *Collector) checkProcesses(ctx context.Context) ([]monitor.Event, error) {
	processes, err := c.getProcessList(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]monitor.Event, 0)

	// Detect new processes
	for pid, cmdline := range processes {
		if _, exists := c.lastProcesses[pid]; !exists {
			// New process detected
			severity := monitor.SeverityInfo
			
			// Check for suspicious processes
			if isSuspiciousProcess(cmdline) {
				severity = monitor.SeverityWarning
			}

			events = append(events, monitor.NewEvent(
				monitor.EventTypeProcess,
				c.Name(),
				severity,
				fmt.Sprintf("New process: %s (PID %d)", truncateCmd(cmdline), pid),
			).WithContainer(c.containerName).
				WithData("pid", pid).
				WithData("cmdline", cmdline))
		}
	}

	c.mu.Lock()
	c.lastProcesses = processes
	c.mu.Unlock()

	return events, nil
}

// checkNetwork monitors network connections
func (c *Collector) checkNetwork(ctx context.Context) ([]monitor.Event, error) {
	connections, err := c.getNetworkConnections(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]monitor.Event, 0)

	// Track which connections are new
	lastSet := make(map[string]bool)
	for _, conn := range c.lastConnections {
		lastSet[conn] = true
	}

	for _, conn := range connections {
		if !lastSet[conn] {
			// New connection
			severity := monitor.SeverityInfo
			
			// Check for suspicious connections
			if isSuspiciousConnection(conn) {
				severity = monitor.SeverityWarning
			}

			events = append(events, monitor.NewEvent(
				monitor.EventTypeNetwork,
				c.Name(),
				severity,
				fmt.Sprintf("Network connection: %s", conn),
			).WithContainer(c.containerName).
				WithData("connection", conn))
		}
	}

	c.mu.Lock()
	c.lastConnections = connections
	c.mu.Unlock()

	return events, nil
}

// checkCapabilities checks for capability usage
func (c *Collector) checkCapabilities(ctx context.Context) ([]monitor.Event, error) {
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{json .HostConfig.CapAdd}}", c.containerName)
	
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var caps []string
	if err := json.Unmarshal(stdout.Bytes(), &caps); err != nil {
		return nil, err
	}

	events := make([]monitor.Event, 0)
	for _, cap := range caps {
		// Report added capabilities as security events
		events = append(events, monitor.NewEvent(
			monitor.EventTypeCapability,
			c.Name(),
			monitor.SeverityInfo,
			fmt.Sprintf("Container has capability: %s", cap),
		).WithContainer(c.containerName).
			WithData("capability", cap))
	}

	return events, nil
}

// checkResourceLimits checks if container is hitting resource limits
func (c *Collector) checkResourceLimits(ctx context.Context) ([]monitor.Event, error) {
	// Check OOM events using podman events (non-blocking check)
	cmd := exec.CommandContext(ctx, "podman", "events", 
		"--filter", fmt.Sprintf("container=%s", c.containerName),
		"--filter", "event=oom",
		"--since", "10s",
		"--format", "json",
		"--no-trunc")
	
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	// Use timeout to prevent blocking
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := cmd.Run(); err != nil {
		// Ignore errors - events command might not have data
		return nil, nil
	}

	events := make([]monitor.Event, 0)
	
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "oom") {
			events = append(events, monitor.NewEvent(
				monitor.EventTypeAlert,
				c.Name(),
				monitor.SeverityCritical,
				"Container hit OOM (Out of Memory) limit",
			).WithContainer(c.containerName))
		}
	}

	return events, nil
}

// getProcessList returns map of PID -> cmdline
func (c *Collector) getProcessList(ctx context.Context) (map[int]string, error) {
	cmd := exec.CommandContext(ctx, "podman", "exec", c.containerName, "ps", "aux")
	
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	processes := make(map[int]string)
	scanner := bufio.NewScanner(&stdout)
	
	// Skip header
	scanner.Scan()
	
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 11 {
			pid, _ := strconv.Atoi(fields[1])
			cmdline := strings.Join(fields[10:], " ")
			processes[pid] = cmdline
		}
	}

	return processes, nil
}

// getNetworkConnections returns active network connections
func (c *Collector) getNetworkConnections(ctx context.Context) ([]string, error) {
	// Try ss first, fall back to netstat
	cmd := exec.CommandContext(ctx, "podman", "exec", c.containerName, "ss", "-tuln")
	
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		// Try netstat as fallback
		cmd = exec.CommandContext(ctx, "podman", "exec", c.containerName, "netstat", "-tuln")
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			return nil, err
		}
	}

	connections := make([]string, 0)
	scanner := bufio.NewScanner(&stdout)
	
	// Skip header(s)
	scanner.Scan()
	scanner.Scan()
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			connections = append(connections, line)
		}
	}

	return connections, nil
}

// AddEvent adds a custom security event
func (c *Collector) AddEvent(event SecurityEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	event.Timestamp = time.Now()
	c.events = append(c.events, event)
}

// GetEvents returns collected events
func (c *Collector) GetEvents() []SecurityEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	result := make([]SecurityEvent, len(c.events))
	copy(result, c.events)
	return result
}

// isSuspiciousProcess checks if a process name/cmdline is suspicious
func isSuspiciousProcess(cmdline string) bool {
	suspicious := []string{
		"nc ", "netcat", "ncat",       // Network tools
		"curl ", "wget ",               // Download tools
		"python -c", "python3 -c",     // Inline scripts
		"bash -c", "sh -c",            // Shell commands
		"base64",                       // Encoding
		"/dev/tcp",                     // Bash network
		"reverse", "shell",            // Common malware terms
	}
	
	lower := strings.ToLower(cmdline)
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// isSuspiciousConnection checks if a connection is suspicious
func isSuspiciousConnection(conn string) bool {
	// Check for connections to common malicious ports
	suspiciousPorts := []string{
		":4444", ":5555", ":6666", // Common reverse shell ports
		":1337",                    // Leet port
		":31337",                   // Elite port
	}
	
	for _, port := range suspiciousPorts {
		if strings.Contains(conn, port) {
			return true
		}
	}
	return false
}

// truncateCmd truncates a command line for display
func truncateCmd(cmd string) string {
	if len(cmd) > 80 {
		return cmd[:77] + "..."
	}
	return cmd
}
