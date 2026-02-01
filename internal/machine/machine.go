// Package machine manages the devkit Podman machine
package machine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// MachineName is the name of the devkit Podman machine
	MachineName = "devkit"

	// DefaultCPUs for the devkit machine
	DefaultCPUs = 2

	// DefaultMemoryMB for the devkit machine (4GB)
	DefaultMemoryMB = 4096

	// DefaultDiskSizeGB for the devkit machine
	DefaultDiskSizeGB = 20
)

// MachineInfo contains information about a Podman machine
type MachineInfo struct {
	Name       string `json:"Name"`
	Running    bool   `json:"Running"`
	Starting   bool   `json:"Starting"`
	CPUs       int    `json:"CPUs"`
	Memory     string `json:"Memory"`
	DiskSize   string `json:"DiskSize"`
	LastUp     string `json:"LastUp"`
	VMType     string `json:"VMType"`
	Port       int    `json:"Port"`
	Default    bool   `json:"Default"`
}

// Manager handles Podman machine lifecycle
type Manager struct{}

// New creates a new machine Manager
func New() *Manager {
	return &Manager{}
}

// Exists checks if the devkit machine exists
func (m *Manager) Exists(ctx context.Context) (bool, error) {
	return m.ExistsNamed(ctx, MachineName)
}

// ExistsNamed checks if a machine with the given name exists
func (m *Manager) ExistsNamed(ctx context.Context, name string) (bool, error) {
	machines, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, machine := range machines {
		if machine.Name == name {
			return true, nil
		}
	}

	return false, nil
}

// IsRunning checks if the devkit machine is running
func (m *Manager) IsRunning(ctx context.Context) (bool, error) {
	return m.IsRunningNamed(ctx, MachineName)
}

// IsRunningNamed checks if a machine with the given name is running
func (m *Manager) IsRunningNamed(ctx context.Context, name string) (bool, error) {
	machines, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, machine := range machines {
		if machine.Name == name {
			return machine.Running, nil
		}
	}

	return false, nil
}

// List returns all Podman machines
func (m *Manager) List(ctx context.Context) ([]MachineInfo, error) {
	output, err := m.runPodman(ctx, "machine", "list", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list machines: %w", err)
	}

	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return []MachineInfo{}, nil
	}

	var machines []MachineInfo
	if err := json.Unmarshal([]byte(output), &machines); err != nil {
		return nil, fmt.Errorf("failed to parse machine list: %w", err)
	}

	return machines, nil
}

// GetInfo returns information about the devkit machine
func (m *Manager) GetInfo(ctx context.Context) (*MachineInfo, error) {
	machines, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, machine := range machines {
		if machine.Name == MachineName {
			return &machine, nil
		}
	}

	return nil, fmt.Errorf("devkit machine not found")
}

// InitOptions contains options for initializing the machine
type InitOptions struct {
	CPUs       int
	MemoryMB   int
	DiskSizeGB int
	Rootful    bool
}

// DefaultInitOptions returns default initialization options
func DefaultInitOptions() InitOptions {
	return InitOptions{
		CPUs:       DefaultCPUs,
		MemoryMB:   DefaultMemoryMB,
		DiskSizeGB: DefaultDiskSizeGB,
		Rootful:    false, // Rootless by default for security
	}
}

// Init initializes the devkit Podman machine
func (m *Manager) Init(ctx context.Context, opts InitOptions) error {
	return m.InitNamed(ctx, MachineName, opts)
}

// InitNamed initializes a Podman machine with the given name
func (m *Manager) InitNamed(ctx context.Context, name string, opts InitOptions) error {
	exists, err := m.ExistsNamed(ctx, name)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("machine '%s' already exists", name)
	}

	args := []string{
		"machine", "init",
		"--cpus", fmt.Sprintf("%d", opts.CPUs),
		"--memory", fmt.Sprintf("%d", opts.MemoryMB),
		"--disk-size", fmt.Sprintf("%d", opts.DiskSizeGB),
	}

	if opts.Rootful {
		args = append(args, "--rootful")
	}

	args = append(args, name)

	_, err = m.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to initialize machine: %w", err)
	}

	return nil
}

// Start starts the devkit machine
func (m *Manager) Start(ctx context.Context) error {
	return m.StartNamed(ctx, MachineName, false)
}

// StartNamed starts a Podman machine with the given name
// If stopOthers is true, it will stop other running machines first (for total isolation)
func (m *Manager) StartNamed(ctx context.Context, name string, stopOthers bool) error {
	running, err := m.IsRunningNamed(ctx, name)
	if err != nil {
		return err
	}

	if running {
		// Already running, just ensure it's the default
		m.SetDefaultNamed(ctx, name)
		return nil
	}

	// Check if another machine is running (Podman only allows one VM at a time)
	otherRunning, otherName, err := m.GetRunningMachine(ctx)
	if err != nil {
		return err
	}

	if otherRunning && otherName != name {
		if stopOthers {
			// For total isolation mode, stop other machines automatically
			fmt.Printf("[%s] Stopping machine '%s' for total isolation...\n", timestamp(), otherName)
			if err := m.StopNamed(ctx, otherName); err != nil {
				return fmt.Errorf("failed to stop machine '%s': %w", otherName, err)
			}
			fmt.Printf("[%s] Machine '%s' stopped\n", timestamp(), otherName)
		} else {
			return fmt.Errorf("another Podman machine '%s' is already running.\n"+
				"Podman only allows one VM at a time.\n"+
				"Options:\n"+
				"  1. Stop the other machine: podman machine stop %s\n"+
				"  2. Use the existing machine: devkit machine use-existing\n"+
				"  3. Stop all machines: devkit machine stop-all",
				otherName, otherName)
		}
	}

	// Set as default connection BEFORE starting
	// This prevents podman commands from trying to connect to a stopped machine
	if err := m.SetDefaultNamed(ctx, name); err != nil {
		// Non-fatal, but log it
		fmt.Printf("[%s] Note: could not pre-set default connection: %v\n", timestamp(), err)
	}

	_, err = m.runPodman(ctx, "machine", "start", name)
	if err != nil {
		return fmt.Errorf("failed to start machine: %w", err)
	}

	// Ensure default is set after start (in case pre-set failed)
	m.SetDefaultNamed(ctx, name)

	// Wait for machine to be ready
	return m.waitForReadyNamed(ctx, name, 90*time.Second)
}

// GetRunningMachine returns the name of the currently running machine, if any
func (m *Manager) GetRunningMachine(ctx context.Context) (bool, string, error) {
	machines, err := m.List(ctx)
	if err != nil {
		return false, "", err
	}

	for _, machine := range machines {
		if machine.Running {
			return true, machine.Name, nil
		}
	}

	return false, "", nil
}

// StopAll stops all running Podman machines
func (m *Manager) StopAll(ctx context.Context) error {
	machines, err := m.List(ctx)
	if err != nil {
		return err
	}

	for _, machine := range machines {
		if machine.Running {
			fmt.Printf("[%s] Stopping machine: %s\n", timestamp(), machine.Name)
			_, err := m.runPodman(ctx, "machine", "stop", machine.Name)
			if err != nil {
				return fmt.Errorf("failed to stop machine %s: %w", machine.Name, err)
			}
			fmt.Printf("[%s] Machine '%s' stopped\n", timestamp(), machine.Name)
		}
	}

	return nil
}

// UseExisting checks if an existing running machine can be used
func (m *Manager) UseExisting(ctx context.Context) (string, error) {
	running, name, err := m.GetRunningMachine(ctx)
	if err != nil {
		return "", err
	}

	if !running {
		return "", fmt.Errorf("no Podman machine is currently running")
	}

	return name, nil
}

// Stop stops the devkit machine
func (m *Manager) Stop(ctx context.Context) error {
	return m.StopNamed(ctx, MachineName)
}

// StopNamed stops a Podman machine with the given name
func (m *Manager) StopNamed(ctx context.Context, name string) error {
	running, err := m.IsRunningNamed(ctx, name)
	if err != nil {
		return err
	}

	if !running {
		return nil // Already stopped
	}

	_, err = m.runPodman(ctx, "machine", "stop", name)
	if err != nil {
		return fmt.Errorf("failed to stop machine: %w", err)
	}

	return nil
}

// Remove removes the devkit machine
func (m *Manager) Remove(ctx context.Context, force bool) error {
	return m.RemoveNamed(ctx, MachineName, force)
}

// RemoveNamed removes a Podman machine with the given name
func (m *Manager) RemoveNamed(ctx context.Context, name string, force bool) error {
	exists, err := m.ExistsNamed(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		return nil // Doesn't exist
	}

	args := []string{"machine", "rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)

	_, err = m.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to remove machine: %w", err)
	}

	return nil
}

// SetDefault sets the devkit machine as the default connection
func (m *Manager) SetDefault(ctx context.Context) error {
	return m.SetDefaultNamed(ctx, MachineName)
}

// SetDefaultNamed sets a Podman machine as the default connection
func (m *Manager) SetDefaultNamed(ctx context.Context, name string) error {
	_, err := m.runPodman(ctx, "system", "connection", "default", name)
	if err != nil {
		return fmt.Errorf("failed to set default connection: %w", err)
	}

	return nil
}

// EnsureRunning ensures the devkit machine exists and is running
func (m *Manager) EnsureRunning(ctx context.Context) error {
	return m.EnsureRunningNamed(ctx, MachineName, false)
}

// EnsureRunningNamed ensures a Podman machine exists and is running
// If stopOthers is true, it will stop other running machines first (for total isolation)
func (m *Manager) EnsureRunningNamed(ctx context.Context, name string, stopOthers bool) error {
	exists, err := m.ExistsNamed(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Printf("[%s] Initializing Podman machine '%s' (this may take a few minutes)...\n", timestamp(), name)
		if err := m.InitNamed(ctx, name, DefaultInitOptions()); err != nil {
			return err
		}
		fmt.Printf("[%s] Machine initialized\n", timestamp())
	}

	running, err := m.IsRunningNamed(ctx, name)
	if err != nil {
		return err
	}

	if !running {
		fmt.Printf("[%s] Starting Podman machine '%s' (this may take 1-2 minutes)...\n", timestamp(), name)
		if err := m.StartNamed(ctx, name, stopOthers); err != nil {
			return err
		}
		fmt.Printf("[%s] Machine started\n", timestamp())
	}

	// Set as default connection
	if err := m.SetDefaultNamed(ctx, name); err != nil {
		return err
	}

	return nil
}

// timestamp returns current time formatted for logs
func timestamp() string {
	return time.Now().Format("15:04:05")
}

// SSH opens an SSH session to the devkit machine
func (m *Manager) SSH(ctx context.Context, command ...string) (string, error) {
	args := []string{"machine", "ssh", MachineName}
	args = append(args, command...)

	return m.runPodman(ctx, args...)
}

// waitForReady waits for the machine to be ready
func (m *Manager) waitForReady(ctx context.Context, timeout time.Duration) error {
	return m.waitForReadyNamed(ctx, MachineName, timeout)
}

// waitForReadyNamed waits for a specific machine to be ready
func (m *Manager) waitForReadyNamed(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		running, err := m.IsRunningNamed(ctx, name)
		if err == nil && running {
			// Try a simple command to verify it's truly ready
			_, err := m.runPodman(ctx, "info", "--format", "{{.Host.Os}}")
			if err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			continue
		}
	}

	return fmt.Errorf("timeout waiting for machine '%s' to be ready", name)
}

// runPodman executes a podman command
func (m *Manager) runPodman(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// CheckPodmanInstalled verifies that podman is installed
func CheckPodmanInstalled() error {
	cmd := exec.Command("podman", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman not found: %w", err)
	}
	return nil
}

// GetConnectionString returns the connection string for the devkit machine
func (m *Manager) GetConnectionString(ctx context.Context) (string, error) {
	output, err := m.runPodman(ctx, "system", "connection", "list", "--format", "json")
	if err != nil {
		return "", err
	}

	var connections []struct {
		Name string `json:"Name"`
		URI  string `json:"URI"`
	}

	if err := json.Unmarshal([]byte(output), &connections); err != nil {
		return "", err
	}

	for _, conn := range connections {
		if strings.Contains(conn.Name, MachineName) {
			return conn.URI, nil
		}
	}

	return "", fmt.Errorf("connection for devkit machine not found")
}
