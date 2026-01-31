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
	machines, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, machine := range machines {
		if machine.Name == MachineName {
			return true, nil
		}
	}

	return false, nil
}

// IsRunning checks if the devkit machine is running
func (m *Manager) IsRunning(ctx context.Context) (bool, error) {
	machines, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, machine := range machines {
		if machine.Name == MachineName {
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
	exists, err := m.Exists(ctx)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("devkit machine already exists")
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

	args = append(args, MachineName)

	_, err = m.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to initialize machine: %w", err)
	}

	return nil
}

// Start starts the devkit machine
func (m *Manager) Start(ctx context.Context) error {
	running, err := m.IsRunning(ctx)
	if err != nil {
		return err
	}

	if running {
		return nil // Already running
	}

	_, err = m.runPodman(ctx, "machine", "start", MachineName)
	if err != nil {
		return fmt.Errorf("failed to start machine: %w", err)
	}

	// Wait for machine to be ready
	return m.waitForReady(ctx, 60*time.Second)
}

// Stop stops the devkit machine
func (m *Manager) Stop(ctx context.Context) error {
	running, err := m.IsRunning(ctx)
	if err != nil {
		return err
	}

	if !running {
		return nil // Already stopped
	}

	_, err = m.runPodman(ctx, "machine", "stop", MachineName)
	if err != nil {
		return fmt.Errorf("failed to stop machine: %w", err)
	}

	return nil
}

// Remove removes the devkit machine
func (m *Manager) Remove(ctx context.Context, force bool) error {
	exists, err := m.Exists(ctx)
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
	args = append(args, MachineName)

	_, err = m.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to remove machine: %w", err)
	}

	return nil
}

// SetDefault sets the devkit machine as the default connection
func (m *Manager) SetDefault(ctx context.Context) error {
	// Get the connection name (usually machine-name-root or machine-name)
	connectionName := MachineName

	_, err := m.runPodman(ctx, "system", "connection", "default", connectionName)
	if err != nil {
		// Try with just the machine name
		return fmt.Errorf("failed to set default connection: %w", err)
	}

	return nil
}

// EnsureRunning ensures the devkit machine exists and is running
func (m *Manager) EnsureRunning(ctx context.Context) error {
	exists, err := m.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Println("Initializing devkit Podman machine...")
		if err := m.Init(ctx, DefaultInitOptions()); err != nil {
			return err
		}
	}

	running, err := m.IsRunning(ctx)
	if err != nil {
		return err
	}

	if !running {
		fmt.Println("Starting devkit Podman machine...")
		if err := m.Start(ctx); err != nil {
			return err
		}
	}

	return nil
}

// SSH opens an SSH session to the devkit machine
func (m *Manager) SSH(ctx context.Context, command ...string) (string, error) {
	args := []string{"machine", "ssh", MachineName}
	args = append(args, command...)

	return m.runPodman(ctx, args...)
}

// waitForReady waits for the machine to be ready
func (m *Manager) waitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		running, err := m.IsRunning(ctx)
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

	return fmt.Errorf("timeout waiting for machine to be ready")
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
