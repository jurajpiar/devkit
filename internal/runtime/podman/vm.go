package podman

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/runtime"
)

// VMManager implements the runtime.VMManager interface for Podman machines
type VMManager struct{}

// NewVMManager creates a new Podman VM manager
func NewVMManager() *VMManager {
	return &VMManager{}
}

// Name returns the VM manager name
func (m *VMManager) Name() runtime.Backend {
	return runtime.BackendPodman
}

// Create creates a new Podman machine
func (m *VMManager) Create(ctx context.Context, name string, opts runtime.VMOpts) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("machine '%s' already exists", name)
	}

	// Set defaults
	cpus := opts.CPUs
	if cpus <= 0 {
		cpus = 2
	}
	memoryMB := opts.MemoryMB
	if memoryMB <= 0 {
		memoryMB = 4096
	}
	diskGB := opts.DiskSizeGB
	if diskGB <= 0 {
		diskGB = 20
	}

	args := []string{
		"machine", "init",
		"--cpus", fmt.Sprintf("%d", cpus),
		"--memory", fmt.Sprintf("%d", memoryMB),
		"--disk-size", fmt.Sprintf("%d", diskGB),
		name,
	}

	_, err = m.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to initialize machine: %w", err)
	}

	return nil
}

// Start starts a Podman machine
func (m *VMManager) Start(ctx context.Context, name string) error {
	running, err := m.IsRunning(ctx, name)
	if err != nil {
		return err
	}

	if running {
		// Already running, ensure it's the default
		m.SetDefault(ctx, name)
		return nil
	}

	// Check if another machine is running
	runningVM, err := m.GetRunning(ctx)
	if err != nil {
		return err
	}

	if runningVM != nil && runningVM.Name != name {
		return fmt.Errorf("another Podman machine '%s' is already running.\n"+
			"Podman only allows one VM at a time.\n"+
			"Options:\n"+
			"  1. Stop the other machine: devkit vm stop %s\n"+
			"  2. Use the existing machine: devkit vm list",
			runningVM.Name, runningVM.Name)
	}

	// Set as default connection BEFORE starting
	if err := m.SetDefault(ctx, name); err != nil {
		// Non-fatal
		fmt.Printf("Note: could not pre-set default connection: %v\n", err)
	}

	_, err = m.runPodman(ctx, "machine", "start", name)
	if err != nil {
		return fmt.Errorf("failed to start machine: %w", err)
	}

	// Ensure default is set after start
	m.SetDefault(ctx, name)

	// Wait for machine to be ready
	return m.waitForReady(ctx, name, 90*time.Second)
}

// Stop stops a Podman machine
func (m *VMManager) Stop(ctx context.Context, name string) error {
	running, err := m.IsRunning(ctx, name)
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

// Remove removes a Podman machine
func (m *VMManager) Remove(ctx context.Context, name string, force bool) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		return nil
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

// Exists checks if a Podman machine exists
func (m *VMManager) Exists(ctx context.Context, name string) (bool, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return true, nil
		}
	}

	return false, nil
}

// IsRunning checks if a Podman machine is running
func (m *VMManager) IsRunning(ctx context.Context, name string) (bool, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return vm.Status == "running", nil
		}
	}

	return false, nil
}

// GetInfo returns information about a Podman machine
func (m *VMManager) GetInfo(ctx context.Context, name string) (*runtime.VMInfo, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("machine '%s' not found", name)
}

// List returns all Podman machines
func (m *VMManager) List(ctx context.Context) ([]runtime.VMInfo, error) {
	output, err := m.runPodman(ctx, "machine", "list", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list machines: %w", err)
	}

	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return []runtime.VMInfo{}, nil
	}

	var machines []struct {
		Name       string `json:"Name"`
		Running    bool   `json:"Running"`
		Starting   bool   `json:"Starting"`
		CPUs       int    `json:"CPUs"`
		Memory     string `json:"Memory"`
		DiskSize   string `json:"DiskSize"`
		VMType     string `json:"VMType"`
		Default    bool   `json:"Default"`
	}

	if err := json.Unmarshal([]byte(output), &machines); err != nil {
		return nil, fmt.Errorf("failed to parse machine list: %w", err)
	}

	result := make([]runtime.VMInfo, len(machines))
	for i, m := range machines {
		status := "stopped"
		if m.Running {
			status = "running"
		} else if m.Starting {
			status = "starting"
		}

		result[i] = runtime.VMInfo{
			Name:    m.Name,
			Status:  status,
			CPUs:    m.CPUs,
			Memory:  m.Memory,
			Disk:    m.DiskSize,
			VMType:  m.VMType,
			Default: m.Default,
		}
	}

	return result, nil
}

// GetRunning returns the currently running VM
func (m *VMManager) GetRunning(ctx context.Context) (*runtime.VMInfo, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Status == "running" {
			return &vm, nil
		}
	}

	return nil, nil
}

// SetDefault sets a Podman machine as the default connection
func (m *VMManager) SetDefault(ctx context.Context, name string) error {
	_, err := m.runPodman(ctx, "system", "connection", "default", name)
	if err != nil {
		return fmt.Errorf("failed to set default connection: %w", err)
	}
	return nil
}

// Shell runs a command in the VM via SSH
func (m *VMManager) Shell(ctx context.Context, name string, cmd ...string) (string, error) {
	args := append([]string{"machine", "ssh", name}, cmd...)
	return m.runPodman(ctx, args...)
}

// waitForReady waits for the machine to be ready
func (m *VMManager) waitForReady(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		running, err := m.IsRunning(ctx, name)
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

// EnsureRunning ensures a VM exists and is running
func (m *VMManager) EnsureRunning(ctx context.Context, name string, opts runtime.VMOpts) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Printf("Initializing VM '%s' (this may take a few minutes)...\n", name)
		if err := m.Create(ctx, name, opts); err != nil {
			return err
		}
		fmt.Printf("VM '%s' initialized\n", name)
	}

	running, err := m.IsRunning(ctx, name)
	if err != nil {
		return err
	}

	if !running {
		fmt.Printf("Starting VM '%s' (this may take 1-2 minutes)...\n", name)
		if err := m.Start(ctx, name); err != nil {
			return err
		}
		fmt.Printf("VM '%s' started\n", name)
	}

	return m.SetDefault(ctx, name)
}

// StopOthers stops all VMs except the specified one
func (m *VMManager) StopOthers(ctx context.Context, exceptName string) error {
	vms, err := m.List(ctx)
	if err != nil {
		return err
	}

	for _, vm := range vms {
		if vm.Status == "running" && vm.Name != exceptName {
			fmt.Printf("Stopping VM '%s' for isolation...\n", vm.Name)
			if err := m.Stop(ctx, vm.Name); err != nil {
				return fmt.Errorf("failed to stop VM '%s': %w", vm.Name, err)
			}
		}
	}

	return nil
}

// runPodman executes a podman command
func (m *VMManager) runPodman(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}
