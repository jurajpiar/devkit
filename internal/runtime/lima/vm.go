// Package lima provides a Lima-based implementation of the runtime interfaces.
// Lima enables true per-project VM isolation (double isolation) on macOS.
package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/runtime"
)

const (
	// VMPrefix is the prefix for all Lima VMs created by devkit
	VMPrefix = "devkit-"
)

// VMManager implements the runtime.VMManager interface for Lima
type VMManager struct {
	// ConfigDir is the directory for Lima VM configs (default: ~/.devkit/lima)
	ConfigDir string
}

// NewVMManager creates a new Lima VM manager
func NewVMManager() *VMManager {
	homeDir, _ := os.UserHomeDir()
	return &VMManager{
		ConfigDir: filepath.Join(homeDir, ".devkit", "lima"),
	}
}

// Name returns the VM manager name
func (m *VMManager) Name() runtime.Backend {
	return runtime.BackendLima
}

// Create creates a new Lima VM
func (m *VMManager) Create(ctx context.Context, name string, opts runtime.VMOpts) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("VM '%s' already exists", name)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(m.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate Lima YAML config
	configPath := filepath.Join(m.ConfigDir, name+".yaml")
	if err := m.generateConfig(configPath, opts); err != nil {
		return fmt.Errorf("failed to generate VM config: %w", err)
	}

	// Create the VM
	_, err = m.runLimactl(ctx, "create", "--name", name, configPath)
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	return nil
}

// Start starts a Lima VM
func (m *VMManager) Start(ctx context.Context, name string) error {
	running, err := m.IsRunning(ctx, name)
	if err != nil {
		return err
	}

	if running {
		return nil // Already running
	}

	_, err = m.runLimactl(ctx, "start", name)
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// Wait for VM to be ready
	return m.waitForReady(ctx, name, 120*time.Second)
}

// Stop stops a Lima VM
func (m *VMManager) Stop(ctx context.Context, name string) error {
	running, err := m.IsRunning(ctx, name)
	if err != nil {
		return err
	}

	if !running {
		return nil // Already stopped
	}

	_, err = m.runLimactl(ctx, "stop", name)
	if err != nil {
		return fmt.Errorf("failed to stop VM: %w", err)
	}

	return nil
}

// Remove removes a Lima VM
func (m *VMManager) Remove(ctx context.Context, name string, force bool) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		return nil
	}

	args := []string{"delete", name}
	if force {
		args = append(args, "--force")
	}

	_, err = m.runLimactl(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to remove VM: %w", err)
	}

	// Also remove the config file
	configPath := filepath.Join(m.ConfigDir, name+".yaml")
	os.Remove(configPath)

	return nil
}

// Exists checks if a Lima VM exists
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

// IsRunning checks if a Lima VM is running
func (m *VMManager) IsRunning(ctx context.Context, name string) (bool, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return false, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return vm.Status == "Running", nil
		}
	}

	return false, nil
}

// GetInfo returns information about a Lima VM
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

	return nil, fmt.Errorf("VM '%s' not found", name)
}

// limaVMInfo represents the JSON structure returned by limactl list
type limaVMInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Arch   string `json:"arch"`
	CPUs   int    `json:"cpus"`
	Memory int64  `json:"memory"`
	Disk   int64  `json:"disk"`
	VMType string `json:"vmType"`
}

// List returns all Lima VMs (filtered to devkit- prefix)
func (m *VMManager) List(ctx context.Context) ([]runtime.VMInfo, error) {
	output, err := m.runLimactl(ctx, "list", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}

	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return []runtime.VMInfo{}, nil
	}

	// Lima outputs newline-delimited JSON (one object per line), not a JSON array
	var vms []limaVMInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var vm limaVMInfo
		if err := json.Unmarshal([]byte(line), &vm); err != nil {
			// Skip lines that don't parse (could be header or other output)
			continue
		}
		vms = append(vms, vm)
	}

	// Filter to only devkit VMs
	result := make([]runtime.VMInfo, 0)
	for _, vm := range vms {
		if !strings.HasPrefix(vm.Name, VMPrefix) {
			continue // Skip non-devkit VMs
		}

		result = append(result, runtime.VMInfo{
			Name:   vm.Name,
			Status: vm.Status,
			Arch:   vm.Arch,
			CPUs:   vm.CPUs,
			Memory: formatBytes(vm.Memory),
			Disk:   formatBytes(vm.Disk),
			VMType: vm.VMType,
		})
	}

	return result, nil
}

// GetRunning returns the currently running devkit VM (if any)
func (m *VMManager) GetRunning(ctx context.Context) (*runtime.VMInfo, error) {
	vms, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Status == "Running" {
			return &vm, nil
		}
	}

	return nil, nil
}

// SetDefault is a no-op for Lima (not applicable)
func (m *VMManager) SetDefault(ctx context.Context, name string) error {
	// Lima doesn't have a "default" concept like Podman
	return nil
}

// Shell runs a command inside the VM
func (m *VMManager) Shell(ctx context.Context, name string, cmd ...string) (string, error) {
	args := append([]string{"shell", name}, cmd...)
	return m.runLimactl(ctx, args...)
}

// EnsureRunning ensures a VM exists and is running
func (m *VMManager) EnsureRunning(ctx context.Context, name string, opts runtime.VMOpts) error {
	exists, err := m.Exists(ctx, name)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Printf("Creating Lima VM '%s' (this may take a few minutes)...\n", name)
		if err := m.Create(ctx, name, opts); err != nil {
			return err
		}
		fmt.Printf("VM '%s' created\n", name)
	}

	running, err := m.IsRunning(ctx, name)
	if err != nil {
		return err
	}

	if !running {
		fmt.Printf("Starting Lima VM '%s' (this may take 1-2 minutes)...\n", name)
		if err := m.Start(ctx, name); err != nil {
			return err
		}
		fmt.Printf("VM '%s' started\n", name)
	}

	return nil
}

// StopAll stops all devkit Lima VMs
func (m *VMManager) StopAll(ctx context.Context) error {
	vms, err := m.List(ctx)
	if err != nil {
		return err
	}

	for _, vm := range vms {
		if vm.Status == "Running" {
			fmt.Printf("Stopping VM '%s'...\n", vm.Name)
			if err := m.Stop(ctx, vm.Name); err != nil {
				return fmt.Errorf("failed to stop VM '%s': %w", vm.Name, err)
			}
		}
	}

	return nil
}

// waitForReady waits for the VM to be ready
func (m *VMManager) waitForReady(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		running, err := m.IsRunning(ctx, name)
		if err == nil && running {
			// Try a simple command to verify it's truly ready
			_, err := m.Shell(ctx, name, "uname", "-a")
			if err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
			continue
		}
	}

	return fmt.Errorf("timeout waiting for VM '%s' to be ready", name)
}

// runLimactl executes a limactl command
func (m *VMManager) runLimactl(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "limactl", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// formatBytes formats bytes to human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CheckInstalled verifies that Lima is available
func CheckInstalled() error {
	cmd := exec.Command("limactl", "--version")
	if err := cmd.Run(); err != nil {
		return runtime.ErrNotInstalled{Runtime: runtime.BackendLima}
	}
	return nil
}
