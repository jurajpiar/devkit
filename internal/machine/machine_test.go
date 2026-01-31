package machine

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func skipIfNoPodman(t *testing.T) {
	t.Helper()
	if err := CheckPodmanInstalled(); err != nil {
		t.Skip("Podman not installed, skipping test")
	}
}

func TestCheckPodmanInstalled(t *testing.T) {
	// This test just verifies the function doesn't panic
	err := CheckPodmanInstalled()
	if err != nil {
		t.Logf("Podman not installed: %v", err)
	} else {
		t.Log("Podman is installed")
	}
}

func TestMachineName(t *testing.T) {
	if MachineName != "devkit" {
		t.Errorf("MachineName = %s, want devkit", MachineName)
	}
}

func TestDefaultInitOptions(t *testing.T) {
	opts := DefaultInitOptions()

	if opts.CPUs != DefaultCPUs {
		t.Errorf("CPUs = %d, want %d", opts.CPUs, DefaultCPUs)
	}

	if opts.MemoryMB != DefaultMemoryMB {
		t.Errorf("MemoryMB = %d, want %d", opts.MemoryMB, DefaultMemoryMB)
	}

	if opts.DiskSizeGB != DefaultDiskSizeGB {
		t.Errorf("DiskSizeGB = %d, want %d", opts.DiskSizeGB, DefaultDiskSizeGB)
	}

	if opts.Rootful != false {
		t.Error("Rootful should be false by default (security)")
	}
}

func TestManagerList(t *testing.T) {
	skipIfNoPodman(t)

	mgr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	machines, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	t.Logf("Found %d Podman machines", len(machines))
	for _, m := range machines {
		t.Logf("  - %s (running: %v)", m.Name, m.Running)
	}
}

func TestManagerExists(t *testing.T) {
	skipIfNoPodman(t)

	mgr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}

	t.Logf("Devkit machine exists: %v", exists)
}

func TestManagerIsRunning(t *testing.T) {
	skipIfNoPodman(t)

	mgr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		t.Fatalf("IsRunning() error: %v", err)
	}

	t.Logf("Devkit machine running: %v", running)
}

// TestMachineLifecycle tests the full machine lifecycle
// This test is slow and modifies system state, so it's skipped by default
func TestMachineLifecycle(t *testing.T) {
	skipIfNoPodman(t)

	if testing.Short() {
		t.Skip("Skipping machine lifecycle test in short mode")
	}

	// Check if we're in CI or have permission to manage machines
	cmd := exec.Command("podman", "machine", "list")
	if err := cmd.Run(); err != nil {
		t.Skip("Cannot manage Podman machines, skipping")
	}

	mgr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Check if machine already exists
	exists, err := mgr.Exists(ctx)
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}

	if exists {
		t.Log("Devkit machine already exists, skipping lifecycle test to avoid disruption")
		t.Skip("Machine exists")
	}

	// Note: We don't actually create the machine in tests by default
	// because it takes several minutes and modifies system state.
	// This test serves as documentation of the expected behavior.

	t.Log("Machine lifecycle test would:")
	t.Log("  1. Init machine with default options")
	t.Log("  2. Start machine")
	t.Log("  3. Verify machine is running")
	t.Log("  4. Stop machine")
	t.Log("  5. Verify machine is stopped")
	t.Log("  6. Remove machine")
	t.Log("  7. Verify machine is removed")
}

func TestGetConnectionString(t *testing.T) {
	skipIfNoPodman(t)

	mgr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exists, _ := mgr.Exists(ctx)
	if !exists {
		t.Skip("Devkit machine does not exist")
	}

	connStr, err := mgr.GetConnectionString(ctx)
	if err != nil {
		t.Logf("GetConnectionString() error: %v", err)
	} else {
		t.Logf("Connection string: %s", connStr)
	}
}
