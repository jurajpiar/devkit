package podman

import (
	"testing"

	"github.com/jurajpiar/devkit/internal/runtime"
)

func TestNewRuntime(t *testing.T) {
	r := NewRuntime("")

	if r.Connection != "" {
		t.Errorf("NewRuntime(\"\").Connection = %q, want empty", r.Connection)
	}
}

func TestNewRuntimeWithConnection(t *testing.T) {
	r := NewRuntime("my-machine")

	if r.Connection != "my-machine" {
		t.Errorf("NewRuntime(\"my-machine\").Connection = %q, want \"my-machine\"", r.Connection)
	}
}

func TestRuntimeName(t *testing.T) {
	r := NewRuntime("")

	if r.Name() != runtime.BackendPodman {
		t.Errorf("Runtime.Name() = %q, want %q", r.Name(), runtime.BackendPodman)
	}
}

func TestNewVMManager(t *testing.T) {
	m := NewVMManager()

	if m == nil {
		t.Error("NewVMManager() should not return nil")
	}
}

func TestVMManagerName(t *testing.T) {
	m := NewVMManager()

	if m.Name() != runtime.BackendPodman {
		t.Errorf("VMManager.Name() = %q, want %q", m.Name(), runtime.BackendPodman)
	}
}

func TestCheckInstalled(t *testing.T) {
	// This test just verifies the function doesn't panic
	// The result depends on whether podman is installed
	err := CheckInstalled()
	_ = err // Result depends on system
}

// Integration tests (require Podman to be installed)
// These are skipped if Podman is not available

func skipIfNoPodman(t *testing.T) {
	if err := CheckInstalled(); err != nil {
		t.Skip("Podman not installed, skipping integration test")
	}
}

// Note: Full integration tests would require a running Podman machine
// and should be in a separate _integration_test.go file

func TestRuntimeCreateOpts(t *testing.T) {
	// Test that CreateOpts can be converted to podman args
	r := NewRuntime("")

	// This test verifies the Runtime struct can be created
	// Full tests would require a running environment
	if r.Name() != runtime.BackendPodman {
		t.Errorf("Runtime.Name() = %q, want %q", r.Name(), runtime.BackendPodman)
	}
}
