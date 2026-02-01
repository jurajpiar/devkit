package runtime

import (
	"context"
	"testing"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory(BackendPodman)

	if factory.Backend() != BackendPodman {
		t.Errorf("Factory.Backend() = %q, want %q", factory.Backend(), BackendPodman)
	}
}

func TestFactoryWithVMName(t *testing.T) {
	factory := NewFactory(BackendLima).WithVMName("test-vm")

	if factory.VMName() != "test-vm" {
		t.Errorf("Factory.VMName() = %q, want %q", factory.VMName(), "test-vm")
	}
}

func TestFactoryWithLimaOpts(t *testing.T) {
	opts := VMOpts{
		CPUs:     8,
		MemoryMB: 16384,
	}
	factory := NewFactory(BackendLima).WithLimaOpts(opts)

	if factory.limaOpts.CPUs != 8 {
		t.Errorf("Factory.limaOpts.CPUs = %d, want 8", factory.limaOpts.CPUs)
	}
	if factory.limaOpts.MemoryMB != 16384 {
		t.Errorf("Factory.limaOpts.MemoryMB = %d, want 16384", factory.limaOpts.MemoryMB)
	}
}

func TestFactoryWithPodmanMachine(t *testing.T) {
	factory := NewFactory(BackendPodman).WithPodmanMachine("devkit-custom")

	if factory.podmanMachine != "devkit-custom" {
		t.Errorf("Factory.podmanMachine = %q, want %q", factory.podmanMachine, "devkit-custom")
	}
}

func TestFactoryChaining(t *testing.T) {
	factory := NewFactory(BackendLima).
		WithVMName("my-vm").
		WithLimaOpts(VMOpts{CPUs: 4}).
		WithPodmanMachine("unused")

	if factory.Backend() != BackendLima {
		t.Errorf("Factory.Backend() = %q, want %q", factory.Backend(), BackendLima)
	}
	if factory.VMName() != "my-vm" {
		t.Errorf("Factory.VMName() = %q, want %q", factory.VMName(), "my-vm")
	}
}

func TestGetInstallerPodman(t *testing.T) {
	factory := NewFactory(BackendPodman)
	ctx := context.Background()

	installer, err := factory.GetInstaller(ctx)
	if err != nil {
		t.Fatalf("GetInstaller() error = %v", err)
	}

	if installer.Name() != BackendPodman {
		t.Errorf("Installer.Name() = %q, want %q", installer.Name(), BackendPodman)
	}
}

func TestGetInstallerLima(t *testing.T) {
	factory := NewFactory(BackendLima)
	ctx := context.Background()

	installer, err := factory.GetInstaller(ctx)
	if err != nil {
		t.Fatalf("GetInstaller() error = %v", err)
	}

	if installer.Name() != BackendLima {
		t.Errorf("Installer.Name() = %q, want %q", installer.Name(), BackendLima)
	}
}

func TestGetInstallerDocker(t *testing.T) {
	factory := NewFactory(BackendDocker)
	ctx := context.Background()

	_, err := factory.GetInstaller(ctx)
	if err == nil {
		t.Error("GetInstaller(docker) should return error (not implemented)")
	}
}

func TestGetInstallerUnknown(t *testing.T) {
	factory := NewFactory(Backend("unknown"))
	ctx := context.Background()

	_, err := factory.GetInstaller(ctx)
	if err == nil {
		t.Error("GetInstaller(unknown) should return error")
	}
}

func TestDetectBestBackend(t *testing.T) {
	ctx := context.Background()

	// This test just verifies the function runs without panic
	// The actual result depends on what's installed on the system
	backend := DetectBestBackend(ctx)

	if backend != BackendPodman && backend != BackendLima {
		t.Errorf("DetectBestBackend() = %q, want podman or lima", backend)
	}
}

func TestIsInstalled(t *testing.T) {
	// Just test that the function doesn't panic
	// Actual result depends on system
	_ = IsInstalled(BackendPodman)
	_ = IsInstalled(BackendLima)
	_ = IsInstalled(BackendDocker)
}

func TestPodmanInstallerName(t *testing.T) {
	installer := &PodmanInstaller{}

	if installer.Name() != BackendPodman {
		t.Errorf("PodmanInstaller.Name() = %q, want %q", installer.Name(), BackendPodman)
	}
}

func TestLimaInstallerName(t *testing.T) {
	installer := &LimaInstaller{}

	if installer.Name() != BackendLima {
		t.Errorf("LimaInstaller.Name() = %q, want %q", installer.Name(), BackendLima)
	}
}

func TestEnsureRuntimeNotInstalled(t *testing.T) {
	ctx := context.Background()

	// Test with an unknown backend
	err := EnsureRuntime(ctx, Backend("invalid"))
	if err == nil {
		t.Error("EnsureRuntime(invalid) should return error")
	}
}
