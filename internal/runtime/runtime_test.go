package runtime

import (
	"testing"
)

func TestBackendConstants(t *testing.T) {
	// Verify backend constants are correct strings
	if BackendPodman != "podman" {
		t.Errorf("BackendPodman = %q, want %q", BackendPodman, "podman")
	}
	if BackendLima != "lima" {
		t.Errorf("BackendLima = %q, want %q", BackendLima, "lima")
	}
	if BackendDocker != "docker" {
		t.Errorf("BackendDocker = %q, want %q", BackendDocker, "docker")
	}
}

func TestDefaultVMOpts(t *testing.T) {
	opts := DefaultVMOpts()

	if opts.CPUs != 4 {
		t.Errorf("DefaultVMOpts().CPUs = %d, want 4", opts.CPUs)
	}
	if opts.MemoryMB != 4096 {
		t.Errorf("DefaultVMOpts().MemoryMB = %d, want 4096", opts.MemoryMB)
	}
	if opts.DiskSizeGB != 50 {
		t.Errorf("DefaultVMOpts().DiskSizeGB = %d, want 50", opts.DiskSizeGB)
	}
	if opts.VMType != "vz" {
		t.Errorf("DefaultVMOpts().VMType = %q, want %q", opts.VMType, "vz")
	}
}

func TestErrNotInstalledError(t *testing.T) {
	err := ErrNotInstalled{Runtime: BackendPodman}
	expected := "podman is not installed. Run: devkit setup"

	if err.Error() != expected {
		t.Errorf("ErrNotInstalled.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrVMNotRunningError(t *testing.T) {
	err := ErrVMNotRunning{Name: "test-vm"}
	expected := "VM 'test-vm' is not running. Run: devkit start"

	if err.Error() != expected {
		t.Errorf("ErrVMNotRunning.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrContainerNotFoundError(t *testing.T) {
	err := ErrContainerNotFound{Name: "test-container"}
	expected := "container 'test-container' not found"

	if err.Error() != expected {
		t.Errorf("ErrContainerNotFound.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrContainerNotRunningError(t *testing.T) {
	err := ErrContainerNotRunning{Name: "test-container"}
	expected := "container 'test-container' is not running. Run: devkit start"

	if err.Error() != expected {
		t.Errorf("ErrContainerNotRunning.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestDiagnosticStatusValues(t *testing.T) {
	tests := []struct {
		status   DiagnosticStatus
		expected string
	}{
		{DiagnosticOK, "ok"},
		{DiagnosticWarning, "warning"},
		{DiagnosticError, "error"},
	}

	for _, tc := range tests {
		if string(tc.status) != tc.expected {
			t.Errorf("DiagnosticStatus = %q, want %q", tc.status, tc.expected)
		}
	}
}

func TestCreateOptsDefaults(t *testing.T) {
	// Test that CreateOpts can be created with minimal fields
	opts := CreateOpts{
		Name:  "test",
		Image: "alpine",
	}

	if opts.Name != "test" {
		t.Errorf("CreateOpts.Name = %q, want %q", opts.Name, "test")
	}
	if opts.Image != "alpine" {
		t.Errorf("CreateOpts.Image = %q, want %q", opts.Image, "alpine")
	}
	if opts.ReadOnly != false {
		t.Error("CreateOpts.ReadOnly should default to false")
	}
}

func TestVolumeMountTypes(t *testing.T) {
	mount := VolumeMount{
		Source:   "/host/path",
		Target:   "/container/path",
		ReadOnly: true,
		Type:     "bind",
	}

	if mount.Source != "/host/path" {
		t.Errorf("VolumeMount.Source = %q, want %q", mount.Source, "/host/path")
	}
	if mount.Target != "/container/path" {
		t.Errorf("VolumeMount.Target = %q, want %q", mount.Target, "/container/path")
	}
	if !mount.ReadOnly {
		t.Error("VolumeMount.ReadOnly should be true")
	}
	if mount.Type != "bind" {
		t.Errorf("VolumeMount.Type = %q, want %q", mount.Type, "bind")
	}
}

func TestPortMappingDefaults(t *testing.T) {
	port := PortMapping{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	if port.HostPort != 8080 {
		t.Errorf("PortMapping.HostPort = %d, want 8080", port.HostPort)
	}
	if port.ContainerPort != 80 {
		t.Errorf("PortMapping.ContainerPort = %d, want 80", port.ContainerPort)
	}
	if port.Protocol != "tcp" {
		t.Errorf("PortMapping.Protocol = %q, want %q", port.Protocol, "tcp")
	}
}

func TestBuildOpts(t *testing.T) {
	opts := BuildOpts{
		ContextDir: "/path/to/context",
		Dockerfile: "Dockerfile.dev",
		ImageName:  "myapp:latest",
		Tags:       []string{"myapp:v1", "myapp:stable"},
		BuildArgs: map[string]string{
			"NODE_ENV": "production",
		},
		NoCache: true,
	}

	if opts.ContextDir != "/path/to/context" {
		t.Errorf("BuildOpts.ContextDir = %q, want %q", opts.ContextDir, "/path/to/context")
	}
	if opts.Dockerfile != "Dockerfile.dev" {
		t.Errorf("BuildOpts.Dockerfile = %q, want %q", opts.Dockerfile, "Dockerfile.dev")
	}
	if opts.ImageName != "myapp:latest" {
		t.Errorf("BuildOpts.ImageName = %q, want %q", opts.ImageName, "myapp:latest")
	}
	if len(opts.Tags) != 2 {
		t.Errorf("len(BuildOpts.Tags) = %d, want 2", len(opts.Tags))
	}
	if !opts.NoCache {
		t.Error("BuildOpts.NoCache should be true")
	}
}

func TestVMInfo(t *testing.T) {
	info := VMInfo{
		Name:   "devkit-test",
		Status: "running",
		CPUs:   4,
		Memory: "4GiB",
		Disk:   "50GiB",
		VMType: "vz",
	}

	if info.Name != "devkit-test" {
		t.Errorf("VMInfo.Name = %q, want %q", info.Name, "devkit-test")
	}
	if info.Status != "running" {
		t.Errorf("VMInfo.Status = %q, want %q", info.Status, "running")
	}
	if info.CPUs != 4 {
		t.Errorf("VMInfo.CPUs = %d, want 4", info.CPUs)
	}
}

func TestContainerInfo(t *testing.T) {
	info := ContainerInfo{
		ID:      "abc123",
		Name:    "devkit-test",
		Image:   "node:22-alpine",
		Status:  "running",
		Running: true,
	}

	if info.ID != "abc123" {
		t.Errorf("ContainerInfo.ID = %q, want %q", info.ID, "abc123")
	}
	if info.Name != "devkit-test" {
		t.Errorf("ContainerInfo.Name = %q, want %q", info.Name, "devkit-test")
	}
	if info.Image != "node:22-alpine" {
		t.Errorf("ContainerInfo.Image = %q, want %q", info.Image, "node:22-alpine")
	}
	if !info.Running {
		t.Error("ContainerInfo.Running should be true")
	}
}

func TestDiagnosticResult(t *testing.T) {
	result := DiagnosticResult{
		Check:   "Podman installed",
		Status:  DiagnosticOK,
		Message: "Version 5.0.0",
		Fix:     "",
	}

	if result.Check != "Podman installed" {
		t.Errorf("DiagnosticResult.Check = %q, want %q", result.Check, "Podman installed")
	}
	if result.Status != DiagnosticOK {
		t.Errorf("DiagnosticResult.Status = %q, want %q", result.Status, DiagnosticOK)
	}
}
