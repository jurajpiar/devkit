package lima

import (
	"testing"

	"github.com/jurajpiar/devkit/internal/runtime"
)

func TestDefaultLimaConfig(t *testing.T) {
	cfg := DefaultLimaConfig()

	if cfg.VMType != "vz" {
		t.Errorf("DefaultLimaConfig().VMType = %q, want %q", cfg.VMType, "vz")
	}
	if cfg.CPUs != 4 {
		t.Errorf("DefaultLimaConfig().CPUs = %d, want 4", cfg.CPUs)
	}
	if cfg.MemoryGB != 8 {
		t.Errorf("DefaultLimaConfig().MemoryGB = %d, want 8", cfg.MemoryGB)
	}
	if cfg.DiskGB != 50 {
		t.Errorf("DefaultLimaConfig().DiskGB = %d, want 50", cfg.DiskGB)
	}
	if cfg.Arch != "aarch64" {
		t.Errorf("DefaultLimaConfig().Arch = %q, want %q", cfg.Arch, "aarch64")
	}
	if !cfg.Plain {
		t.Error("DefaultLimaConfig().Plain should be true for security")
	}
}

func TestDefaultLimaConfigProvision(t *testing.T) {
	cfg := DefaultLimaConfig()

	if len(cfg.Provision) == 0 {
		t.Error("DefaultLimaConfig().Provision should not be empty")
	}

	// Verify first provision is system mode
	if cfg.Provision[0].Mode != "system" {
		t.Errorf("DefaultLimaConfig().Provision[0].Mode = %q, want %q", cfg.Provision[0].Mode, "system")
	}

	// Verify script contains containerd setup
	if len(cfg.Provision[0].Script) == 0 {
		t.Error("DefaultLimaConfig().Provision[0].Script should not be empty")
	}
}

func TestDefaultLimaConfigMounts(t *testing.T) {
	cfg := DefaultLimaConfig()

	// Security: no mounts by default
	if len(cfg.Mounts) != 0 {
		t.Errorf("DefaultLimaConfig().Mounts should be empty for security, got %d mounts", len(cfg.Mounts))
	}
}

func TestDefaultLimaConfigPortForwards(t *testing.T) {
	cfg := DefaultLimaConfig()

	if len(cfg.PortForwards) == 0 {
		t.Error("DefaultLimaConfig().PortForwards should not be empty")
	}

	// Should have SSH port forward
	sshFound := false
	for _, pf := range cfg.PortForwards {
		if pf.GuestPort == 22 {
			sshFound = true
			if pf.HostIP != "127.0.0.1" {
				t.Errorf("SSH port forward HostIP = %q, want 127.0.0.1", pf.HostIP)
			}
			if pf.HostPort != 0 {
				t.Errorf("SSH port forward HostPort = %d, want 0 (auto-assign)", pf.HostPort)
			}
		}
	}
	if !sshFound {
		t.Error("SSH port forward (guest port 22) not found")
	}
}

func TestGenerateDevkitConfig(t *testing.T) {
	opts := runtime.VMOpts{
		CPUs:       2,
		MemoryMB:   4096,
		DiskSizeGB: 100,
		VMType:     "qemu",
	}

	cfg := GenerateDevkitConfig("test-project", opts)

	if cfg.CPUs != 2 {
		t.Errorf("GenerateDevkitConfig().CPUs = %d, want 2", cfg.CPUs)
	}
	if cfg.MemoryGB != 4 { // 4096MB = 4GB
		t.Errorf("GenerateDevkitConfig().MemoryGB = %d, want 4", cfg.MemoryGB)
	}
	if cfg.DiskGB != 100 {
		t.Errorf("GenerateDevkitConfig().DiskGB = %d, want 100", cfg.DiskGB)
	}
	if cfg.VMType != "qemu" {
		t.Errorf("GenerateDevkitConfig().VMType = %q, want %q", cfg.VMType, "qemu")
	}
}

func TestGenerateDevkitConfigPortForwards(t *testing.T) {
	cfg := GenerateDevkitConfig("test", runtime.VMOpts{})

	// Should have common development ports
	commonPorts := map[int]bool{
		3000: false, // React
		3001: false,
		5173: false, // Vite
		8080: false, // Common
		8000: false, // Django
		9229: false, // Node.js debug
	}

	for _, pf := range cfg.PortForwards {
		if _, ok := commonPorts[pf.GuestPort]; ok {
			commonPorts[pf.GuestPort] = true
		}
	}

	for port, found := range commonPorts {
		if !found {
			t.Errorf("Common port %d not found in port forwards", port)
		}
	}
}

func TestGenerateDevkitConfigProvision(t *testing.T) {
	cfg := GenerateDevkitConfig("test", runtime.VMOpts{})

	// Should have at least 2 provision scripts (base + dev)
	if len(cfg.Provision) < 2 {
		t.Errorf("GenerateDevkitConfig() should have at least 2 provision scripts, got %d", len(cfg.Provision))
	}
}

func TestLimaConfigStruct(t *testing.T) {
	cfg := LimaConfig{
		VMType:   "vz",
		CPUs:     4,
		MemoryGB: 8,
		DiskGB:   50,
		Image:    "https://example.com/image.img",
		Arch:     "aarch64",
		Plain:    true,
		PortForwards: []PortForward{
			{GuestPort: 22, HostPort: 0},
		},
		Mounts: []Mount{
			{Location: "/tmp", Writable: true},
		},
		Provision: []Provision{
			{Mode: "system", Script: "echo hello"},
		},
	}

	if cfg.VMType != "vz" {
		t.Errorf("LimaConfig.VMType = %q, want %q", cfg.VMType, "vz")
	}
	if len(cfg.PortForwards) != 1 {
		t.Errorf("len(LimaConfig.PortForwards) = %d, want 1", len(cfg.PortForwards))
	}
	if len(cfg.Mounts) != 1 {
		t.Errorf("len(LimaConfig.Mounts) = %d, want 1", len(cfg.Mounts))
	}
	if len(cfg.Provision) != 1 {
		t.Errorf("len(LimaConfig.Provision) = %d, want 1", len(cfg.Provision))
	}
}

func TestPortForwardStruct(t *testing.T) {
	pf := PortForward{
		GuestPort: 3000,
		HostPort:  3000,
		GuestIP:   "0.0.0.0",
		HostIP:    "127.0.0.1",
		Proto:     "tcp",
		Ignore:    false,
	}

	if pf.GuestPort != 3000 {
		t.Errorf("PortForward.GuestPort = %d, want 3000", pf.GuestPort)
	}
	if pf.HostIP != "127.0.0.1" {
		t.Errorf("PortForward.HostIP = %q, want 127.0.0.1", pf.HostIP)
	}
}

func TestMountStruct(t *testing.T) {
	mount := Mount{
		Location: "/workspace",
		Writable: false,
	}

	if mount.Location != "/workspace" {
		t.Errorf("Mount.Location = %q, want /workspace", mount.Location)
	}
	if mount.Writable {
		t.Error("Mount.Writable should be false")
	}
}

func TestProvisionStruct(t *testing.T) {
	provision := Provision{
		Mode:   "user",
		Script: "npm install",
	}

	if provision.Mode != "user" {
		t.Errorf("Provision.Mode = %q, want user", provision.Mode)
	}
	if provision.Script != "npm install" {
		t.Errorf("Provision.Script = %q, want npm install", provision.Script)
	}
}

func TestDefaultImage(t *testing.T) {
	if DefaultImage == "" {
		t.Error("DefaultImage should not be empty")
	}
	// Should be Ubuntu cloud image
	if !contains(DefaultImage, "ubuntu") {
		t.Errorf("DefaultImage = %q, should contain 'ubuntu'", DefaultImage)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
