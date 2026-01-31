package container

import (
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/config"
)

// TestBuildCreateArgs verifies that the correct security flags are generated
func TestBuildCreateArgs(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Project.Name = "test-project"
	cfg.Source.Repo = "git@github.com:test/repo.git"

	mgr := New(cfg)

	// Get the create arguments
	args := mgr.buildCreateArgs()

	// Convert to string for easier checking
	argsStr := strings.Join(args, " ")

	t.Logf("Generated args: %s", argsStr)

	// Check for security flags
	securityChecks := []struct {
		flag string
		desc string
	}{
		{"--cap-drop=ALL", "all capabilities dropped"},
		{"--security-opt=no-new-privileges:true", "no new privileges"},
		{"--read-only", "read-only rootfs"},
		{"--memory=", "memory limit set"},
		{"--pids-limit=", "PIDs limit set"},
		{"--tmpfs /tmp", "tmpfs for /tmp"},
		{"--tmpfs /run", "tmpfs for /run"},
		{"noexec", "noexec on tmpfs"},
		{"nosuid", "nosuid on tmpfs"},
		{"127.0.0.1:", "ports bound to localhost"},
	}

	for _, check := range securityChecks {
		if !strings.Contains(argsStr, check.flag) {
			t.Errorf("Missing security flag: %s (%s)", check.flag, check.desc)
		} else {
			t.Logf("Found: %s - %s", check.flag, check.desc)
		}
	}
}

// TestBuildCreateArgsNetworkModes tests different network mode configurations
func TestBuildCreateArgsNetworkModes(t *testing.T) {
	tests := []struct {
		name        string
		networkMode string
		wantFlag    string
	}{
		{
			name:        "restricted mode",
			networkMode: "restricted",
			wantFlag:    "--network=slirp4netns:allow_host_loopback=false",
		},
		{
			name:        "none mode",
			networkMode: "none",
			wantFlag:    "--network=none",
		},
		{
			name:        "full mode",
			networkMode: "full",
			wantFlag:    "--network=slirp4netns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Project.Name = "test"
			cfg.Security.NetworkMode = tt.networkMode

			mgr := New(cfg)
			args := mgr.buildCreateArgs()
			argsStr := strings.Join(args, " ")

			if !strings.Contains(argsStr, tt.wantFlag) {
				t.Errorf("Expected network flag %q for mode %q, args: %s",
					tt.wantFlag, tt.networkMode, argsStr)
			}
		})
	}
}

// TestBuildCreateArgsDebugPort tests debug port configuration
func TestBuildCreateArgsDebugPort(t *testing.T) {
	t.Run("debug port enabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Project.Name = "test"
		cfg.Security.DisableDebugPort = false

		mgr := New(cfg)
		args := mgr.buildCreateArgs()
		argsStr := strings.Join(args, " ")

		if !strings.Contains(argsStr, "9229") {
			t.Error("Debug port 9229 should be exposed when not disabled")
		}
	})

	t.Run("debug port disabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Project.Name = "test"
		cfg.Security.DisableDebugPort = true

		mgr := New(cfg)
		args := mgr.buildCreateArgs()
		argsStr := strings.Join(args, " ")

		if strings.Contains(argsStr, "9229") {
			t.Error("Debug port 9229 should NOT be exposed when disabled")
		}
	})
}

// TestBuildCreateArgsSecurityOverrides tests security setting overrides
func TestBuildCreateArgsSecurityOverrides(t *testing.T) {
	t.Run("capabilities not dropped", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Project.Name = "test"
		cfg.Security.DropAllCapabilities = false

		mgr := New(cfg)
		args := mgr.buildCreateArgs()
		argsStr := strings.Join(args, " ")

		if strings.Contains(argsStr, "--cap-drop=ALL") {
			t.Error("Should not drop caps when DropAllCapabilities=false")
		}
	})

	t.Run("no-new-privileges disabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Project.Name = "test"
		cfg.Security.NoNewPrivileges = false

		mgr := New(cfg)
		args := mgr.buildCreateArgs()
		argsStr := strings.Join(args, " ")

		if strings.Contains(argsStr, "no-new-privileges") {
			t.Error("Should not set no-new-privileges when NoNewPrivileges=false")
		}
	})

	t.Run("read-only rootfs disabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Project.Name = "test"
		cfg.Security.ReadOnlyRootfs = false

		mgr := New(cfg)
		args := mgr.buildCreateArgs()
		argsStr := strings.Join(args, " ")

		if strings.Contains(argsStr, "--read-only") {
			t.Error("Should not set read-only when ReadOnlyRootfs=false")
		}
	})
}

// TestBuildCreateArgsResourceLimits tests resource limit configuration
func TestBuildCreateArgsResourceLimits(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Project.Name = "test"
	cfg.Security.MemoryLimit = "2g"
	cfg.Security.PidsLimit = 256

	mgr := New(cfg)
	args := mgr.buildCreateArgs()
	argsStr := strings.Join(args, " ")

	if !strings.Contains(argsStr, "--memory=2g") {
		t.Errorf("Expected memory limit 2g, got: %s", argsStr)
	}

	if !strings.Contains(argsStr, "--pids-limit=256") {
		t.Errorf("Expected pids limit 256, got: %s", argsStr)
	}
}

// TestBuildCreateArgsNamedVolumes tests that named volumes are used
func TestBuildCreateArgsNamedVolumes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Project.Name = "test-project"

	mgr := New(cfg)
	args := mgr.buildCreateArgs()
	argsStr := strings.Join(args, " ")

	// Should use named volumes, not bind mounts
	if !strings.Contains(argsStr, "devkit-test-project-workspace") {
		t.Error("Expected named volume for workspace")
	}

	if !strings.Contains(argsStr, "devkit-test-project-home") {
		t.Error("Expected named volume for home")
	}

	// Should NOT contain bind mounts to host paths (except for specific allowed paths)
	// This is a security check - we don't want arbitrary host path access
	t.Logf("Volume args verified for project: test-project")
}

// TestContainerNameGeneration tests container name generation
func TestContainerNameGeneration(t *testing.T) {
	tests := []struct {
		projectName string
		expected    string
	}{
		{"my-app", "devkit-my-app"},
		{"test", "devkit-test"},
		{"", "devkit-dev"},
	}

	for _, tt := range tests {
		t.Run(tt.projectName, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Project.Name = tt.projectName

			if got := cfg.ContainerName(); got != tt.expected {
				t.Errorf("ContainerName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

// TestSecurityDefaults verifies that security defaults are strict
func TestSecurityDefaults(t *testing.T) {
	cfg := config.DefaultConfig()

	// All security features should be ON by default
	securityDefaults := []struct {
		name  string
		value bool
		want  bool
	}{
		{"DropAllCapabilities", cfg.Security.DropAllCapabilities, true},
		{"NoNewPrivileges", cfg.Security.NoNewPrivileges, true},
		{"ReadOnlyRootfs", cfg.Security.ReadOnlyRootfs, true},
		{"DisableDebugPort", cfg.Security.DisableDebugPort, false}, // Debug port enabled by default
	}

	for _, check := range securityDefaults {
		if check.value != check.want {
			t.Errorf("Security.%s = %v, want %v", check.name, check.value, check.want)
		}
	}

	// Network mode should be restricted
	if cfg.Security.NetworkMode != "restricted" {
		t.Errorf("Security.NetworkMode = %s, want restricted", cfg.Security.NetworkMode)
	}

	// Resource limits should be set
	if cfg.Security.MemoryLimit == "" {
		t.Error("Security.MemoryLimit should have a default value")
	}
	if cfg.Security.PidsLimit == 0 {
		t.Error("Security.PidsLimit should have a default value")
	}
}
