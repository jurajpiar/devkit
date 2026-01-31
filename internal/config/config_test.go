package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Check project defaults
	if cfg.Project.Type != "nodejs" {
		t.Errorf("Project.Type = %s, want nodejs", cfg.Project.Type)
	}

	// Check source defaults
	if cfg.Source.Method != "copy" {
		t.Errorf("Source.Method = %s, want git", cfg.Source.Method)
	}
	if cfg.Source.Branch != "main" {
		t.Errorf("Source.Branch = %s, want main", cfg.Source.Branch)
	}

	// Check dependencies defaults
	if cfg.Dependencies.Runtime != "node:22-alpine" {
		t.Errorf("Dependencies.Runtime = %s, want node:22-alpine", cfg.Dependencies.Runtime)
	}

	// Check features defaults (copy enabled since it's the default secure method)
	if !cfg.Features.AllowCopy {
		t.Error("Features.AllowCopy should be true by default (copy is the default method)")
	}
	if cfg.Features.AllowMount {
		t.Error("Features.AllowMount should be false by default")
	}

	// Check SSH defaults
	if cfg.SSH.Port != 2222 {
		t.Errorf("SSH.Port = %d, want 2222", cfg.SSH.Port)
	}

	// Check security defaults
	if cfg.Security.NetworkMode != "restricted" {
		t.Errorf("Security.NetworkMode = %s, want restricted", cfg.Security.NetworkMode)
	}
	if cfg.Security.MemoryLimit != "4g" {
		t.Errorf("Security.MemoryLimit = %s, want 4g", cfg.Security.MemoryLimit)
	}
	if cfg.Security.PidsLimit != 512 {
		t.Errorf("Security.PidsLimit = %d, want 512", cfg.Security.PidsLimit)
	}
	if !cfg.Security.ReadOnlyRootfs {
		t.Error("Security.ReadOnlyRootfs should be true by default")
	}
	if !cfg.Security.DropAllCapabilities {
		t.Error("Security.DropAllCapabilities should be true by default")
	}
	if !cfg.Security.NoNewPrivileges {
		t.Error("Security.NoNewPrivileges should be true by default")
	}
	if cfg.Security.DisableDebugPort {
		t.Error("Security.DisableDebugPort should be false by default")
	}
	if cfg.Security.UseDebugProxy {
		t.Error("Security.UseDebugProxy should be false by default")
	}
	if cfg.Security.DebugProxyFilterLevel != "filtered" {
		t.Errorf("Security.DebugProxyFilterLevel = %s, want filtered", cfg.Security.DebugProxyFilterLevel)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid default config",
			config:    DefaultConfig(),
			expectErr: false, // Copy method doesn't require repo
		},
		{
			name: "valid config with repo",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				return c
			}(),
			expectErr: false,
		},
		{
			name: "invalid source method",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Method = "invalid"
				return c
			}(),
			expectErr: true,
			errMsg:    "invalid source method",
		},
		{
			name: "copy method without feature flag",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Method = "copy"
				c.Features.AllowCopy = false
				return c
			}(),
			expectErr: true,
			errMsg:    "allow_copy",
		},
		{
			name: "copy method with feature flag",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Method = "copy"
				c.Features.AllowCopy = true
				return c
			}(),
			expectErr: false,
		},
		{
			name: "mount method without feature flag",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Method = "mount"
				c.Features.AllowMount = false
				return c
			}(),
			expectErr: true,
			errMsg:    "allow_mount",
		},
		{
			name: "mount method with feature flag",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Method = "mount"
				c.Features.AllowMount = true
				return c
			}(),
			expectErr: false,
		},
		{
			name: "invalid SSH port (too low)",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				c.SSH.Port = 0
				return c
			}(),
			expectErr: true,
			errMsg:    "invalid SSH port",
		},
		{
			name: "invalid SSH port (too high)",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				c.SSH.Port = 70000
				return c
			}(),
			expectErr: true,
			errMsg:    "invalid SSH port",
		},
		{
			name: "invalid network mode",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				c.Security.NetworkMode = "invalid"
				return c
			}(),
			expectErr: true,
			errMsg:    "invalid network_mode",
		},
		{
			name: "valid network mode none",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				c.Security.NetworkMode = "none"
				return c
			}(),
			expectErr: false,
		},
		{
			name: "valid network mode full",
			config: func() *Config {
				c := DefaultConfig()
				c.Source.Repo = "git@github.com:user/repo.git"
				c.Security.NetworkMode = "full"
				return c
			}(),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "devkit-config-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "devkit.yaml")

	// Create a config
	original := DefaultConfig()
	original.Project.Name = "test-project"
	original.Source.Repo = "git@github.com:test/repo.git"
	original.SSH.Port = 3333
	original.Security.NetworkMode = "none"
	original.Security.MemoryLimit = "2g"

	// Save it
	if err := original.Save(configPath); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify values
	if loaded.Project.Name != original.Project.Name {
		t.Errorf("Project.Name = %s, want %s", loaded.Project.Name, original.Project.Name)
	}
	if loaded.Source.Repo != original.Source.Repo {
		t.Errorf("Source.Repo = %s, want %s", loaded.Source.Repo, original.Source.Repo)
	}
	if loaded.SSH.Port != original.SSH.Port {
		t.Errorf("SSH.Port = %d, want %d", loaded.SSH.Port, original.SSH.Port)
	}
	if loaded.Security.NetworkMode != original.Security.NetworkMode {
		t.Errorf("Security.NetworkMode = %s, want %s", loaded.Security.NetworkMode, original.Security.NetworkMode)
	}
	if loaded.Security.MemoryLimit != original.Security.MemoryLimit {
		t.Errorf("Security.MemoryLimit = %s, want %s", loaded.Security.MemoryLimit, original.Security.MemoryLimit)
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/devkit.yaml")
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}
}

func TestLoadOrDefault(t *testing.T) {
	// Non-existent file should return default
	cfg, err := LoadOrDefault("/nonexistent/devkit.yaml")
	if err != nil {
		t.Fatalf("LoadOrDefault should not error for non-existent file: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadOrDefault should return a config")
	}
	if cfg.Project.Type != "nodejs" {
		t.Error("LoadOrDefault should return default config for non-existent file")
	}
}

func TestContainerName(t *testing.T) {
	tests := []struct {
		name     string
		projName string
		expected string
	}{
		{
			name:     "with project name",
			projName: "my-app",
			expected: "devkit-my-app",
		},
		{
			name:     "empty project name",
			projName: "",
			expected: "devkit-dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Project.Name = tt.projName

			if got := cfg.ContainerName(); got != tt.expected {
				t.Errorf("ContainerName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestImageName(t *testing.T) {
	tests := []struct {
		name     string
		projName string
		expected string
	}{
		{
			name:     "with project name",
			projName: "my-app",
			expected: "devkit/my-app:latest",
		},
		{
			name:     "empty project name",
			projName: "",
			expected: "devkit/dev:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Project.Name = tt.projName

			if got := cfg.ImageName(); got != tt.expected {
				t.Errorf("ImageName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-config-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("Expected error when loading invalid YAML")
	}
}

// Helper function
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
