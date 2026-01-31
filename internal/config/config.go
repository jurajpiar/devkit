package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the devkit configuration
type Config struct {
	Project      ProjectConfig      `yaml:"project" mapstructure:"project"`
	Source       SourceConfig       `yaml:"source" mapstructure:"source"`
	Dependencies DependenciesConfig `yaml:"dependencies" mapstructure:"dependencies"`
	Features     FeaturesConfig     `yaml:"features" mapstructure:"features"`
	SSH          SSHConfig          `yaml:"ssh" mapstructure:"ssh"`
}

// ProjectConfig holds project metadata
type ProjectConfig struct {
	Name string `yaml:"name" mapstructure:"name"`
	Type string `yaml:"type" mapstructure:"type"`
}

// SourceConfig defines how code gets into the container
type SourceConfig struct {
	Method string `yaml:"method" mapstructure:"method"` // git, copy, mount
	Repo   string `yaml:"repo" mapstructure:"repo"`
	Branch string `yaml:"branch" mapstructure:"branch"`
}

// DependenciesConfig specifies runtime and packages
type DependenciesConfig struct {
	Runtime string   `yaml:"runtime" mapstructure:"runtime"`
	Install []string `yaml:"install" mapstructure:"install"`
}

// FeaturesConfig holds feature flags
type FeaturesConfig struct {
	AllowCopy  bool `yaml:"allow_copy" mapstructure:"allow_copy"`
	AllowMount bool `yaml:"allow_mount" mapstructure:"allow_mount"`
}

// SSHConfig holds SSH server settings
type SSHConfig struct {
	Port int `yaml:"port" mapstructure:"port"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Project: ProjectConfig{
			Type: "nodejs",
		},
		Source: SourceConfig{
			Method: "git",
			Branch: "main",
		},
		Dependencies: DependenciesConfig{
			Runtime: "node:22-alpine",
		},
		Features: FeaturesConfig{
			AllowCopy:  false,
			AllowMount: false,
		},
		SSH: SSHConfig{
			Port: 2222,
		},
	}
}

// Load reads configuration from the specified file path
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Set config file
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil, fmt.Errorf("config file not found: %s", configPath)
		}
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	// Unmarshal to struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// LoadOrDefault loads config from file or returns default if file doesn't exist
func LoadOrDefault(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}
	return Load(configPath)
}

// Save writes the configuration to the specified file path
func (c *Config) Save(configPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate source method
	validMethods := map[string]bool{"git": true, "copy": true, "mount": true}
	if !validMethods[c.Source.Method] {
		return fmt.Errorf("invalid source method: %s (must be git, copy, or mount)", c.Source.Method)
	}

	// Validate feature flags for copy/mount methods
	if c.Source.Method == "copy" && !c.Features.AllowCopy {
		return fmt.Errorf("source method 'copy' requires features.allow_copy to be true")
	}
	if c.Source.Method == "mount" && !c.Features.AllowMount {
		return fmt.Errorf("source method 'mount' requires features.allow_mount to be true")
	}

	// Validate git source requires repo
	if c.Source.Method == "git" && c.Source.Repo == "" {
		return fmt.Errorf("source method 'git' requires source.repo to be set")
	}

	// Validate SSH port
	if c.SSH.Port < 1 || c.SSH.Port > 65535 {
		return fmt.Errorf("invalid SSH port: %d", c.SSH.Port)
	}

	return nil
}

// setDefaults sets default values in viper
func setDefaults(v *viper.Viper) {
	v.SetDefault("project.type", "nodejs")
	v.SetDefault("source.method", "git")
	v.SetDefault("source.branch", "main")
	v.SetDefault("dependencies.runtime", "node:22-alpine")
	v.SetDefault("features.allow_copy", false)
	v.SetDefault("features.allow_mount", false)
	v.SetDefault("ssh.port", 2222)
}

// ContainerName returns the container name for this project
func (c *Config) ContainerName() string {
	if c.Project.Name != "" {
		return fmt.Sprintf("devkit-%s", c.Project.Name)
	}
	return "devkit-dev"
}

// ImageName returns the image name for this project
func (c *Config) ImageName() string {
	if c.Project.Name != "" {
		return fmt.Sprintf("devkit/%s:latest", c.Project.Name)
	}
	return "devkit/dev:latest"
}
