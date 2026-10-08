// Package project defines the devkit.yaml configuration for a sandbox.
//
// One devkit.yaml describes one project, and one project maps to exactly one
// dedicated virtual machine. The file is intentionally small: everything a
// user does not set falls back to a safe default.
package project

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Network modes.
const (
	NetworkOpen      = "open"      // outbound allowed, audited
	NetworkAllowlist = "allowlist" // outbound only to allowed hosts, enforced by firewall
	NetworkNone      = "none"      // no outbound traffic at all
)

// Source methods.
const (
	SourceCopy  = "copy"  // copy the current directory into the VM (default)
	SourceGit   = "git"   // clone a repository inside the VM
	SourceMount = "mount" // mount the current directory read-only (opt-in)
)

// DefaultFile is the config file name looked up in the current directory.
const DefaultFile = "devkit.yaml"

// Config is the parsed devkit.yaml.
type Config struct {
	Name    string   `yaml:"name"`
	Source  string   `yaml:"source"`
	Repo    string   `yaml:"repo,omitempty"`
	Branch  string   `yaml:"branch,omitempty"`
	Tools   Tools    `yaml:"tools"`
	VM      VM       `yaml:"vm"`
	SSHPort int      `yaml:"ssh_port"`
	Network Network  `yaml:"network"`
	Exclude []string `yaml:"exclude,omitempty"`
	// MountWritable lets the VM modify the mounted host directory. Only used
	// with source: mount, and dangerous: the sandbox can then alter your files.
	MountWritable bool `yaml:"mount_writable,omitempty"`
	// Sudo grants the sandbox user passwordless root inside the VM. Off by
	// default because root can disable the egress firewall.
	Sudo bool `yaml:"sudo,omitempty"`
}

// Tools lists what gets installed into the VM at first boot.
type Tools struct {
	// Node is a Node.js major version such as "22". Empty means no Node.js.
	Node string `yaml:"node,omitempty"`
	// Containers installs rootless containerd and nerdctl inside the VM.
	Containers bool `yaml:"containers"`
	// Packages are extra apt packages.
	Packages []string `yaml:"packages,omitempty"`
}

// VM sizes the virtual machine.
type VM struct {
	CPUs     int `yaml:"cpus"`
	MemoryGB int `yaml:"memory_gb"`
	DiskGB   int `yaml:"disk_gb"`
}

// Network controls outbound traffic from the VM.
type Network struct {
	Mode string `yaml:"mode"`
	// Allow lists host patterns reachable in allowlist mode. Patterns:
	// "example.com", "*.example.com" (one level), "**.example.com" (any depth).
	Allow []string `yaml:"allow,omitempty"`
	// AllowHost lets the VM reach services on the macOS host. Off by default.
	AllowHost bool `yaml:"allow_host"`
}

// DefaultAllow is the seed allowlist for a Node.js project.
var DefaultAllow = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"github.com",
	"**.github.com",
	"**.githubusercontent.com",
	"nodejs.org",
}

// DefaultExclude lists paths never copied into the VM.
var DefaultExclude = []string{
	".git", "node_modules", ".next", "dist", "build", ".cache",
	".DS_Store", "._*", "*.log", "devkit.yaml", ".devkit",
}

// Default returns a config with every default applied.
func Default() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.Source == "" {
		c.Source = SourceCopy
	}
	if c.Branch == "" {
		c.Branch = "main"
	}
	if c.VM.CPUs == 0 {
		c.VM.CPUs = 4
	}
	if c.VM.MemoryGB == 0 {
		c.VM.MemoryGB = 8
	}
	if c.VM.DiskGB == 0 {
		c.VM.DiskGB = 50
	}
	if c.SSHPort == 0 {
		c.SSHPort = 2222
	}
	if c.Network.Mode == "" {
		c.Network.Mode = NetworkAllowlist
	}
	if c.Network.Allow == nil {
		c.Network.Allow = append([]string(nil), DefaultAllow...)
	}
	if c.Exclude == nil {
		c.Exclude = append([]string(nil), DefaultExclude...)
	}
}

// Load reads and validates a devkit.yaml.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found (run 'devkit init' first)", path)
		}
		return nil, err
	}
	return Parse(data)
}

// Parse decodes YAML, applies defaults and validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if strings.Contains(err.Error(), "EOF") {
			return nil, fmt.Errorf("config is empty")
		}
		return nil, fmt.Errorf("invalid devkit.yaml: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid devkit.yaml: %w", err)
	}
	return &c, nil
}

// Save writes the config as YAML.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// Validate checks the config for mistakes a user could make.
func (c *Config) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and dashes (max 41 chars)", c.Name)
	}
	switch c.Source {
	case SourceCopy, SourceMount:
	case SourceGit:
		if c.Repo == "" {
			return fmt.Errorf("source: git requires repo to be set")
		}
	default:
		return fmt.Errorf("source must be copy, git or mount (got %q)", c.Source)
	}
	if c.MountWritable && c.Source != SourceMount {
		return fmt.Errorf("mount_writable only applies to source: mount")
	}
	switch c.Network.Mode {
	case NetworkOpen, NetworkAllowlist, NetworkNone:
	default:
		return fmt.Errorf("network.mode must be open, allowlist or none (got %q)", c.Network.Mode)
	}
	if c.SSHPort < 1024 || c.SSHPort > 65535 {
		return fmt.Errorf("ssh_port must be between 1024 and 65535 (got %d)", c.SSHPort)
	}
	if c.VM.CPUs < 1 || c.VM.MemoryGB < 1 || c.VM.DiskGB < 10 {
		return fmt.Errorf("vm needs at least 1 cpu, 1 GB memory and 10 GB disk")
	}
	if c.Tools.Node != "" && !regexp.MustCompile(`^[0-9]{1,3}$`).MatchString(c.Tools.Node) {
		return fmt.Errorf("tools.node must be a major version such as \"22\" (got %q)", c.Tools.Node)
	}
	for _, p := range c.Tools.Packages {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`).MatchString(p) {
			return fmt.Errorf("tools.packages entry %q is not a valid apt package name", p)
		}
	}
	for _, h := range c.Network.Allow {
		if strings.ContainsAny(h, " ,\"'\n") {
			return fmt.Errorf("network.allow entry %q contains invalid characters", h)
		}
	}
	return nil
}

// VMName is the Lima instance name for this project.
func (c *Config) VMName() string {
	return "devkit-" + c.Name
}

// SSHHost is the Host alias written to ~/.ssh/config.
func (c *Config) SSHHost() string {
	return "devkit-" + c.Name
}
