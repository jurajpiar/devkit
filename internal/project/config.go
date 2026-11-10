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
	"strconv"
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

// Toolchain managers.
const (
	ManagerMise = "mise" // pinned mise binary installs the versions in tools.versions
	ManagerNix  = "nix"  // multi-user Nix; the project's flake.nix provides the dev shell
	ManagerNone = "none" // apt packages only
)

// DefaultFile is the config file name looked up in the current directory.
const DefaultFile = "devkit.yaml"

// LockDir is reserved beside devkit.yaml for host-side state and is never
// copied into the VM. devkit writes nothing there today.
const LockDir = ".devkit"

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
	// Install replaces the lockfile-based dependency install that devkit
	// would otherwise pick from the files in the workspace. It runs as the
	// sandbox user, inside the dev shell when manager is nix.
	Install string `yaml:"install,omitempty"`
	// Services run inside the VM as the sandbox user; see Services.
	Services Services `yaml:"services,omitempty"`
}

// Tools lists what gets installed into the VM.
type Tools struct {
	// Manager chooses how language toolchains get into the VM: mise, nix or
	// none. Empty means mise when versions are set, otherwise none.
	Manager string `yaml:"manager,omitempty"`
	// Versions maps a mise tool name to a version, such as node: "22" or
	// go: "1.27". Only used with manager: mise. A mise.toml or idiomatic
	// version file in the repository layers on top of these.
	Versions map[string]string `yaml:"versions,omitempty"`
	// Node is shorthand for versions.node, kept for older configs.
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
	// SecurityUpdates applies Ubuntu's security pocket at every boot, before
	// the firewall comes up. On by default: a frozen image is the one part
	// of the sandbox that gets weaker every week. nil means on.
	SecurityUpdates *bool `yaml:"security_updates,omitempty"`
	// LockModules refuses kernel module loading, for root too, once
	// provisioning has loaded what the configuration needs, until the VM
	// restarts. On by default: any process can otherwise make the kernel
	// load code for an unused socket family or link type. nil means on.
	LockModules *bool `yaml:"lock_modules,omitempty"`
}

// SecurityUpdatesOn is VM.SecurityUpdates with its default applied.
func (v VM) SecurityUpdatesOn() bool { return v.SecurityUpdates == nil || *v.SecurityUpdates }

// LockModulesOn is VM.LockModules with its default applied.
func (v VM) LockModulesOn() bool { return v.LockModules == nil || *v.LockModules }

// Values of Network.DNS.
const (
	DNSProxy     = "proxy"
	DNSResolvers = "resolvers"
)

// Values of Network.Enforce.
const (
	EnforceGuest = "guest" // the firewall and proxy inside the VM decide (default)
	EnforceHost  = "host"  // the Mac decides too: the VM's network process may reach only devkit's host proxy
)

// Network controls outbound traffic from the VM.
type Network struct {
	Mode string `yaml:"mode"`
	// Enforce says where egress is enforced. "guest" (default): by the
	// firewall and proxy inside the VM, which root in the guest can remove.
	// "host": additionally on the Mac, where Lima's network process runs
	// under a sandbox profile that lets it reach only devkit's own proxy,
	// so root in the guest still cannot get past the allowlist.
	Enforce string `yaml:"enforce,omitempty"`
	// Allow lists host patterns reachable in allowlist mode. Patterns:
	// "example.com", "*.example.com" (one level), "**.example.com" (any depth),
	// each reachable on the web ports 80 and 443 only, or "host:port" for
	// exactly one other port.
	Allow []string `yaml:"allow,omitempty"`
	// DNS says who may resolve names. "proxy" (default): only the egress
	// proxy, which resolves allowed hosts itself; the sandbox cannot query a
	// resolver at all, so names cannot carry data out. "resolvers": the
	// whole VM may query the configured resolvers, for tools that insist on
	// resolving a name before they use the proxy.
	DNS string `yaml:"dns,omitempty"`
	// Forward lists guest ports to expose on the Mac at 127.0.0.1. Nothing
	// is forwarded otherwise: a page the sandbox serves, opened in a
	// browser, runs with the browser's unrestricted network.
	Forward []int `yaml:"forward,omitempty"`
	// AllowHost lets the VM reach services on the macOS host. Off by default.
	AllowHost bool `yaml:"allow_host"`
	// Distrust names root CAs, as in the system bundle ("AAA Certificate
	// Services"), that the VM must not trust for TLS. Applied by root at
	// boot on top of the distro's current ca-certificates package, which is
	// the source of truth and is refreshed on every boot. Empty by default.
	Distrust []string `yaml:"distrust,omitempty"`
}

// DefaultAllow is the seed allowlist every project gets. devkit init adds
// the registries for the ecosystems it detects and the toolchain manager's
// download hosts on top.
var DefaultAllow = []string{
	"github.com",
	"**.github.com",
	"**.githubusercontent.com",
}

// ManagerHosts are the hosts a toolchain manager needs to fetch and verify
// toolchains. Tool-specific hosts live in package detect.
var ManagerHosts = map[string][]string{
	ManagerMise: {"mise-versions.jdx.dev", "**.sigstore.dev"},
	ManagerNix:  {"cache.nixos.org", "channels.nixos.org"},
}

// DefaultExclude lists paths never copied into the VM.
var DefaultExclude = []string{
	".git", "node_modules", ".next", "dist", "build", ".cache", "target",
	".venv", "__pycache__", "vendor",
	".DS_Store", "._*", "*.log", "devkit.yaml", LockDir,
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
	if c.Tools.Node != "" {
		if c.Tools.Versions == nil {
			c.Tools.Versions = map[string]string{}
		}
		if c.Tools.Versions["node"] == "" {
			c.Tools.Versions["node"] = c.Tools.Node
		}
		c.Tools.Node = ""
	}
	if c.Tools.Manager == "" {
		c.Tools.Manager = ManagerNone
		if len(c.Tools.Versions) > 0 {
			c.Tools.Manager = ManagerMise
		}
	}
	if c.Network.Allow == nil {
		c.Network.Allow = append([]string(nil), DefaultAllow...)
	}
	c.Services.applyDefaults()
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

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	// hostRe is the allowlist grammar: an optional "*." or "**." prefix and
	// then DNS labels. Nothing else, because entries end up in a root-owned
	// file written by the provisioning script.
	hostRe = regexp.MustCompile(`^(\*\*?\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`)
	// repoRe and branchRe cover git URLs and ref names without shell
	// metacharacters; both are interpolated into a command run in the VM.
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:/@%+-]*$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]*$`)
	// toolRe and versionRe cover mise tool short names and version specs;
	// both end up in a TOML file the user provisioning script writes.
	toolRe    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,40}$`)
	pkgRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	// distrustRe is a root CA display name as the system bundle spells it.
	// The provisioning script maps spaces to underscores to find the file.
	distrustRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,80}$`)
)

// Validate checks the config for mistakes a user could make.
func (c *Config) Validate() error {
	if err := c.Services.validate(); err != nil {
		return err
	}
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and dashes (max 41 chars)", c.Name)
	}
	switch c.Source {
	case SourceCopy, SourceMount:
	case SourceGit:
		if c.Repo == "" {
			return fmt.Errorf("source: git requires repo to be set")
		}
		if !repoRe.MatchString(c.Repo) {
			return fmt.Errorf("repo %q contains characters that are not allowed in a git URL", c.Repo)
		}
		if !branchRe.MatchString(c.Branch) {
			return fmt.Errorf("branch %q is not a valid git ref name", c.Branch)
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
	switch c.Tools.Manager {
	case ManagerMise, ManagerNone:
	case ManagerNix:
		if len(c.Tools.Versions) > 0 {
			return fmt.Errorf("tools.versions is not used with manager: nix; put toolchains in flake.nix")
		}
	default:
		return fmt.Errorf("tools.manager must be mise, nix or none (got %q)", c.Tools.Manager)
	}
	for tool, v := range c.Tools.Versions {
		if !toolRe.MatchString(tool) {
			return fmt.Errorf("tools.versions key %q is not a mise tool name (backends such as aqua: belong in the repo's mise.toml)", tool)
		}
		if !versionRe.MatchString(v) {
			return fmt.Errorf("tools.versions.%s %q is not a version", tool, v)
		}
	}
	for _, p := range c.Tools.Packages {
		if !pkgRe.MatchString(p) {
			return fmt.Errorf("tools.packages entry %q is not a valid apt package name", p)
		}
	}
	for _, d := range c.Network.Distrust {
		if !distrustRe.MatchString(d) {
			return fmt.Errorf("network.distrust entry %q is not a root CA name", d)
		}
	}
	for i, h := range c.Network.Allow {
		h = strings.ToLower(h)
		if !hostRe.MatchString(h) {
			return fmt.Errorf("network.allow entry %q must be a hostname, *.host or **.host, optionally :port (use mode: open to allow everything)", c.Network.Allow[i])
		}
		if j := strings.LastIndex(h, ":"); j > 0 {
			if port, _ := strconv.Atoi(h[j+1:]); port < 1 || port > 65535 {
				return fmt.Errorf("network.allow entry %q has a port outside 1-65535", c.Network.Allow[i])
			}
		}
		c.Network.Allow[i] = h
	}
	switch c.Network.DNS {
	case "", DNSProxy, DNSResolvers:
	default:
		return fmt.Errorf("network.dns must be %q or %q", DNSProxy, DNSResolvers)
	}
	for _, p := range c.Network.Forward {
		if p < 1 || p > 65535 {
			return fmt.Errorf("network.forward port %d is outside 1-65535", p)
		}
	}
	switch c.Network.Enforce {
	case "", EnforceGuest:
	case EnforceHost:
		// Each of these needs the VM to reach something on the Mac other
		// than devkit's proxy, which is exactly what host enforcement takes
		// away. Refused rather than quietly weakened.
		if c.Network.AllowHost {
			return fmt.Errorf("network.enforce: host cannot be combined with allow_host: true (the Mac lets the VM reach only devkit's proxy)")
		}
		if c.Network.DNS == DNSResolvers {
			return fmt.Errorf("network.enforce: host cannot be combined with dns: resolvers (the VM has no resolver to ask; the proxy on the Mac resolves names)")
		}
		if c.Network.Mode == NetworkNone {
			return fmt.Errorf("network.enforce: host does not support mode: none yet (provisioning needs the host proxy to install base packages; use enforce: guest for an air-gapped VM)")
		}
	default:
		return fmt.Errorf("network.enforce must be guest or host (got %q)", c.Network.Enforce)
	}
	return nil
}

// HostEnforced reports whether the Mac enforces egress (network.enforce: host).
func (c *Config) HostEnforced() bool { return c.Network.Enforce == EnforceHost }

// VMName is the Lima instance name for this project.
func (c *Config) VMName() string {
	return "devkit-" + c.Name
}

// SSHHost is the Host alias written to ~/.ssh/config.
func (c *Config) SSHHost() string {
	return "devkit-" + c.Name
}

// AptPackages are the packages root installs: tools.packages plus those the
// enabled services need.
func (c *Config) AptPackages() []string {
	pkgs := append([]string(nil), c.Tools.Packages...)
	if c.Services.Postgres != nil {
		pkgs = append(pkgs, PostgresPackage)
	}
	return pkgs
}
