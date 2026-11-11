package dockerfilter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultConfigPath is where provisioning writes the filter's settings.
const DefaultConfigPath = "/etc/devkit/docker/filter.json"

// Config is the filter's root-owned configuration.
type Config struct {
	// DaemonSocket is the daemon's own socket, which only the filter's
	// account may reach.
	DaemonSocket string `json:"daemon_socket"`
	// Workspace is the real path of the sandbox user's workspace: the only
	// tree a bind mount may come from.
	Workspace string `json:"workspace"`
	// Runtimes are the runtime names a container may ask for by name. An
	// empty Runtime, the daemon's default, is always allowed.
	Runtimes []string `json:"runtimes"`
	// RuntimeGuard says the runtime guard stands in front of the runtime
	// and checks every container's mounts as made; provisioning writes
	// true for runc and gVisor alike. Without it the filter's own check of
	// a bind source is the only one, so a source it cannot see through is
	// refused. Absent means false, the stricter reading.
	RuntimeGuard bool `json:"runtime_guard"`
	// Capabilities are allowed in CapAdd on top of Docker's default set
	// (less NET_RAW).
	Capabilities []string `json:"capabilities"`
}

// LoadConfig reads and checks the configuration at path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &c, nil
}

func (c *Config) check() error {
	if !filepath.IsAbs(c.DaemonSocket) {
		return errors.New("daemon_socket must be an absolute path")
	}
	if !filepath.IsAbs(c.Workspace) || filepath.Clean(c.Workspace) != c.Workspace || c.Workspace == "/" {
		return errors.New("workspace must be a clean absolute path other than /")
	}
	for _, r := range c.Runtimes {
		if r == "" || r == "runc" || r == "io.containerd.runc.v2" {
			return fmt.Errorf("runtime %q may not be allowed by name", r)
		}
	}
	for _, cp := range c.Capabilities {
		if n := normCap(cp); n == "CAP_ALL" || n == "CAP_NET_RAW" {
			return fmt.Errorf("capability %q may not be allowed", cp)
		}
	}
	return nil
}

// defaultCaps is Docker's default capability set. Re-adding one is
// harmless; NET_RAW is taken out of it below.
var defaultCaps = []string{
	"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID",
	"SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE",
}

// normCap is a capability name as the daemon normalises it: upper case,
// with the CAP_ prefix.
func normCap(c string) string {
	n := strings.ToUpper(strings.TrimSpace(c))
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	return n
}

// allowedRuntime reports whether a container may name the runtime rt.
func (c *Config) allowedRuntime(rt string) bool {
	for _, a := range c.Runtimes {
		if rt == a {
			return true
		}
	}
	return false
}

func (c *Config) allowedCaps() map[string]bool {
	out := map[string]bool{}
	for _, cp := range defaultCaps {
		out[normCap(cp)] = true
	}
	delete(out, "CAP_NET_RAW")
	for _, cp := range c.Capabilities {
		out[normCap(cp)] = true
	}
	return out
}
