// Package hostenforce confines Lima's network process on the Mac.
//
// Every packet the guest sends leaves through Lima's host agent, a process
// on the Mac that limactl start launches and that inherits limactl's macOS
// sandbox. Started under the profile rendered here, the host agent may open
// outbound connections to three things only: Lima's own control sockets,
// the VM's SSH forward and devkit's host proxy. Root in the guest can then
// remove every control inside the VM and still reach nothing else: no
// internet, no DNS (the Mac's resolver socket is not among the three), no
// service on the Mac's loopback.
//
// The profile is applied with sandbox-exec, which needs no root. Apple marks
// it deprecated; when it is missing devkit refuses to start rather than run
// the VM unconfined.
package hostenforce

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// SandboxExec is the macOS tool that starts a process under a profile.
const SandboxExec = "/usr/bin/sandbox-exec"

// ProfileFile is the profile's name in the VM's state directory.
const ProfileFile = "network.sb"

// Seams for tests.
var (
	goos        = runtime.GOOS
	sandboxExec = SandboxExec
)

// Check reports why host enforcement cannot run on this machine, or nil.
func Check() error {
	if goos != "darwin" {
		return fmt.Errorf("network.enforce: host needs macOS (this is %s); refusing to start the VM without it", goos)
	}
	fi, err := os.Stat(sandboxExec)
	if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		return fmt.Errorf("network.enforce: host needs %s, which is missing on this Mac (Apple has deprecated it); refusing to start the VM unprotected. Set network.enforce: guest to run with in-guest enforcement only", sandboxExec)
	}
	return nil
}

// Profile is what the rendered profile lets the host agent reach.
type Profile struct {
	// LimaHome is Lima's data directory, symlinks resolved (lima.Home()).
	// Unix sockets under it are Lima's own control channels.
	LimaHome string
	// SSHPort is the VM's SSH forward on the Mac's loopback.
	SSHPort int
	// ProxyPort is devkit's host proxy on the Mac's loopback; 0 for none.
	ProxyPort int
}

// unsafePath matches what the profile syntax cannot carry inside a string
// or regex literal: a double quote ends it, a backslash escapes, and line
// breaks and other control characters have no business in a path.
var unsafePath = regexp.MustCompile(`["\\\x00-\x1f\x7f]`)

// Render returns the sandbox profile for p.
//
// Unix sockets are allowed under Lima's home only, never wholesale: with
// every unix socket allowed, Lima's built-in DNS at 192.168.5.2:53 resolved
// names through the Mac's resolver socket, which is a channel out for
// anything in the guest that can send a query.
func Render(p Profile) (string, error) {
	home := p.LimaHome
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("lima home %q must be an absolute path", home)
	}
	if unsafePath.MatchString(home) {
		return "", fmt.Errorf("lima home %q contains a character the sandbox profile cannot carry safely (a quote, backslash or control character); move it or set LIMA_HOME", home)
	}
	home = strings.TrimRight(home, "/")
	if home == "" {
		return "", errors.New("lima home must not be the root directory")
	}
	if p.SSHPort < 1 || p.SSHPort > 65535 {
		return "", fmt.Errorf("ssh port %d is outside 1-65535", p.SSHPort)
	}
	if p.ProxyPort < 0 || p.ProxyPort > 65535 {
		return "", fmt.Errorf("proxy port %d is outside 1-65535", p.ProxyPort)
	}
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("; Written by devkit for network.enforce: host. Lima's host agent, which\n")
	b.WriteString("; carries all of the VM's traffic, may dial Lima's own sockets, the VM's\n")
	b.WriteString("; SSH forward and devkit's host proxy, and nothing else.\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny network-outbound)\n")
	fmt.Fprintf(&b, "(allow network-outbound (remote unix-socket (path-regex #\"^%s/\")))\n", regexp.QuoteMeta(home))
	fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", p.SSHPort)
	if p.ProxyPort != 0 {
		fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", p.ProxyPort)
	}
	return b.String(), nil
}

// WriteProfile renders p into dir/ProfileFile, readable by the owner only,
// and returns its path.
func WriteProfile(dir string, p Profile) (string, error) {
	s, err := Render(p)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, ProfileFile)
	tmp, err := os.CreateTemp(dir, ProfileFile+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(s); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// StartArgs is the command that starts the instance under the profile:
// sandbox-exec, then limactl start exactly as devkit runs it otherwise.
// limactl create is not wrapped: it downloads the image.
func StartArgs(profilePath, name string) []string {
	return []string{sandboxExec, "-f", profilePath, "limactl", "start", "--tty=false", name}
}
