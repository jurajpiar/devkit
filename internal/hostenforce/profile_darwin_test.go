//go:build darwin

package hostenforce

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These run a process under the rendered profile, the way Lima's host agent
// runs, and check what it can reach. Everything is local: loopback
// listeners and unix sockets in temporary directories. No VM is needed.

const probe = `
import socket, sys
kind, target = sys.argv[1], sys.argv[2]
try:
    if kind == "tcp":
        s = socket.create_connection(("127.0.0.1", int(target)), timeout=3)
    elif kind == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(target)
    elif kind == "resolve":
        socket.getaddrinfo(target, 443)
    print("ok")
except Exception as e:
    print("fail", type(e).__name__, e)
`

type harness struct {
	t       *testing.T
	profile string
	python  string
}

// shortTempDir is a temporary directory with symlinks resolved, short
// enough for a unix socket path (104 bytes on macOS).
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if len(base) > 50 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func newHarness(t *testing.T, limaHome string, sshPort, proxyPort int) *harness {
	t.Helper()
	if _, err := os.Stat(SandboxExec); err != nil {
		t.Skip("sandbox-exec is not available")
	}
	python := "/usr/bin/python3"
	if out, err := exec.Command(python, "-c", "print('ok')").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Skipf("python3 is not usable: %v %s", err, out)
	}
	path, err := WriteProfile(filepath.Join(t.TempDir(), "state"), Profile{LimaHome: limaHome, SSHPort: sshPort, ProxyPort: proxyPort})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, profile: path, python: python}
	// The sandbox itself must work here, or every "fail" below is vacuous.
	if out, err := exec.Command(SandboxExec, "-f", path, "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("sandbox-exec cannot apply a profile in this environment: %v %s", err, out)
	}
	return h
}

// run probes one target under the profile, or without it when sandboxed is
// false (the positive control that the target itself works).
func (h *harness) run(sandboxed bool, kind, target string) string {
	h.t.Helper()
	args := []string{h.python, "-I", "-c", probe, kind, target}
	if sandboxed {
		args = append([]string{SandboxExec, "-f", h.profile}, args...)
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		h.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func tcpListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptAll(ln)
	return ln.Addr().(*net.TCPAddr).Port
}

func unixListener(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptAll(ln)
}

func acceptAll(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

func TestProfileConfinesNetworkToLimaSSHAndProxy(t *testing.T) {
	base := shortTempDir(t)
	limaHome := filepath.Join(base, "lima")
	outside := filepath.Join(base, "other")
	for _, d := range []string{limaHome, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sshPort, proxyPort, otherPort := tcpListener(t), tcpListener(t), tcpListener(t)
	inSock, outSock := filepath.Join(limaHome, "ha.sock"), filepath.Join(outside, "x.sock")
	unixListener(t, inSock)
	unixListener(t, outSock)
	h := newHarness(t, limaHome, sshPort, proxyPort)

	cases := []struct {
		label, kind, target string
		allowed             bool
	}{
		{"the VM's SSH forward", "tcp", fmt.Sprint(sshPort), true},
		{"the host proxy", "tcp", fmt.Sprint(proxyPort), true},
		{"another loopback listener", "tcp", fmt.Sprint(otherPort), false},
		{"a unix socket in Lima's home", "unix", inSock, true},
		{"a unix socket outside Lima's home", "unix", outSock, false},
		// A sibling whose name only starts like Lima's home must not match.
		{"a unix socket beside Lima's home", "unix", filepath.Join(base, "lima2.sock"), false},
	}
	unixListener(t, filepath.Join(base, "lima2.sock"))
	for _, c := range cases {
		if got := h.run(false, c.kind, c.target); got != "ok" {
			t.Fatalf("control: %s should be reachable without the profile: %s", c.label, got)
		}
		got := h.run(true, c.kind, c.target)
		if c.allowed && got != "ok" {
			t.Errorf("%s should be reachable under the profile: %s", c.label, got)
		}
		if !c.allowed && got == "ok" {
			t.Errorf("%s must be unreachable under the profile", c.label)
		}
	}
}

// The Mac's resolver is mDNSResponder, reached over a unix socket outside
// Lima's home; every lookup that /etc/hosts does not answer goes through
// it. In the spike, Lima's built-in DNS resolved through it whenever unix
// sockets were allowed wholesale. Under the profile it must be out of reach,
// and a real name must then fail to resolve. The socket check runs first and
// is fatal, so the lookup can never leave the Mac even if the profile were
// wrong. (localhost is no control: libc answers it from /etc/hosts.)
func TestProfileBlocksNameResolution(t *testing.T) {
	const resolver = "/private/var/run/mDNSResponder"
	if _, err := os.Stat(resolver); err != nil {
		t.Skip("no mDNSResponder socket on this Mac")
	}
	h := newHarness(t, shortTempDir(t), tcpListener(t), 0)
	if got := h.run(false, "unix", resolver); got != "ok" {
		t.Fatalf("control: the resolver socket should be reachable without the profile: %s", got)
	}
	if got := h.run(true, "unix", resolver); got == "ok" {
		t.Fatal("the Mac's resolver socket is reachable under the profile: names would resolve for the guest")
	}
	if got := h.run(true, "resolve", "example.com"); got == "ok" {
		t.Error("a process under the profile resolved example.com")
	}
}

// A profile without a proxy port allows only the SSH forward.
func TestProfileWithoutProxyAllowsOnlySSH(t *testing.T) {
	sshPort, otherPort := tcpListener(t), tcpListener(t)
	h := newHarness(t, shortTempDir(t), sshPort, 0)
	if got := h.run(true, "tcp", fmt.Sprint(sshPort)); got != "ok" {
		t.Errorf("SSH forward: %s", got)
	}
	if got := h.run(true, "tcp", fmt.Sprint(otherPort)); got == "ok" {
		t.Error("another port must be unreachable")
	}
}
