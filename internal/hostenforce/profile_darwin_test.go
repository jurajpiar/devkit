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
	"time"
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
    elif kind == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"devkit-udp-probe", ("127.0.0.1", int(target)))
    elif kind == "resolve":
        socket.getaddrinfo(target, 443)
    elif kind == "icmp":
        # An unprivileged ICMP datagram socket, as Lima's network stack uses
        # to forward a guest's ping. Echo request, checksum precomputed.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        s.settimeout(3)
        s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", (target, 0))
        s.recv(64)
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

// tcpUDPListener listens on one port number over both TCP and UDP and
// returns the port and the datagrams the UDP side receives.
func tcpUDPListener(t *testing.T) (int, <-chan string) {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			ln.Close() // the UDP port number is taken; try another
			continue
		}
		t.Cleanup(func() { ln.Close(); pc.Close() })
		go acceptAll(ln)
		got := make(chan string, 16)
		go func() {
			buf := make([]byte, 512)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				got <- string(buf[:n])
			}
		}()
		return port, got
	}
	t.Fatal("no port number free over both TCP and UDP")
	return 0, nil
}

// received waits briefly for a datagram and reports whether one arrived.
func received(got <-chan string) bool {
	select {
	case <-got:
		return true
	case <-time.After(time.Second):
		return false
	}
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

// The allowances are for TCP: a UDP service on the Mac's loopback at the
// SSH-forward or proxy port number must stay out of reach. The check is
// what the listener received, not whether sendto reported an error.
func TestProfileBlocksUDPOnAllowedPorts(t *testing.T) {
	sshPort, sshGot := tcpUDPListener(t)
	proxyPort, proxyGot := tcpUDPListener(t)
	h := newHarness(t, shortTempDir(t), sshPort, proxyPort)
	for _, c := range []struct {
		label string
		port  int
		got   <-chan string
	}{{"the SSH forward's port", sshPort, sshGot}, {"the host proxy's port", proxyPort, proxyGot}} {
		h.run(false, "udp", fmt.Sprint(c.port))
		if !received(c.got) {
			t.Fatalf("control: a datagram to %s should arrive without the profile", c.label)
		}
		if got := h.run(true, "tcp", fmt.Sprint(c.port)); got != "ok" {
			t.Errorf("TCP to %s should be reachable under the profile: %s", c.label, got)
		}
		h.run(true, "udp", fmt.Sprint(c.port))
		if received(c.got) {
			t.Errorf("a datagram to %s arrived from under the profile: UDP must be denied", c.label)
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

// A guest's ping must not leave the Mac either. Seen from inside the guest
// a refused ping and a forwarded one look the same (no reply), so this is
// checked here, on the process the profile confines: it cannot send ICMP at
// all. Loopback only, with an unsandboxed control showing the ping works.
func TestProfileBlocksICMP(t *testing.T) {
	h := newHarness(t, shortTempDir(t), tcpListener(t), tcpListener(t))
	if got := h.run(false, "icmp", "127.0.0.1"); got != "ok" {
		t.Skipf("this machine does not answer an unprivileged ICMP echo on loopback, so the control is void: %s", got)
	}
	got := h.run(true, "icmp", "127.0.0.1")
	if got == "ok" {
		t.Fatal("a process under the profile sent an ICMP echo and got a reply")
	}
	if !strings.Contains(got, "PermissionError") {
		t.Errorf("ICMP should be refused by the sandbox, not fail some other way: %s", got)
	}
}
