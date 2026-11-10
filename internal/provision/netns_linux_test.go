//go:build linux

package provision

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jurajpiar/devkit/internal/project"
)

// TestNetnsFirewall loads the real firewall and boot-hold scripts, as the
// provisioning renders them, into a network namespace and checks what each
// account can reach. A second namespace plays the outside: 10.231.0.2 is the
// Mac and the DNS resolver (as 192.168.5.2 is in a Lima guest), 10.231.0.3 is
// the internet. It uses the real kernel's netfilter, so rule order, owner
// matching and connection tracking behave as in the VM, without one.
//
// Needs Linux, root, iproute2, iptables, setpriv and python3. Run it with
//
//	go test -c -o /tmp/provision.test ./internal/provision
//	sudo DEVKIT_NETNS=1 /tmp/provision.test -test.run Netns -test.v
func TestNetnsFirewall(t *testing.T) {
	if os.Getenv("DEVKIT_NETNS") == "" {
		t.Skip("set DEVKIT_NETNS=1 and run as root (see the comment)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	n := newNetns(t)

	t.Run("allowlist firewall", func(t *testing.T) {
		n.applyFirewall(t, "allowlist", 0, "proxy")
		n.expect(t, "sandbox", "tcp", "10.231.0.3", 443, false, "sandbox direct to the internet")
		n.expect(t, "proxy", "tcp", "10.231.0.3", 443, true, "the proxy to the internet")
		n.expect(t, "root", "tcp", "10.231.0.3", 443, false, "root has no new egress once the firewall is up")
		n.expect(t, "proxy", "tcp", "10.231.0.2", 22, false, "the proxy to the Mac")
		n.expect(t, "sandbox", "tcp", "10.231.0.2", 5432, false, "the sandbox to the Mac")
		n.expect(t, "sandbox", "udp", "10.231.0.2", 53, false, "sandbox DNS to the resolver")
		n.expect(t, "proxy", "udp", "10.231.0.2", 53, true, "proxy DNS to the resolver")
		n.expect(t, "sandbox", "tcp", "127.0.0.1", 7777, true, "sandbox to loopback (the proxy listens there)")
		n.expect(t, "subuid", "tcp", "10.231.0.3", 443, false, "a container UID direct to the internet")
		n.expectInbound(t, "a connection made to the sandbox gets its replies")
		n.expectNoRide(t, "proxy", "the sandbox cannot ride the proxy's tracked DNS flow")
	})

	t.Run("allow_host", func(t *testing.T) {
		n.applyFirewall(t, "allowlist", 1, "proxy")
		n.expect(t, "sandbox", "tcp", "10.231.0.2", 5432, true, "allow_host opens the Mac to the sandbox")
		n.expect(t, "sandbox", "tcp", "10.231.0.3", 443, false, "but not the internet")
	})

	t.Run("dns resolvers", func(t *testing.T) {
		n.applyFirewall(t, "allowlist", 0, "resolvers")
		n.expect(t, "sandbox", "udp", "10.231.0.2", 53, true, "dns: resolvers lets the sandbox query the resolver")
		n.expect(t, "sandbox", "tcp", "10.231.0.3", 443, false, "and nothing else")
	})

	t.Run("air gap", func(t *testing.T) {
		n.applyFirewall(t, "none", 0, "proxy")
		n.expect(t, "proxy", "tcp", "10.231.0.3", 443, false, "none mode: not even the proxy")
		n.expect(t, "proxy", "udp", "10.231.0.2", 53, false, "none mode: no DNS")
	})

	t.Run("boot hold", func(t *testing.T) {
		n.applyHold(t)
		n.expect(t, "sandbox", "tcp", "10.231.0.3", 443, false, "the sandbox during the hold")
		n.expect(t, "sandbox", "tcp", "127.0.0.1", 7777, false, "the sandbox's loopback during the hold (proxy, resolver stub)")
		n.expect(t, "subuid", "tcp", "10.231.0.3", 443, false, "a container UID during the hold")
		n.expect(t, "root", "tcp", "10.231.0.3", 443, true, "root keeps its downloads during the hold")
		n.expect(t, "root", "udp", "10.231.0.2", 53, true, "root keeps DNS during the hold")
		if n.uids["resolved"] != "" {
			n.expect(t, "resolved", "udp", "10.231.0.2", 53, false, "systemd-resolved during the hold")
		}
		n.expectInbound(t, "SSH-like sessions to the sandbox still get replies during the hold")
		n.expectNoRide(t, "root", "the sandbox cannot ride root's tracked DNS flow during the hold")
	})

	// network.enforce: host. The Mac's service on 5432 stands in for the
	// host proxy: the proxy's account may reach it and nothing else.
	t.Run("host enforcement", func(t *testing.T) {
		s, err := System(hostParams(nil))
		if err != nil {
			t.Fatal(err)
		}
		n.applyFirewallFrom(t, s, "MODE=allowlist\nALLOW_HOST=0\nDNS=proxy\nFORWARD=\nHOST_PROXY_IP=10.231.0.2\nHOST_PROXY_PORT=5432\n")
		n.expect(t, "proxy", "tcp", "10.231.0.2", 5432, true, "the proxy to the host proxy")
		n.expect(t, "proxy", "tcp", "10.231.0.2", 22, false, "the proxy to another port on the Mac")
		n.expect(t, "proxy", "tcp", "10.231.0.3", 443, false, "the proxy straight to the internet")
		n.expect(t, "proxy", "udp", "10.231.0.2", 53, false, "the proxy's DNS: the host proxy resolves")
		n.expect(t, "sandbox", "tcp", "10.231.0.2", 5432, false, "the sandbox to the host proxy, past its own proxy")
		n.expect(t, "sandbox", "udp", "10.231.0.2", 53, false, "sandbox DNS")
		n.expect(t, "root", "tcp", "10.231.0.2", 5432, false, "root has no new egress once the firewall is up")
		n.expect(t, "sandbox", "tcp", "127.0.0.1", 7777, true, "sandbox to loopback (the proxy listens there)")
	})
}

type netns struct {
	guest, peer string
	dir         string
	uids        map[string]string // role -> uid
	gids        map[string]string
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func newNetns(t *testing.T) *netns {
	t.Helper()
	for _, tool := range []string{"ip", "iptables", "setpriv", "python3", "useradd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	id := strconv.Itoa(rand.Intn(90000) + 10000)
	// The probe and server scripts run as several accounts, so their directory
	// must be readable by all of them (t.TempDir is private to root).
	dir, err := os.MkdirTemp("", "dkt-netns-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	t.Cleanup(func() { os.RemoveAll(dir) })
	n := &netns{guest: "dkg" + id, peer: "dkp" + id, dir: dir, uids: map[string]string{}, gids: map[string]string{}}

	// Accounts: the sandbox user (with container subordinate UIDs), the
	// proxy's account by its real name, which the firewall matches on.
	ensureUser(t, "dkt-sandbox", false)
	ensureUser(t, "devkit-proxy", true)
	for role, name := range map[string]string{"sandbox": "dkt-sandbox", "proxy": "devkit-proxy", "resolved": "systemd-resolve"} {
		if u, err := user.Lookup(name); err == nil {
			n.uids[role], n.gids[role] = u.Uid, u.Gid
		}
	}
	n.uids["root"], n.gids["root"] = "0", "0"
	n.uids["subuid"], n.gids["subuid"] = subuidStart(t, "dkt-sandbox"), "65534"

	sh(t, "ip", "netns", "add", n.guest)
	sh(t, "ip", "netns", "add", n.peer)
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", n.guest).Run()
		exec.Command("ip", "netns", "del", n.peer).Run()
	})
	g, p := "vg"+id, "vp"+id
	sh(t, "ip", "link", "add", g, "type", "veth", "peer", "name", p)
	sh(t, "ip", "link", "set", g, "netns", n.guest)
	sh(t, "ip", "link", "set", p, "netns", n.peer)
	sh(t, "ip", "-n", n.guest, "addr", "add", "10.231.0.10/24", "dev", g)
	sh(t, "ip", "-n", n.peer, "addr", "add", "10.231.0.2/24", "dev", p)
	sh(t, "ip", "-n", n.peer, "addr", "add", "10.231.0.3/24", "dev", p)
	for _, ns := range []string{n.guest, n.peer} {
		sh(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	sh(t, "ip", "-n", n.guest, "link", "set", g, "up")
	sh(t, "ip", "-n", n.peer, "link", "set", p, "up")
	sh(t, "ip", "-n", n.guest, "route", "add", "default", "via", "10.231.0.2")

	write := func(name, body string) string {
		path := filepath.Join(n.dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("probe.py", probePy)
	server := write("server.py", serverPy)
	// The outside: services on the Mac (.2) and the internet (.3), a DNS
	// responder on .2:53. The guest: a loopback service and, as the sandbox
	// user, a listener the outside connects to (an SSH session's shape).
	n.background(t, "ip", "netns", "exec", n.peer, "python3", "-I", server,
		"tcp:10.231.0.2:22", "tcp:10.231.0.2:5432", "tcp:10.231.0.3:443", "udp:10.231.0.2:53")
	n.background(t, "ip", "netns", "exec", n.guest, "python3", "-I", server, "tcp:127.0.0.1:7777")
	n.background(t, n.as("sandbox", "python3", "-I", server, "tcp:10.231.0.10:8888")...)
	time.Sleep(500 * time.Millisecond)
	return n
}

func ensureUser(t *testing.T, name string, system bool) {
	t.Helper()
	if _, err := user.Lookup(name); err == nil {
		return
	}
	args := []string{"--no-create-home", "--shell", "/usr/sbin/nologin"}
	if system {
		args = append(args, "--system")
	}
	sh(t, append([]string{"useradd"}, append(args, name)...)...)
	t.Cleanup(func() { exec.Command("userdel", name).Run() })
}

func subuidStart(t *testing.T, name string) string {
	t.Helper()
	read := func() string {
		data, _ := os.ReadFile("/etc/subuid")
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Split(l, ":"); len(f) == 3 && f[0] == name {
				return f[1]
			}
		}
		return ""
	}
	if s := read(); s != "" {
		return s
	}
	sh(t, "usermod", "--add-subuids", "900000-965535", "--add-subgids", "900000-965535", name)
	return read()
}

func (n *netns) background(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
}

// as runs a command in the guest namespace as the given role.
func (n *netns) as(role string, args ...string) []string {
	base := []string{"ip", "netns", "exec", n.guest}
	if role == "root" {
		return append(base, args...)
	}
	return append(base, append([]string{"setpriv", "--reuid=" + n.uids[role], "--regid=" + n.gids[role], "--clear-groups"}, args...)...)
}

// probe sends one TCP connection or UDP datagram and reports "OK ..." when
// something answered, else why not.
func (n *netns) probe(role, proto, host string, port int, extra ...string) string {
	args := n.as(role, append([]string{"python3", "-I", filepath.Join(n.dir, "probe.py"), proto, host, strconv.Itoa(port)}, extra...)...)
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func (n *netns) expect(t *testing.T, role, proto, host string, port int, open bool, what string) {
	t.Helper()
	got := n.probe(role, proto, host, port)
	if strings.HasPrefix(got, "OK") != open {
		state := "blocked"
		if open {
			state = "open"
		}
		t.Errorf("%s: want %s, %s %s %s:%d gave %q", what, state, role, proto, host, port, got)
	}
}

// expectInbound connects from the outside to the sandbox's listener and needs
// its reply: replies on connections made to the sandbox must pass.
func (n *netns) expectInbound(t *testing.T, what string) {
	t.Helper()
	out, _ := exec.Command("ip", "netns", "exec", n.peer, "python3", "-I", filepath.Join(n.dir, "probe.py"), "tcp", "10.231.0.10", "8888").CombinedOutput()
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "OK") {
		t.Errorf("%s: got %q", what, out)
	}
}

// expectNoRide has a trusted account resolve from a fixed source port, then
// the sandbox send from that same port while the flow is still tracked. Its
// packet must not pass as part of the trusted account's connection.
func (n *netns) expectNoRide(t *testing.T, trusted, what string) {
	t.Helper()
	port := strconv.Itoa(40000 + rand.Intn(20000))
	if got := n.probe(trusted, "udp", "10.231.0.2", 53, port); !strings.HasPrefix(got, "OK") {
		t.Fatalf("%s: the %s account's own lookup should work first, got %q", what, trusted, got)
	}
	if got := n.probe("sandbox", "udp", "10.231.0.2", 53, port); strings.HasPrefix(got, "OK") {
		t.Errorf("%s: the sandbox's packet from port %s was answered (%q)", what, port, got)
	}
}

// heredoc pulls a heredoc's body out of the rendered system script.
func heredoc(t *testing.T, s, opener string) string {
	t.Helper()
	i := strings.Index(s, opener)
	if i < 0 {
		t.Fatalf("%q not in the system script", opener)
	}
	body := s[i+len(opener):]
	return body[:strings.Index(body, "\nEOF\n")+1]
}

func (n *netns) applyFirewall(t *testing.T, mode string, allowHost int, dns string) {
	t.Helper()
	s, err := System(params(nil))
	if err != nil {
		t.Fatal(err)
	}
	n.applyFirewallFrom(t, s, fmt.Sprintf("MODE=%s\nALLOW_HOST=%d\nDNS=%s\nFORWARD=\n", mode, allowHost, dns))
}

// applyFirewallFrom loads the firewall from system script s with confBody as
// its network.conf.
func (n *netns) applyFirewallFrom(t *testing.T, s, confBody string) {
	t.Helper()
	fw := heredoc(t, s, "cat > /usr/local/sbin/devkit-firewall <<'EOF'\n")
	conf := filepath.Join(n.dir, "network.conf")
	resolv := filepath.Join(n.dir, "resolv.conf")
	os.WriteFile(conf, []byte(confBody), 0o644)
	os.WriteFile(resolv, []byte("nameserver 10.231.0.2\n"), 0o644)
	for old, repl := range map[string]string{
		"/etc/devkit/network.conf":         conf,
		"/run/systemd/resolve/resolv.conf": resolv,
		"getent hosts host.lima.internal":  "echo 10.231.0.2 host.lima.internal",
		"mkdir -p /run/devkit":             "mkdir -p " + n.dir,
		"/run/devkit/firewall-at":          filepath.Join(n.dir, "firewall-at"),
	} {
		if !strings.Contains(fw, old) {
			t.Fatalf("firewall script no longer contains %q; update this test", old)
		}
		fw = strings.ReplaceAll(fw, old, repl)
	}
	path := filepath.Join(n.dir, "firewall.sh")
	os.WriteFile(path, []byte(fw), 0o755)
	sh(t, "ip", "netns", "exec", n.guest, "bash", path)
}

func (n *netns) applyHold(t *testing.T) {
	t.Helper()
	s, err := System(params(func(c *project.Config) {}))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(s, `SANDBOX_UID="$(id -u "$DEVKIT_USER")"`)
	end := strings.Index(s, "chmod 755 /usr/local/sbin/devkit-boot-hold")
	if start < 0 || end < 0 {
		t.Fatal("boot hold generator not found in the system script; update this test")
	}
	hold := filepath.Join(n.dir, "hold.sh")
	gen := "DEVKIT_USER=dkt-sandbox\n" + strings.ReplaceAll(s[start:end], "/usr/local/sbin/devkit-boot-hold", hold)
	genPath := filepath.Join(n.dir, "hold-gen.sh")
	os.WriteFile(genPath, []byte(gen), 0o755)
	sh(t, "bash", genPath)
	sh(t, "ip", "netns", "exec", n.guest, "sh", hold)
}

const probePy = `import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
src = int(sys.argv[4]) if len(sys.argv) > 4 else 0
try:
    if proto == "tcp":
        s = socket.create_connection((host, port), timeout=2)
        data = s.recv(64)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if src:
            s.bind(("0.0.0.0", src))
        s.settimeout(2)
        s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", (host, port))
        data, _ = s.recvfrom(512)
    print("OK", data[:24])
except Exception as e:
    print("NO", type(e).__name__, e)
`

const serverPy = `import socket, sys, threading
def tcp(host, port):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port)); srv.listen(16)
    while True:
        c, _ = srv.accept()
        try: c.sendall(f"svc {host}:{port}\n".encode())
        finally: c.close()
def udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((host, port))
    while True:
        q, peer = s.recvfrom(512)
        if len(q) >= 12:
            s.sendto(q[:2] + b"\x81\x80" + q[4:], peer)
for spec in sys.argv[1:]:
    proto, host, port = spec.split(":")
    threading.Thread(target=tcp if proto == "tcp" else udp, args=(host, int(port)), daemon=True).start()
threading.Event().wait()
`
