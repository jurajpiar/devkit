package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hardeningAttempts are the escapes that do not need a bug: each one uses
// a channel the sandbox leaves open by design. Written red first, then the
// design was changed until they went green.
func hardeningAttempts(t *testing.T, s *sandbox, dir string) {
	t.Run("allowed hosts are reachable on web ports only", func(t *testing.T) {
		// github.com is allowed. That must mean HTTPS to GitHub, not a TCP
		// tunnel to port 22 on it, which is git-over-SSH and a generic
		// tunnel to anything GitHub (or any allowed host) listens on.
		out, _ := s.shell("curl -s -m 10 -p -x http://127.0.0.1:3128 --noproxy '' -o /dev/null -w '%{http_connect}' https://github.com:22/ ; echo")
		if strings.TrimSpace(out) != "403" {
			t.Errorf("CONNECT github.com:22 should be refused by policy (403), got %s", strings.TrimSpace(out))
		}
		out, _ = s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' http://github.com:22/ ; echo")
		if strings.TrimSpace(out) != "403" {
			t.Errorf("plain HTTP to github.com:22 should be refused by policy (403), got %s", strings.TrimSpace(out))
		}
		// Positive control: the same host on 443 still works.
		out, _ = s.shell("curl -s -m 15 -o /dev/null -w '%{http_code}' https://github.com/ ; echo")
		if strings.TrimSpace(out) != "200" {
			t.Errorf("github.com:443 should still be allowed, got %s", strings.TrimSpace(out))
		}
	})

	t.Run("DNS is not a side channel", func(t *testing.T) {
		// Encoding data in query names to a domain the attacker controls
		// only needs the resolver to forward the query. The sandbox user
		// must not be able to resolve names at all: the proxy resolves the
		// allowed ones itself.
		// A name that exists, so the only way to fail is not being allowed
		// to ask: a made-up name would fail with NXDOMAIN after the query,
		// and the data, had already left.
		// It must also fail fast: a lookup that hangs for resolved's retry
		// budget would make every tool that resolves first crawl.
		out, _ := s.shell("timeout 5 getent hosts example.com; echo exit=$?")
		if strings.Contains(out, "exit=0") {
			t.Errorf("sandbox user resolved a name (data would have left in the query): %s", out)
		}
		if strings.Contains(out, "exit=124") {
			t.Errorf("a refused lookup should fail within 5 s, not hang: %s", out)
		}
		out, _ = s.shell("python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'x', ('1.1.1.1', 53)); print('sent')\" 2>&1 | tail -1")
		if strings.Contains(out, "sent") {
			t.Errorf("a UDP packet to port 53 on a public resolver left the VM: %s", out)
		}
		resolver, _ := s.shell("awk '/^nameserver/{print $2; exit}' /run/systemd/resolve/resolv.conf")
		resolver = strings.TrimSpace(resolver)
		if resolver != "" {
			out, _ = s.shell("python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'x', ('" + resolver + "', 53)); print('sent')\" 2>&1 | tail -1")
			if strings.Contains(out, "sent") {
				t.Errorf("a UDP packet to port 53 on the configured resolver %s left the VM from the sandbox user: %s", resolver, out)
			}
		}
		// Positive control: names still resolve where they should, inside
		// the proxy, so an allowed host is reachable by name.
		out, _ = s.shell("curl -s -m 15 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/is-odd ; echo")
		if strings.TrimSpace(out) != "200" {
			t.Errorf("the proxy should still resolve and reach allowed hosts, got %s", strings.TrimSpace(out))
		}
	})

	t.Run("guest listeners are not forwarded to the Mac unless configured", func(t *testing.T) {
		// Lima forwards every port the guest listens on to 127.0.0.1 on the
		// host. A page the sandbox serves and you open in a browser then
		// runs with your browser's unrestricted network. Forwarding must be
		// opt-in per port.
		port := 18080 + int(time.Now().UnixNano()%1000)
		s.mustRun("shell", fmt.Sprintf("nohup python3 -m http.server %d --bind 0.0.0.0 >/dev/null 2>&1 & sleep 1; echo started", port))
		if reached := hostCanConnect(port, 8*time.Second); reached {
			t.Errorf("guest port %d was forwarded to the Mac without being configured", port)
			if home, err := os.UserHomeDir(); err == nil {
				ha, _ := os.ReadFile(filepath.Join(home, ".lima", "devkit-"+s.name, "ha.stderr.log"))
				for _, line := range strings.Split(string(ha), "\n") {
					if strings.Contains(line, fmt.Sprint(port)) {
						t.Log(line)
					}
				}
			}
		}
		// The bracket keeps pkill from matching the shell running it.
		s.mustRun("shell", fmt.Sprintf("pkill -f '[h]ttp.server %d'; true", port))
		// Positive control, on a different port so a forward left over from
		// the first listener cannot satisfy it: a configured port is forwarded.
		port2 := port + 1
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: false", fmt.Sprintf("allow_host: false\n  forward: [%d]", port2))
		t.Cleanup(func() {
			setYAML(t, filepath.Join(dir, "devkit.yaml"), fmt.Sprintf("\n  forward: [%d]", port2), "")
		})
		s.mustRun("up", "--no-sync", "--no-install")
		s.mustRun("shell", fmt.Sprintf("nohup python3 -m http.server %d --bind 0.0.0.0 >/dev/null 2>&1 & sleep 1; echo started", port2))
		defer s.shell(fmt.Sprintf("pkill -f '[h]ttp.server %d'; true", port2))
		if !hostCanConnect(port2, 15*time.Second) {
			t.Errorf("configured port %d should be forwarded to the Mac", port2)
		}
	})

	t.Run("unprivileged kernel attack surface is reduced", func(t *testing.T) {
		// A local privilege escalation is what turns the sandbox user into
		// root, and root can drop the firewall. These are the interfaces
		// most kernel exploits of the last few years needed from an
		// unprivileged process.
		want := map[string]string{
			"kernel.io_uring_disabled":                     "2",
			"kernel.unprivileged_bpf_disabled":             "1|2",
			"kernel.perf_event_paranoid":                   "3|4",
			"vm.unprivileged_userfaultfd":                  "0",
			"kernel.yama.ptrace_scope":                     "1|2|3",
			"kernel.kptr_restrict":                         "1|2",
			"kernel.dmesg_restrict":                        "1",
			"kernel.apparmor_restrict_unprivileged_userns": "1",
			"kernel.sysrq":                                 "0",
		}
		// The kernel crypto socket family is out of reach: creating an AF_ALG
		// socket (the surface of Copy-Fail and its algif siblings) must fail
		// for the sandbox user. AF_ALG is 38; a working family (AF_INET, 2)
		// is the control.
		out, _ := s.shell("python3 -c 'import socket; socket.socket(38, 5); print(\"opened\")' 2>&1; echo ---; python3 -c 'import socket; socket.socket(2, 1); print(\"inet-ok\")' 2>&1")
		if strings.Contains(out, "opened") {
			t.Errorf("AF_ALG socket should be refused but opened: %s", out)
		}
		if !strings.Contains(out, "inet-ok") {
			t.Errorf("a normal AF_INET socket should still work: %s", out)
		}
		for key, accept := range want {
			out, _ := s.shell("sysctl -n " + key + " 2>/dev/null; echo")
			got := strings.TrimSpace(out)
			ok := false
			for _, a := range strings.Split(accept, "|") {
				if got == a {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s = %q, want one of %s", key, got, accept)
			}
		}
	})

	t.Run("security updates are applied", func(t *testing.T) {
		// A frozen image gets weaker every week. The guest must have no
		// pending updates from the security pocket once provisioning is
		// done. (A new kernel on disk needs the next restart to run.)
		// Not vacuous: root records when the pocket was last applied
		// successfully (the index files carry the repository's own
		// timestamps, which say nothing about this boot).
		stamp, _ := s.shell("cat /var/lib/devkit/.security-updated 2>/dev/null; echo")
		if sec, err := strconv.ParseInt(strings.TrimSpace(stamp), 10, 64); err != nil || time.Since(time.Unix(sec, 0)) > 2*time.Hour {
			t.Errorf("no successful security-pocket refresh recorded for this boot (stamp %q): 'nothing pending' would mean nothing", strings.TrimSpace(stamp))
		}
		out, _ := s.shell("apt list --upgradable 2>/dev/null | grep -c -- '-security'; true")
		if strings.TrimSpace(out) != "0" {
			t.Errorf("pending security updates: %s", strings.TrimSpace(out))
			list, _ := s.shell("apt list --upgradable 2>/dev/null | grep -- '-security' | head -8")
			t.Log(list)
		}
	})
}

// hostCanConnect reports whether something on the Mac answers on 127.0.0.1:port
// within the deadline. Lima's forwarding is asynchronous, so it polls.
func hostCanConnect(port int, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// TestRootInGuestReachesHost documents the limit rather than a defence: with
// root inside the guest the firewall is gone, and Lima routes
// host.lima.internal to the Mac's loopback. It needs a VM with sudo and is
// gated because it is expected to show the reach, not to pass.
func TestRootInGuestReachesHost(t *testing.T) {
	if os.Getenv("DEVKIT_E2E_SUDO") == "" {
		t.Skip("set DEVKIT_E2E_SUDO=1 to run (creates a VM with sudo enabled)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2esudo-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"e2e","version":"1.0.0"}`)
	s.mustRun("init", "--name", name)
	setYAML(t, filepath.Join(dir, "devkit.yaml"), "# sudo: false", "sudo: true")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	s.mustRun("up", "--no-install")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("mac-loopback-service\n"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	probe := fmt.Sprintf("timeout 5 bash -c 'exec 3<>/dev/tcp/host.lima.internal/%d && head -c 20 <&3' 2>&1; echo", port)
	if out, _ := s.shell(probe); strings.Contains(out, "mac-loopback-service") {
		t.Fatalf("the firewall should hold before root is used: %s", out)
	}
	s.mustRun("shell", "sudo iptables -F OUTPUT && sudo iptables -P OUTPUT ACCEPT && echo flushed")
	if out, _ := s.shell(probe); strings.Contains(out, "mac-loopback-service") {
		t.Errorf("with root in the guest, a service on the Mac's loopback is reachable: %s", strings.TrimSpace(out))
	}
}
