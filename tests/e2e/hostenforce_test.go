//go:build darwin

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jurajpiar/devkit/internal/app"
)

// TestHostEnforcement checks network.enforce: host on a real VM: the Mac,
// not the guest, holds the line. It first checks the normal path through
// both proxies, then becomes root in the guest, removes every in-guest
// control, and runs the spike's raw-socket probe
// (testdata/guest-root-probe.py), which must find exactly one reachable
// thing: the host proxy.
//
// LuLu or another outbound firewall on the Mac must allow the devkit binary
// this test builds, or the host proxy's connections hang.
func TestHostEnforcement(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	probe, err := os.ReadFile(filepath.Join("testdata", "guest-root-probe.py"))
	if err != nil {
		t.Fatal(err)
	}

	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2ehost-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	cfg := filepath.Join(dir, "devkit.yaml")
	setYAML(t, cfg, "  # enforce: guest", "  enforce: host")
	setYAML(t, cfg, "# sudo: false", "sudo: true")
	setYAML(t, cfg, "  allow:\n", "  allow:\n    - example.com\n")

	// A service on the Mac's loopback that nothing in the VM may reach.
	canary, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { canary.Close() })
	canaryPort := canary.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := canary.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("devkit-canary\n"))
			c.Close()
		}
	}()

	upOut := s.mustRun("up", "--no-install")
	if strings.Contains(upOut, "warning: could not") {
		t.Fatalf("devkit up reported a failed step:\n%s", upOut)
	}
	if !strings.Contains(upOut, "enforced on the Mac") {
		t.Fatalf("devkit up should report host enforcement:\n%s", upOut)
	}
	// Resolved as devkit does: namespaced by Lima home under a custom
	// LIMA_HOME.
	state := app.VMStateDir("devkit-" + name)
	portData, err := os.ReadFile(filepath.Join(state, "hostproxy.port"))
	if err != nil {
		t.Fatal(err)
	}
	hostPort := strings.TrimSpace(string(portData))
	// A UDP service on the Mac's loopback at the host proxy's port number,
	// which the profile allows over TCP only. It answers every datagram and
	// counts those that arrive; TCP and UDP port numbers are separate, so it
	// binds beside the proxy.
	udpCanary, err := net.ListenPacket("udp", "127.0.0.1:"+hostPort)
	if err != nil {
		t.Fatalf("UDP listener on the host proxy's port number: %v", err)
	}
	t.Cleanup(func() { udpCanary.Close() })
	var udpGot atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udpCanary.ReadFrom(buf)
			if err != nil {
				return
			}
			udpGot.Add(1)
			_, _ = udpCanary.WriteTo(append([]byte("devkit-udp-canary:"), buf[:n]...), from)
		}
	}()
	// Control, from the Mac: the listener answers.
	if c, err := net.Dial("udp", "127.0.0.1:"+hostPort); err != nil {
		t.Fatal(err)
	} else {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("control"))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		c.Close()
		if err != nil || !strings.HasPrefix(string(buf[:n]), "devkit-udp-canary:") {
			t.Fatalf("control: the UDP listener should answer on the Mac: %v %q", err, buf[:n])
		}
	}
	udpBefore := udpGot.Load()
	hostLog := func() string {
		b, _ := os.ReadFile(filepath.Join(state, "hostproxy.log"))
		return string(b)
	}

	t.Run("provisioning completed through the host proxy", func(t *testing.T) {
		out, _ := s.shell("test -s /etc/devkit/provision.id && test -s /run/devkit/firewall-at && systemctl is-active devkit-egress && grep -c -- '-upstream 192.168.5.2:" + hostPort + "' /etc/systemd/system/devkit-egress.service")
		if !strings.Contains(out, "active") || !strings.Contains(out, "\n1") {
			t.Fatalf("stamp, firewall and chained proxy expected: %s", out)
		}
		if strings.Contains(out, "host enforcement is off") || strings.Contains(out, "older devkit policy") {
			t.Fatalf("a VM devkit just started must not warn: %s", out)
		}
		// Root's apt went through the host proxy: the Ubuntu archive is in
		// the host log, though it is not in network.allow.
		if !regexp.MustCompile(`ALLOWED \S+ (ports|archive|security)\.ubuntu\.com:`).MatchString(hostLog()) {
			t.Errorf("root's apt should appear in the host log:\n%s", hostLog())
		}
	})

	t.Run("the sandbox reaches allowed hosts through both proxies", func(t *testing.T) {
		out, _ := s.shell("curl -s -m 30 -o /dev/null -w '%{http_code}' https://example.com/ ; echo")
		if strings.TrimSpace(out) != "200" {
			t.Fatalf("example.com should be reachable, got %s", out)
		}
		out, _ = s.shell("curl -s -m 30 -o /dev/null -w '%{http_connect}' https://example.org/ ; echo")
		if strings.TrimSpace(out) != "403" {
			t.Errorf("example.org is not allowed and must be refused (403), got %s", out)
		}
		if !strings.Contains(hostLog(), "ALLOWED CONNECT example.com:443") {
			t.Errorf("the host log must record the allowed tunnel:\n%s", hostLog())
		}
	})

	t.Run("guest root without in-guest controls reaches only the host proxy", func(t *testing.T) {
		s.mustRun("shell", "cat > ~/guest-root-probe.py <<'PYEOF'\n"+string(probe)+"\nPYEOF")
		s.mustRun("shell", "sudo systemctl stop devkit-egress devkit-proxy-install.path && "+
			"for t in iptables ip6tables; do sudo $t -P OUTPUT ACCEPT; sudo $t -F OUTPUT; done && echo controls-removed")
		if out, _ := s.shell("sudo iptables -S OUTPUT; systemctl is-active devkit-egress"); !strings.Contains(out, "-P OUTPUT ACCEPT") || strings.Contains(out, "-A OUTPUT") || !strings.Contains(out, "inactive") {
			t.Fatalf("the in-guest controls should be gone: %s", out)
		}

		// The host proxy still decides by the allowlist, now that it is
		// the only thing standing.
		// sudo warns on stderr that it cannot resolve the hostname: the
		// guest has no DNS. Only curl's own line is compared.
		out, _ := s.shell("sudo curl -s -m 30 -p -x http://192.168.5.2:" + hostPort + " -o /dev/null -w 'code=%{http_connect}\\n' https://example.org/ 2>/dev/null")
		if !strings.Contains(out, "code=403") {
			t.Errorf("root through the host proxy to a host off the allowlist: want 403, got %s", out)
		}
		out, _ = s.shell("sudo curl -s -m 30 -x http://192.168.5.2:" + hostPort + " -o /dev/null -w 'code=%{http_code}\\n' https://example.com/ 2>/dev/null")
		if !strings.Contains(out, "code=200") {
			t.Errorf("root through the host proxy to an allowed host: want 200, got %s", out)
		}
		logs := s.mustRun("logs", "-n", "1000")
		if !strings.Contains(logs, "ALLOWED CONNECT example.com:443") || !strings.Contains(logs, "BLOCKED CONNECT example.org:443") {
			t.Errorf("devkit logs (the host log) must have both decisions:\n%s", logs)
		}

		out, _ = s.shell(fmt.Sprintf("sudo python3 -I ~/guest-root-probe.py %s %d", hostPort, canaryPort))
		t.Logf("probe:\n%s", out)
		m := regexp.MustCompile(`SUMMARY: (\d+) pass, (\d+) fail`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("the probe did not report a summary")
		}
		if m[2] != "0" || m[1] == "0" {
			t.Errorf("guest root escaped host enforcement: %s pass, %s fail", m[1], m[2])
		}
		if !strings.Contains(out, "UDP to the host proxy's port number") {
			t.Errorf("the probe did not try UDP to the host proxy's port number")
		}
		// A probe that tries less passes more easily. Each route out must
		// have been tried: an edit that drops a block of checks fails here
		// instead of passing with a smaller count (it happened once).
		for _, tried := range []string{
			"host proxy port on the Mac",
			"TCP to 1.1.1.1:80", "TCP to 1.1.1.1:443", "TCP to 35.180.139.74:8080", "TCP to 140.82.121.3:22",
			"TCP over IPv6",
			"DNS over UDP to 8.8.8.8", "DNS over TCP to 8.8.8.8",
			"UDP (NTP)",
			"DNS over UDP through Lima at 192.168.5.2", "DNS over TCP through Lima at 192.168.5.2",
			"canary listener on the Mac",
			"port sweep of the Mac",
		} {
			if !strings.Contains(out, "PASS "+tried) {
				t.Errorf("the probe did not pass, or did not try: %s", tried)
			}
		}
		if n, _ := strconv.Atoi(m[1]); n < 21 {
			t.Errorf("the probe ran %d checks, fewer than the 21 it should", n)
		}
		if n := udpGot.Load() - udpBefore; n != 0 {
			t.Errorf("%d datagram(s) from the guest reached the UDP listener at the host proxy's port number", n)
		}
	})
}
