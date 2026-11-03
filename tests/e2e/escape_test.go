package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// escapeAttempts runs inside the shared allowlist-mode VM. Each case is
// something code in the sandbox could try in order to reach the host, the
// open internet, or the policy that keeps it in. Hypervisor bugs are out of
// scope: these cover every channel devkit itself opens or could leave open.
func escapeAttempts(t *testing.T, s *sandbox, hostDir string) {
	gw, _ := s.shell("ip route | awk '/default/{print $3; exit}'")
	gw = strings.TrimSpace(gw)
	if gw == "" {
		t.Fatal("could not find the gateway address")
	}

	t.Run("host is unreachable under every address form", func(t *testing.T) {
		for _, target := range []string{"host.lima.internal:2222", gw + ":2222", gw + ":22", gw + ":80", gw + ":3128"} {
			out, _ := s.shell("timeout 5 bash -c 'exec 3<>/dev/tcp/" + strings.Replace(target, ":", "/", 1) + "' 2>&1; echo exit=$?")
			if strings.Contains(out, "exit=0") {
				t.Errorf("direct TCP to %s should be rejected: %s", target, out)
			}
			out, _ = s.shell("curl -s -m 5 -o /dev/null -w '%{http_code}' http://" + target + "/; echo exit=$?")
			if strings.Contains(out, "200") {
				t.Errorf("proxied request to %s got through: %s", target, out)
			}
		}
		// UDP: the firewall answers with ICMP port unreachable, which the
		// socket sees as a refusal; a reply would mean the host was reached.
		py := `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b"x",("` + gw + `",2222))
try: s.recvfrom(16); print("got-reply")
except ConnectionRefusedError: print("refused")
except socket.timeout: print("timeout")`
		out, _ := s.shell("python3 -c '" + py + "'")
		if !strings.Contains(out, "refused") && !strings.Contains(out, "timeout") {
			t.Errorf("UDP to the host should be rejected: %s", out)
		}
		// IPv6: the OUTPUT chain rejects it too.
		out, _ = s.shell("timeout 5 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>&1; echo exit=$?")
		if strings.Contains(out, "exit=0") {
			t.Errorf("IPv6 egress should be rejected: %s", out)
		}
	})

	t.Run("firewall cannot be bypassed without root", func(t *testing.T) {
		checks := map[string]string{
			"iptables -F":       "iptables -F 2>&1; echo exit=$?",
			"user namespace":    "unshare -rn bash -c 'ip link set lo up; timeout 5 bash -c \"exec 3<>/dev/tcp/1.1.1.1/443\"' 2>&1; echo exit=$?",
			"raw socket":        "python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)' 2>&1; echo exit=$?",
			"bind port 22":      "python3 -c 'import socket; s=socket.socket(); s.bind((\"0.0.0.0\",22))' 2>&1; echo exit=$?",
			"change proxy user": "su devkit-proxy -s /bin/sh -c id 2>&1 </dev/null; echo exit=$?",
			"resolver override": "timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>&1; echo exit=$?",
		}
		for name, cmd := range checks {
			out, _ := s.shell(cmd)
			if strings.Contains(out, "exit=0") {
				t.Errorf("%s should fail: %s", name, out)
			}
		}
		// Killing the proxy would not open anything, but it would be a denial
		// of service the sandbox should not have either.
		out, _ := s.shell("pkill -f devkit-egressproxy 2>&1; sleep 1; systemctl is-active devkit-egress")
		if !strings.Contains(out, "active") || strings.Contains(out, "inactive") {
			t.Errorf("sandbox user should not be able to stop the proxy: %s", out)
		}
		out, _ = s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ ; echo exit=$?")
		if !strings.Contains(out, "200") {
			t.Fatalf("the proxy should still be serving after the attempts: %s", out)
		}
	})

	t.Run("lima channels carry no secrets and no host paths", func(t *testing.T) {
		out, _ := s.shell("grep -rl 'PRIVATE KEY' /mnt/lima-cidata 2>/dev/null | wc -l; findmnt -t virtiofs -n | wc -l; ls /mnt/lima-cidata")
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) < 2 || lines[0] != "0" || lines[1] != "0" {
			t.Fatalf("cidata must hold no private keys and no host directory may be mounted:\n%s", out)
		}
		// The host side of the vsock is not something the sandbox can dial.
		py := `import socket
try:
    s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.settimeout(3); s.connect((2, 2222)); print("connected")
except Exception as e: print("failed:", type(e).__name__)`
		out, _ = s.shell("python3 -c '" + py + "'")
		if strings.Contains(out, "connected") {
			t.Errorf("sandbox user should not reach the host over vsock: %s", out)
		}
	})

	t.Run("policy files are root-only", func(t *testing.T) {
		files := []string{
			"/usr/local/sbin/devkit-firewall", "/usr/local/sbin/devkit-install-proxy",
			"/etc/devkit/network.conf", "/etc/devkit/egress.conf", "/etc/devkit/egress.sha256",
			"/usr/local/bin/devkit-egressproxy", "/var/log/devkit/egress.log",
			"/etc/environment", "/etc/profile.d/devkit-proxy.sh", "/etc/profile.d/devkit-mise.sh",
			"/etc/systemd/system/devkit-egress.service", "/etc/systemd/system/devkit-proxy-install.service",
			"/etc/sudoers.d/devkit", "/run/systemd/resolve/resolv.conf",
		}
		out, _ := s.shell("for f in " + strings.Join(files, " ") + "; do [ -e \"$f\" ] || echo MISSING:$f; [ -w \"$f\" ] && echo WRITABLE:$f; done; echo done")
		if strings.Contains(out, "WRITABLE") || strings.Contains(out, "MISSING") {
			t.Fatalf("policy files must exist and be unwritable:\n%s", out)
		}
		out, _ = s.shell("sudo -ln 2>&1")
		if strings.Contains(out, "(ALL)") || !strings.Contains(out, "DEVKIT_LIMA") && !strings.Contains(out, "lima-cidata") {
			t.Fatalf("sudo should allow only Lima's boot checks: %s", out)
		}
		out, _ = s.shell("find /usr/local /home /var /opt /tmp -xdev -perm -4000 -type f 2>/dev/null | wc -l")
		if strings.TrimSpace(out) != "0" {
			t.Fatalf("no setuid binaries outside Ubuntu's defaults expected: %s", out)
		}
	})

	t.Run("nothing from the VM lands on the host", func(t *testing.T) {
		// A hostile workspace rewrites every file devkit might be tempted to
		// bring back, then up runs again. The host directory must not change.
		before := dirDigest(t, hostDir)
		s.mustRun("shell", "echo pwned > ~/.config/mise/mise.lock.tmp; echo '{\"pwned\":true}' > flake.lock; echo pwned > package.json; printf '\\033[2J\\033]0;pwned\\007' > pwn.txt")
		s.mustRun("up", "--no-install")
		if after := dirDigest(t, hostDir); after != before {
			t.Fatal("devkit up changed the project directory on the host")
		}
		s.mustRun("shell", "rm -f flake.lock pwn.txt ~/.config/mise/mise.lock.tmp")
	})
}

// dirDigest hashes the names and contents of every file under dir.
func dirDigest(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		h.Write([]byte(rel + "\n"))
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			h.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}
