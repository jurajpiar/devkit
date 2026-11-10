package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// netProbe runs as the sandbox user with plain sockets: no curl, no proxy
// variables. It prints "<label> OPEN|closed" per destination. Option 25 is
// SO_BINDTODEVICE, which binds a socket to an interface without privilege
// and so sidesteps routing rules.
const netProbe = `import socket
def tcp(label, host, port, dev=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        if dev:
            s.setsockopt(socket.SOL_SOCKET, 25, dev.encode() + b"\0")
        s.connect((host, port))
        print(label, "OPEN")
    except Exception:
        print(label, "closed")
    finally:
        s.close()
tcp("internet", "1.1.1.1", 80)
tcp("mac", "192.168.5.2", 22)
tcp("internet-eth0", "1.1.1.1", 80, "eth0")
tcp("mac-eth0", "192.168.5.2", 22, "eth0")
tcp("loopback", "127.0.0.1", 22)
`

// TestFailedProvisioningFailsClosed makes provisioning fail with a package
// that does not exist and checks both layers: devkit up stops the VM and
// says why, and a VM started by hand keeps the sandbox user off the network.
// Fixed, the VM provisions and the hold is gone; broken again on a VM that
// was provisioned before, up fails the same way.
func TestFailedProvisioningFailsClosed(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2e-pf-%d", time.Now().Unix()%100000)
	vm := "devkit-" + name
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "provisioning failure e2e\n")
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })

	cfgPath := filepath.Join(dir, "devkit.yaml")
	good, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	pkgLine := regexp.MustCompile(`(?m)^  (# )?packages: \[.*\]$`)
	if !pkgLine.Match(good) {
		t.Fatalf("no packages line in devkit.yaml:\n%s", good)
	}
	bad := pkgLine.ReplaceAllString(string(good), "  packages: [devkit-no-such-package]")
	writeFile(t, cfgPath, bad)

	failsClosed := func(t *testing.T, when string) {
		t.Helper()
		out, err := s.run("up")
		if err == nil {
			t.Fatalf("%s: up must fail when provisioning fails:\n%s", when, out)
		}
		if strings.Contains(out, "Ready") {
			t.Errorf("%s: up must not print Ready:\n%s", when, out)
		}
		if !strings.Contains(out, "did not finish provisioning") || !strings.Contains(out, "checking extra packages") {
			t.Errorf("%s: up should name the failed step:\n%s", when, out)
		}
		if st := limaStatus(t, vm); st != "Stopped" {
			t.Errorf("%s: the VM should be stopped, it is %q", when, st)
		}
	}

	t.Run("first boot: up fails and stops the VM", func(t *testing.T) {
		failsClosed(t, "first boot")
	})

	t.Run("started by hand: the sandbox user reaches nothing", func(t *testing.T) {
		// Provisioning fails again on this boot; limactl may say so.
		b, err := exec.Command("limactl", "start", "--tty=false", vm).CombinedOutput()
		t.Logf("limactl start: %v\n%s", err, b)
		if st := limaStatus(t, vm); st != "Running" {
			t.Fatalf("the VM should be running after limactl start, it is %q", st)
		}
		got := guest(t, vm, "python3 -", netProbe)
		for _, label := range []string{"internet", "mac", "internet-eth0", "mac-eth0", "loopback"} {
			if !strings.Contains(got, label+" closed\n") {
				t.Errorf("%s should be closed under the hold:\n%s", label, got)
			}
		}
		if q := guest(t, vm, "timeout 10 resolvectl query --legend=no ietf.org 2>&1; true", ""); regexp.MustCompile(`(?m)^ietf\.org: [0-9a-f]`).MatchString(q) {
			t.Errorf("systemd-resolved answered for the sandbox user under the hold:\n%s", q)
		}
		if st := guest(t, vm, "test -e /etc/devkit/provision.id && echo present || echo absent", ""); !strings.Contains(st, "absent") {
			t.Errorf("a failed provisioning must leave no stamp: %q", st)
		}
		// The image's passwordless sudo must be gone although provisioning
		// failed, or the sandbox user could lift the hold with
		// "sudo systemctl revert user-<uid>.slice". The probe is sudo -n true:
		// outside Lima's three boot checks like the revert, so the policy
		// decides the same way, but harmless if it were allowed. Lima's own
		// check must still pass: the denial is devkit's policy, not a broken
		// sudo.
		if out := guest(t, vm, "sudo -n true; echo exit=$?", ""); !strings.Contains(out, "exit=1\n") {
			t.Errorf("sudo must be denied on a VM whose first provisioning failed:\n%s", out)
		}
		if out := guest(t, vm, "sudo -n cat /mnt/lima-cidata/param.env >/dev/null; echo exit=$?", ""); !strings.Contains(out, "exit=0\n") {
			t.Errorf("Lima's boot check must still be allowed by sudo:\n%s", out)
		}
	})

	t.Run("shell refuses a VM without a stamp", func(t *testing.T) {
		out, err := s.run("shell", "true")
		if err == nil || !strings.Contains(out, "devkit up") {
			t.Errorf("shell should refuse and point at devkit up: %v\n%s", err, out)
		}
	})

	t.Run("fixed: up succeeds and the hold is lifted", func(t *testing.T) {
		writeFile(t, cfgPath, string(good))
		out := s.mustRun("up")
		if !strings.Contains(out, "Ready") {
			t.Fatalf("up should finish with Ready:\n%s", out)
		}
		// Through the proxy on loopback: works only if the hold was lifted,
		// loopback included.
		code, err := s.shell("curl -sS -m 30 -o /dev/null -w '%{http_code}' https://github.com/")
		if err != nil || !regexp.MustCompile(`(?m)^[23][0-9][0-9]$`).MatchString(strings.TrimSpace(code)) {
			t.Errorf("an allowed host should be reachable through the proxy: %v %q", err, code)
		}
		// The firewall decides now: loopback open, everything else closed.
		got := guest(t, vm, "python3 -", netProbe)
		if !strings.Contains(got, "loopback OPEN\n") {
			t.Errorf("loopback should be open after the lift:\n%s", got)
		}
		for _, label := range []string{"internet", "mac", "internet-eth0", "mac-eth0"} {
			if !strings.Contains(got, label+" closed\n") {
				t.Errorf("%s should be closed by the firewall:\n%s", label, got)
			}
		}
	})

	t.Run("broken again after a good boot: up fails the same way", func(t *testing.T) {
		writeFile(t, cfgPath, bad)
		failsClosed(t, "re-provisioning")
	})
}

// guest runs a command as the sandbox user through limactl directly, not
// devkit shell, which refuses a VM without a stamp.
func guest(t *testing.T, vm, cmd, stdin string) string {
	t.Helper()
	c := exec.Command("limactl", "shell", "--workdir", "/", vm, "--", "bash", "-c", cmd)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	b, err := c.CombinedOutput()
	t.Logf("guest %q: %v\n%s", cmd, err, b)
	return string(b)
}

// limaStatus is the instance's status as limactl reports it, "" if absent.
func limaStatus(t *testing.T, vm string) string {
	t.Helper()
	out, err := exec.Command("limactl", "list", "--format", "json").Output()
	if err != nil {
		t.Fatalf("limactl list: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		var inst struct{ Name, Status string }
		if json.Unmarshal([]byte(line), &inst) == nil && inst.Name == vm {
			return inst.Status
		}
	}
	return ""
}
