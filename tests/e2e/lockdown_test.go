package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKernelLockdown checks the two kernel controls on a real VM with sudo
// and the packages Ubuntu's AppArmor profiles exempt from its user-namespace
// restriction: unprivileged user namespaces are refused outright, even to
// an exempted rootlesskit, and module loading is locked once provisioning is
// done, across a restart, until vm.lock_modules: false.
func TestKernelLockdown(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2elock-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "kernel lockdown e2e\n")
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	cfg := filepath.Join(dir, "devkit.yaml")
	setYAML(t, cfg, "# sudo: false", "sudo: true")
	setYAML(t, cfg, "  # packages: [postgresql-client]", "  packages: [rootlesskit, slirp4netns, uidmap]")
	out := s.mustRun("up", "--no-install")
	if !strings.Contains(out, "locking kernel module loading") {
		t.Errorf("up should show the lock step:\n%s", out)
	}

	// rootlesskit is exempted by Ubuntu's AppArmor profile, so with the
	// namespace allowed it gets a working CAP_NET_ADMIN inside it.
	const rootlesskit = "timeout 30 rootlesskit --net=slirp4netns --disable-host-loopback sh -c 'ip link add dkp0 type dummy && echo NETADMIN-OK' 2>&1; true"
	closed := func(t *testing.T) {
		t.Helper()
		if out, _ := s.shell("unshare -U true 2>&1; echo exit=$?"); strings.Contains(out, "exit=0") {
			t.Errorf("the sandbox user created a user namespace: %s", out)
		}
		if out, _ := s.shell(rootlesskit); strings.Contains(out, "NETADMIN-OK") {
			t.Errorf("an exempted rootlesskit got CAP_NET_ADMIN in a namespace: %s", out)
		}
	}
	locked := func(t *testing.T) {
		t.Helper()
		if out, _ := s.shell("cat /proc/sys/kernel/modules_disabled"); strings.TrimSpace(out) != "1" {
			t.Errorf("modules_disabled = %q, want 1", strings.TrimSpace(out))
		}
		// "Operation not permitted", not "not found": the module exists and
		// loading it is refused, to root.
		out, _ := s.shell("lsmod | grep -qw '^dummy' && echo already-loaded; sudo modprobe dummy 2>&1; echo exit=$?")
		if strings.Contains(out, "already-loaded") {
			t.Fatalf("dummy is already loaded, so modprobe proves nothing: %s", out)
		}
		if strings.Contains(out, "exit=0") || !strings.Contains(out, "Operation not permitted") {
			t.Errorf("root should be refused loading a module: %s", out)
		}
	}
	works := func(t *testing.T) {
		t.Helper()
		// github.com is on the default allowlist; reached through the proxy.
		out, _ := s.shell("curl -s -m 20 -o /dev/null -w '%{http_code}' https://github.com/ ; echo")
		if strings.TrimSpace(out) != "200" {
			t.Errorf("the sandbox user should still reach an allowed host after the lock, got %s", strings.TrimSpace(out))
		}
	}

	t.Run("unprivileged user namespaces are refused, exemptions included", func(t *testing.T) {
		closed(t)
		// Root is unaffected, and the probe is not vacuous: with the switch
		// open, the same rootlesskit gets CAP_NET_ADMIN.
		if out, _ := s.shell("sudo unshare -U true 2>&1; echo exit=$?"); !strings.Contains(out, "exit=0") {
			t.Errorf("root should still create user namespaces: %s", out)
		}
		s.mustRun("shell", "sudo sysctl -q -w kernel.unprivileged_userns_clone=1 && echo opened")
		out, _ := s.shell(rootlesskit)
		s.mustRun("shell", "sudo sysctl -q -w kernel.unprivileged_userns_clone=0 && echo closed")
		if !strings.Contains(out, "NETADMIN-OK") {
			t.Errorf("control: with the switch open, rootlesskit should get CAP_NET_ADMIN (the probe is otherwise vacuous): %s", out)
		}
	})

	t.Run("module loading is locked and the VM still works", func(t *testing.T) {
		locked(t)
		works(t)
	})

	t.Run("a restart provisions and locks again", func(t *testing.T) {
		boot, _ := s.shell("cat /proc/sys/kernel/random/boot_id")
		s.mustRun("down")
		out := s.mustRun("up", "--no-sync", "--no-install")
		if b, _ := s.shell("cat /proc/sys/kernel/random/boot_id"); strings.TrimSpace(b) == strings.TrimSpace(boot) || strings.TrimSpace(b) == "" {
			t.Fatalf("the VM did not restart (boot_id %q)", b)
		}
		if strings.Contains(out, "failed:") {
			t.Errorf("provisioning on the second boot reported a failure:\n%s", out)
		}
		if id, _ := s.shell("cat /etc/devkit/provision.id"); strings.TrimSpace(id) == "" {
			t.Error("no provisioning stamp after the restart")
		}
		locked(t)
		closed(t)
		works(t)
	})

	t.Run("lock_modules: false leaves loading open", func(t *testing.T) {
		setYAML(t, cfg, "# lock_modules: true", "lock_modules: false")
		out := s.mustRun("up", "--no-sync", "--no-install")
		if !strings.Contains(out, "kernel module loading is not locked") {
			t.Errorf("up should note the lock is off:\n%s", out)
		}
		if out, _ := s.shell("cat /proc/sys/kernel/modules_disabled"); strings.TrimSpace(out) != "0" {
			t.Errorf("modules_disabled = %q, want 0", strings.TrimSpace(out))
		}
		if out, _ := s.shell("sudo modprobe dummy 2>&1; echo exit=$?"); !strings.Contains(out, "exit=0") {
			t.Errorf("with the lock off, root should load a module: %s", out)
		}
		closed(t)
	})
}
