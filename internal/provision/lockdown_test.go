package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

const (
	moduleLock    = "\nsysctl -q -w kernel.modules_disabled=1\n"
	moduleLockOff = `note "kernel module loading is not locked (vm.lock_modules: false)"`
	// The first and last modules of the container preload list.
	preloadFirst = "bridge br_netfilter veth overlay"
	preloadLast  = "nft_chain_nat nft_compat"
)

// sysctlDropIn returns the body of the sysctl drop-in heredoc.
func sysctlDropIn(t *testing.T, s string) string {
	t.Helper()
	start := "cat > /etc/sysctl.d/90-devkit.conf <<'EOF'\n"
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatal("sysctl drop-in not found")
	}
	body := s[i+len(start):]
	return body[:strings.Index(body, "\nEOF\n")+1]
}

// Unprivileged user namespaces are refused outright, not only stripped of
// capabilities by AppArmor, whose stock profiles exempt programs a
// tools.packages entry can install. Rootless containers need them.
func TestUserNamespacesClosedUnlessContainers(t *testing.T) {
	for _, containers := range []bool{false, true} {
		s, err := System(params(func(c *project.Config) { c.Tools.Containers = containers }))
		if err != nil {
			t.Fatal(err)
		}
		want := "0"
		if containers {
			want = "1"
		}
		d := sysctlDropIn(t, s)
		if !strings.Contains(d, "\nkernel.unprivileged_userns_clone = "+want+"\n") {
			t.Errorf("containers=%v: the drop-in should set kernel.unprivileged_userns_clone = %s:\n%s", containers, want, d)
		}
		if !strings.Contains(d, "\nkernel.apparmor_restrict_unprivileged_userns = 1\n") {
			t.Errorf("containers=%v: the AppArmor restriction must stay", containers)
		}
		// Applied explicitly where the kernel has it, so its value follows the
		// config on every boot; a kernel without it does not abort the script.
		apply := `if [ -e /proc/sys/kernel/unprivileged_userns_clone ]; then
  sysctl -q -w kernel.unprivileged_userns_clone=` + want + `
else`
		if !strings.Contains(s, apply) {
			t.Errorf("containers=%v: the switch should be applied, guarded by its existence:\n%s", containers, apply)
		}
		if strings.Index(s, apply) < strings.Index(s, "sysctl -q -p /etc/sysctl.d/90-devkit.conf || true") {
			t.Errorf("containers=%v: the explicit switch must come after the drop-in is loaded", containers)
		}
	}
}

// lockVariants is every network mode and manager, guest and host
// enforcement, with and without containers.
func lockVariants(t *testing.T, mod func(*project.Config), check func(t *testing.T, s string)) {
	for _, containers := range []bool{false, true} {
		for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone} {
			for _, mgr := range []string{project.ManagerMise, project.ManagerNix, project.ManagerNone} {
				for _, host := range []bool{false, true} {
					if host && mode == project.NetworkNone {
						continue
					}
					name := mode + "-" + mgr
					if host {
						name += "-host"
					}
					if containers {
						name += "-containers"
					}
					t.Run(name, func(t *testing.T) {
						set := func(c *project.Config) {
							c.Network.Mode = mode
							c.Tools.Manager = mgr
							if mgr != project.ManagerMise {
								c.Tools.Versions = nil
							}
							c.Tools.Containers = containers
							c.Tools.Packages = []string{"jq"}
							c.Services.Postgres = &project.Postgres{Port: 5433, User: "u", Password: "p", Database: "d"}
							if mod != nil {
								mod(c)
							}
						}
						p := params(set)
						if host {
							p = hostParams(set)
						}
						s, err := System(p)
						if err != nil {
							t.Fatal(err)
						}
						check(t, s)
					})
				}
			}
		}
	}
}

// Module loading is locked as the last act before the stamp: after the
// firewall and the lift of the provisioning hold, so nothing that could
// still need a module runs after it.
func TestModulesAreLockedLast(t *testing.T) {
	lockVariants(t, nil, func(t *testing.T, s string) {
		lock := strings.Index(s, moduleLock)
		if lock < 0 || strings.Count(s, "kernel.modules_disabled") != 1 {
			t.Fatalf("module lock missing or repeated")
		}
		fw := strings.Index(s, "\n/usr/local/sbin/devkit-firewall\n")
		revert := strings.Index(s, `systemctl revert "$HOLD_SLICE"`)
		restart := strings.LastIndex(s, "\nsystemctl restart systemd-resolved\n")
		stamp := strings.Index(s, "> /etc/devkit/provision.id")
		if !(fw > 0 && fw < revert && revert < restart && restart < lock && lock < stamp) {
			t.Fatalf("order: firewall=%d revert=%d restart=%d lock=%d stamp=%d", fw, revert, restart, lock, stamp)
		}
		if !strings.Contains(s[:lock], `step "locking kernel module loading"`) {
			t.Error("the lock needs a progress step")
		}
		if strings.Contains(s, moduleLockOff) {
			t.Error("the opt-out note must not be printed when the lock is on")
		}
		// Nothing after the lock can need a module.
		after := s[lock+len(moduleLock):]
		for _, bad := range []string{"modprobe", "iptables", "systemctl", "$APT", "CURL", "mount ", "devkit-firewall"} {
			if strings.Contains(after, bad) {
				t.Errorf("%q runs after the module lock:\n%s", bad, after)
			}
		}
		// The lock is not in the drop-in, which is applied early in boot and
		// would refuse every module the boot loads after it.
		if strings.Contains(sysctlDropIn(t, s), "modules_disabled") {
			t.Error("modules_disabled must not be in the sysctl drop-in")
		}
	})
}

// lock_modules: false leaves loading open and says so.
func TestModuleLockOptOut(t *testing.T) {
	off := false
	lockVariants(t, func(c *project.Config) { c.VM.LockModules = &off }, func(t *testing.T, s string) {
		if strings.Contains(s, "kernel.modules_disabled") {
			t.Error("lock_modules: false must not lock module loading")
		}
		note := strings.Index(s, moduleLockOff)
		if note < 0 || note > strings.Index(s, "> /etc/devkit/provision.id") {
			t.Error("the opt-out should be noted before the stamp")
		}
		if strings.Contains(s, preloadFirst) {
			t.Error("nothing is preloaded when loading stays open")
		}
	})
}

// With containers, what they will need is loaded before the lock, since
// nothing can load afterwards; modules this kernel lacks are tolerated.
// Without containers nothing extra is loaded.
func TestModulePreloadOnlyWithContainers(t *testing.T) {
	lockVariants(t, nil, func(t *testing.T, s string) {
		containers := strings.Contains(s, "\nkernel.unprivileged_userns_clone = 1\n")
		first, last := strings.Index(s, preloadFirst), strings.Index(s, preloadLast)
		if !containers {
			if first >= 0 || strings.Contains(s, "for m in "+preloadFirst) {
				t.Error("without containers nothing extra is preloaded")
			}
			return
		}
		lock := strings.Index(s, moduleLock)
		if first < 0 || last < first || last > lock {
			t.Fatalf("preload: first=%d last=%d lock=%d", first, last, lock)
		}
		list := "bridge br_netfilter veth overlay nf_nat nf_conntrack_netlink tap tun xfrm_user " +
			"xt_MASQUERADE xt_addrtype xt_comment xt_conntrack xt_mark xt_multiport xt_nat xt_owner xt_tcpudp " +
			"ipt_REJECT ip6t_REJECT iptable_nat ip6table_nat iptable_filter ip6table_filter nft_chain_nat nft_compat"
		if !strings.Contains(s, "for m in "+list+"; do\n") {
			t.Errorf("the container preload list should be exactly:\n%s", list)
		}
		loop := s[first:lock]
		if !strings.Contains(loop, `modprobe -q "$m" 2>/dev/null || true`) {
			t.Errorf("a module this kernel lacks must not abort the script:\n%s", loop)
		}
	})
}

// The variants the parse test does not cover: containers, and the lock off.
func TestLockdownScriptsParse(t *testing.T) {
	dir := t.TempDir()
	off := false
	for name, p := range map[string]Params{
		"containers":      params(func(c *project.Config) { c.Tools.Containers = true }),
		"lock-off":        params(func(c *project.Config) { c.VM.LockModules = &off }),
		"containers-host": hostParams(func(c *project.Config) { c.Tools.Containers = true }),
	} {
		s, err := System(p)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".sh")
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %s", name, out)
		}
	}
}
