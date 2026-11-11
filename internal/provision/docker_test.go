package provision

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func dockerParams(mod func(*project.Config)) Params {
	return params(func(c *project.Config) {
		c.Tools.Containers = project.ContainersDocker
		if mod != nil {
			mod(c)
		}
	})
}

// dockerVariants is every network mode and manager, guest and host
// enforcement, with tools.containers: docker.
func dockerVariants(t *testing.T, check func(t *testing.T, p Params, s string)) {
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
				t.Run(name, func(t *testing.T) {
					set := func(c *project.Config) {
						c.Tools.Containers = project.ContainersDocker
						c.Network.Mode = mode
						c.Tools.Manager = mgr
						if mgr != project.ManagerMise {
							c.Tools.Versions = nil
						}
						c.Tools.Packages = []string{"jq"}
					}
					p := params(set)
					if host {
						p = hostParams(set)
					}
					s, err := System(p)
					if err != nil {
						t.Fatal(err)
					}
					check(t, p, s)
				})
			}
		}
	}
}

// index returns where want first appears in s, failing the test if it does
// not appear exactly once.
func index(t *testing.T, s, want string) int {
	t.Helper()
	if n := strings.Count(s, want); n != 1 {
		t.Fatalf("%q appears %d times, want once", want, n)
	}
	return strings.Index(s, want)
}

const (
	dockerHold   = `systemctl set-property --runtime "$DOCKER_SLICE" IPAddressDeny=any`
	dockerLift   = `systemctl set-property --runtime "$DOCKER_SLICE" IPAddressAllow=any`
	dockerRevert = `systemctl revert "$DOCKER_SLICE"`
	dockerStart  = "\n  systemctl start devkit-dockerd.service\n"
	// The daemon starts in the system script only when devkit's guest binary,
	// which every runtime in daemon.json is, is installed and the expected one.
	dockerGuestOK   = `if [ -n "$GUEST_WANT" ] && [ "$(sha256sum ` + EgressBinary + ` 2>/dev/null | awk '{print $1}')" = "$GUEST_WANT" ]; then GUEST_OK=1; fi`
	dockerGuarded   = "\nif [ \"$GUEST_OK\" = 1 ]; then\n  step \"starting Docker\"\n"
	dockerDeferred  = "\nelse\n  note \"Docker starts once devkit up has installed devkit's guest binary\"\nfi\n"
	dockerLinger    = `loginctl enable-linger "$DOCKER_ACCOUNT"`
	dockerMask      = "systemctl mask docker.service docker.socket containerd.service >/dev/null"
	dockerUnit      = "cat > /etc/systemd/system/devkit-dockerd.service <<EOF\n"
	dockerLauncher  = "cat > /usr/local/sbin/devkit-dockerd <<EOF\n"
	dockerOffMarker = "# ---- Docker off: undo what tools.containers: docker set up ----"
)

// Only tools.containers: docker sets Docker up; every other configuration
// carries the steps that undo it instead, for a VM that had it.
func TestDockerStepsOnlyInDockerMode(t *testing.T) {
	steps := []string{dockerHold, dockerStart, dockerLinger, dockerMask, dockerUnit, dockerLauncher,
		"dpkg-statoverride --force-all --update --add root", "apparmor_parser -R", `echo "DOCKER_HOST=unix://` + FilterSocket + `" >> /etc/environment`,
		"cat > " + DockerConfigHelper + " <<'DKEOF'\n", "docker.io docker-compose-v2"}
	for _, v := range []project.Containers{project.ContainersOff, project.ContainersContainerd} {
		s, err := System(params(func(c *project.Config) { c.Tools.Containers = v }))
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range steps {
			if strings.Contains(s, st) {
				t.Errorf("containers %q: %q belongs to docker mode only", v, st)
			}
		}
		for _, undo := range []string{dockerOffMarker, "systemctl stop devkit-dockerd.service", "dpkg-statoverride --remove", `apparmor_parser -r "/etc/apparmor.d/$n"`,
			"loginctl disable-linger " + DockerAccount, "rm -f /etc/profile.d/devkit-docker.sh", "/^DOCKER_HOST=/d"} {
			if !strings.Contains(s, undo) {
				t.Errorf("containers %q: the script should undo Docker with %q", v, undo)
			}
		}
		u, _ := User(params(func(c *project.Config) { c.Tools.Containers = v }))
		if strings.Contains(u, DockerConfigHelper) {
			t.Errorf("containers %q: the user script must not run the Docker helper", v)
		}
	}
	s, err := System(dockerParams(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if !strings.Contains(s, st) {
			t.Errorf("docker mode should contain %q", st)
		}
	}
	if strings.Contains(s, dockerOffMarker) {
		t.Error("docker mode must not undo itself")
	}
	if u, _ := User(dockerParams(nil)); !strings.Contains(u, "\n"+DockerConfigHelper+"\n") {
		t.Errorf("the user script should run the Docker helper:\n%s", u)
	}
	if _, err := System(dockerParams(func(c *project.Config) { c.Source = project.SourceMount })); err != nil {
		// The template renders; Validate is what refuses the combination.
		t.Fatal(err)
	}
}

// The order the design rests on: the account is held before anything can
// start under it; the daemon starts only after the firewall and the lift of
// every hold, and answers before module loading is locked.
func TestDockerOrdering(t *testing.T) {
	dockerVariants(t, func(t *testing.T, p Params, s string) {
		account := index(t, s, `useradd --system --user-group --no-create-home --home-dir "$DOCKER_HOME" --shell /usr/sbin/nologin "$DOCKER_ACCOUNT"`)
		hold := index(t, s, dockerHold)
		sandboxHold := index(t, s, holdSlice)
		if !(sandboxHold < account && account < hold) {
			t.Errorf("the account is made and held with the sandbox user's hold: sandbox=%d account=%d hold=%d", sandboxHold, account, hold)
		}
		for _, later := range []string{dockerLinger, "$APT ", dockerUnit, dockerStart, "apparmor_parser", "dpkg-statoverride"} {
			if i := strings.Index(s, later); i >= 0 && i < hold {
				t.Errorf("%q comes before the account's hold", later)
			}
		}
		// The rootful daemon is masked before the packages could start it.
		mask := strings.Index(s, dockerMask)
		install := index(t, s, "$APT install -y --no-install-recommends $WANT_PKGS")
		if mask < 0 || mask > install {
			t.Errorf("the rootful units must be masked before the packages install: mask=%d install=%d", mask, install)
		}
		fw := index(t, s, "\n/usr/local/sbin/devkit-firewall\n")
		revert := index(t, s, `systemctl revert "$HOLD_SLICE"`)
		restart := strings.LastIndex(s, "\nsystemctl restart systemd-resolved\n")
		lift, dRevert := index(t, s, dockerLift), index(t, s, dockerRevert)
		start := index(t, s, dockerStart)
		wait := index(t, s, `timeout 10 docker --host "unix://`+DockerSocket+`" info`)
		filterWait := index(t, s, filterWait)
		lock := strings.Index(s, moduleLock)
		stamp := index(t, s, "> /etc/devkit/provision.id")
		if !(fw < revert && revert < restart && restart < lift && lift < dRevert && dRevert < start && start < wait && wait < filterWait && filterWait < lock && lock < stamp) {
			t.Errorf("order: firewall=%d revert=%d resolved=%d lift=%d drevert=%d start=%d wait=%d filter=%d lock=%d stamp=%d", fw, revert, restart, lift, dRevert, start, wait, filterWait, lock, stamp)
		}
		// The start, its waits and the filter's are all under the condition
		// that devkit's guest binary is installed and the expected one;
		// otherwise the script only says so, before the module lock.
		guestOK, guarded, deferred := index(t, s, dockerGuestOK), index(t, s, dockerGuarded), index(t, s, dockerDeferred)
		if !(dRevert < guestOK && guestOK < guarded && guarded < start && filterWait < deferred && (lock < 0 || deferred < lock)) {
			t.Errorf("guard: drevert=%d test=%d if=%d start=%d filter=%d else=%d lock=%d", dRevert, guestOK, guarded, start, filterWait, deferred, lock)
		}
		if strings.Contains(s[guarded:deferred], "\nfi\n") || strings.Contains(s[guarded:deferred], "\nelse\n") {
			t.Errorf("the start must stay inside the condition:\n%s", s[guarded:deferred])
		}
		if !strings.Contains(s, `GUEST_WANT="$(cat /etc/devkit/egress.sha256)"`+"\nGUEST_OK=0\n"+dockerGuestOK+dockerGuarded) {
			t.Error("GUEST_OK must start at 0 and be set by the hash test just before the start")
		}
		// The unit exists before it starts, and a workspace before the
		// daemon's mount of it.
		if unit, ws := index(t, s, dockerUnit), index(t, s, `install -d -o "$DEVKIT_USER" -g "$SANDBOX_GID" -m 0755 "$WS"`); !(ws < unit && unit < start) {
			t.Errorf("workspace=%d unit=%d start=%d", ws, unit, start)
		}
		// The wait is bounded and its failure aborts; the lift is never excused.
		tail := s[lift:stamp]
		if !strings.Contains(tail, "for _ in $(seq 1 90); do") || !strings.Contains(tail, "if [ \"$docker_up\" != 1 ]; then\n    warn ") || !strings.Contains(tail, "    exit 1\n  fi\n") {
			t.Errorf("the daemon's start must be waited for, boundedly, and abort on failure:\n%s", tail)
		}
		if strings.Contains(s[lift:dRevert], "||") || strings.Contains(s[start:wait], "||") {
			t.Errorf("a failed lift or start must abort the script:\n%s", s[lift:wait])
		}
		// With the lock on, the modules containers use are loaded once,
		// before the daemon starts.
		if first := strings.Index(s, "for m in "+preloadFirst); p.Config.VM.LockModulesOn() && !(dRevert < first && first < start && strings.Count(s, "for m in "+preloadFirst) == 1) {
			t.Errorf("preload=%d revert=%d start=%d", first, dRevert, start)
		}
		// The hold is on the two slices and resolved, by runtime property;
		// the daemon's own unit never runs before the lift, so it needs none.
		// The filter's unit denies IP outright: it speaks Unix sockets only.
		filterUnit, err := heredocBody(s, filterServiceUnit)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(s, "IPAddressDeny=any") - strings.Count(filterUnit, "IPAddressDeny=any\n"); n != 3 {
			t.Errorf("IPAddressDeny=any should be set on the two slices and resolved only, found %d", n)
		}
		// Nothing but this script, and the install step under its own
		// condition (TestDockerStartFromInstall), starts the daemon.
		inst, err := heredocBody(s, installProxyOpen)
		if err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"start", "restart"} {
			if n, m := strings.Count(s, "systemctl "+verb+" devkit-dockerd"), strings.Count(inst, "systemctl "+verb+" devkit-dockerd"); n-m != map[string]int{"start": 1, "restart": 0}[verb] {
				t.Errorf("systemctl %s devkit-dockerd: %d in the script, %d of them in the install step", verb, n, m)
			}
		}
		unit, err := heredocBody(s, dockerUnit)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(unit, "[Install]") || strings.Contains(s, "enable devkit-dockerd") || strings.Contains(s, "enable --now devkit-dockerd") {
			t.Errorf("devkit-dockerd.service must not be enabled for boot:\n%s", unit)
		}
		for _, want := range []string{"PrivateMounts=yes", "Delegate=yes", "Restart=on-failure", "Requires=user@$DOCKER_UID.service", "After=user@$DOCKER_UID.service", "ExecStart=/usr/local/sbin/devkit-dockerd"} {
			if !strings.Contains(unit, want+"\n") {
				t.Errorf("the unit should have %q:\n%s", want, unit)
			}
		}
		// The boot hold, which covers boots after the first until this script
		// runs, holds the account by UID too.
		gen, err := section(s, bootHoldBegin, bootHoldEnd)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(gen, "for who in $SANDBOX_UID $SUBUIDS $DOCKER_UID; do") || strings.Index(s, `DOCKER_UID="$(id -u "$DOCKER_ACCOUNT")"`) > strings.Index(s, bootHoldBegin) {
			t.Error("the boot hold must hold Docker's account, looked up before the generator")
		}
		if d := sysctlDropIn(t, s); !strings.Contains(d, "\nkernel.unprivileged_userns_clone = 1\n") {
			t.Errorf("docker needs user namespaces on in the kernel:\n%s", d)
		}
	})
}

// When provisioning left the daemon unstarted because devkit's guest binary
// was missing or another build, the install step starts it once the binary
// is in place, and only once this boot's provisioning has finished: the
// firewall's mark in /run and the stamp both present. A replaced binary
// under a running daemon restarts it. Every other configuration's install
// step leaves the daemon alone. The install script parses.
func TestDockerStartFromInstall(t *testing.T) {
	const provisioned = "  if [ -f /run/devkit/firewall-at ] && [ -s /etc/devkit/provision.id ]; then\n"
	const startBlock = provisioned +
		"    if ! systemctl is-active --quiet devkit-dockerd.service; then\n" +
		"      systemctl start devkit-dockerd.service || true\n" +
		"    elif [ \"$prev\" != \"$got\" ]; then\n" +
		"      systemctl restart devkit-dockerd.service || true\n" +
		"    fi\n" +
		"  fi\n"
	dir := t.TempDir()
	dockerAndGvisorVariants(t, func(t *testing.T, p Params, s string) {
		inst, err := heredocBody(s, installProxyOpen)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(inst, startBlock) != 1 {
			t.Fatalf("the install step should start the daemon only once provisioned:\n%s", inst)
		}
		// prev is the hash before the install; the start follows the install
		// and precedes the filter's restart, all under the hash match.
		match := strings.Index(inst, `if [ -n "$want" ] && [ "$got" = "$want" ]; then`)
		prev := strings.Index(inst, `prev="$(sha256sum `+EgressBinary+` 2>/dev/null | awk '{print $1}')"`)
		install := strings.Index(inst, `install -m 755 -o root -g root "$tmp" `+EgressBinary)
		start := strings.Index(inst, startBlock)
		filter := strings.Index(inst, "systemctl restart "+FilterUnit+".socket")
		refused := strings.Index(inst, "\nelse\n")
		if !(match >= 0 && match < prev && prev < install && install < start && start < filter && filter < refused) {
			t.Errorf("order: match=%d prev=%d install=%d start=%d filter=%d else=%d\n%s", match, prev, install, start, filter, refused, inst)
		}
		path := filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-install.sh")
		os.WriteFile(path, []byte(inst), 0o644)
		if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("the install script does not parse: %s\n%s", out, inst)
		}
	})
	for _, v := range []project.Containers{project.ContainersOff, project.ContainersContainerd} {
		for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen} {
			s := mustSystem(t, params(func(c *project.Config) { c.Tools.Containers = v; c.Network.Mode = mode }))
			inst, err := heredocBody(s, installProxyOpen)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(inst, "devkit-dockerd") || strings.Contains(inst, "prev=") {
				t.Errorf("containers %q, %s: the install step must leave Docker alone:\n%s", v, mode, inst)
			}
			path := filepath.Join(dir, string(v)+"-"+mode+"-install.sh")
			os.WriteFile(path, []byte(inst), 0o644)
			if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
				t.Errorf("the install script does not parse: %s", out)
			}
		}
	}
}

// The daemon gets the in-guest proxy as containers reach it, and nothing
// when the VM has no proxy.
func TestDockerLauncher(t *testing.T) {
	dockerVariants(t, func(t *testing.T, p Params, s string) {
		l, err := heredocBody(s, dockerLauncher)
		if err != nil {
			t.Fatal(err)
		}
		proxy := "HTTP_PROXY=http://10.0.2.2:3128 HTTPS_PROXY=http://10.0.2.2:3128 NO_PROXY=localhost,127.0.0.1"
		if none := p.Config.Network.Mode == project.NetworkNone; none && strings.Contains(l, "PROXY") {
			t.Errorf("no proxy, no proxy variables:\n%s", l)
		} else if !none && !strings.Contains(l, proxy) {
			t.Errorf("mode %s: the launcher should hand the daemon the proxy (%s):\n%s", p.Config.Network.Mode, proxy, l)
		}
		for _, want := range []string{
			`mount --bind -o "X-mount.idmap=$IDMAP" "\$W" "\$W"`,
			"exec setpriv --reuid $DOCKER_UID --regid $DOCKER_GID --init-groups",
			"DBUS_SESSION_BUS_ADDRESS=unix:path=$DOCKER_RUN/bus",
			"rootlesskit --state-dir=$DOCKER_RUN/dockerd-rootless --net=slirp4netns --mtu=65520",
			"--disable-host-loopback=false",
			"--config-file=/etc/devkit/docker/daemon.json --host=unix://" + DockerSocket,
		} {
			if !strings.Contains(l, want) {
				t.Errorf("the launcher should contain %q:\n%s", want, l)
			}
		}
		if d := daemonJSON(t, s); d["no-new-privileges"] != true || d["ip"] != "127.0.0.1" {
			t.Errorf("daemon.json should hold devkit's defaults: %v", d)
		}
		// Socket access for the filter's account only, and traversal of the
		// home for it and the Docker account; no ACL on the workspace itself.
		for _, want := range []string{
			`setfacl -m "u:$FILTER_ACCOUNT:rx" -m "d:u:$FILTER_ACCOUNT:rw" "$DOCKER_HOME/run"`,
			`setfacl -m "u:$DOCKER_ACCOUNT:x" "$DEVKIT_HOME"`,
			`setfacl -m "u:$FILTER_ACCOUNT:x" "$DEVKIT_HOME"`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q", want)
			}
		}
		if strings.Count(s, "setfacl -m") != 3 || strings.Contains(s, "setfacl -R") || strings.Contains(s, `setfacl -m "u:$DEVKIT_USER`) {
			t.Error("the workspace must carry no ACL, and the sandbox user none on the daemon's directory")
		}
		// The launcher mounts the workspace by its real path and refuses a
		// symlink in its place.
		if !strings.Contains(l, `W='$WS_REAL'`) || !strings.Contains(l, `if [ -L "\$W" ] || [ ! -d "\$W" ]`) {
			t.Errorf("the launcher should use the workspace's real path and refuse a symlink:\n%s", l)
		}
	})
}

// The scripts parse in every Docker variant, and so do the launcher and the
// helper they write.
func TestDockerScriptsParse(t *testing.T) {
	shellcheck, _ := exec.LookPath("shellcheck")
	python, _ := exec.LookPath("python3")
	dir := t.TempDir()
	dockerVariants(t, func(t *testing.T, p Params, s string) {
		u, err := User(p)
		if err != nil {
			t.Fatal(err)
		}
		l, err := heredocBody(s, dockerLauncher)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.ReplaceAll(t.Name(), "/", "-")
		for kind, body := range map[string]string{"system": s, "user": u} {
			path := filepath.Join(dir, name+"-"+kind+".sh")
			os.WriteFile(path, []byte(body), 0o644)
			if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
				t.Errorf("%s does not parse: %s", kind, out)
			}
			if shellcheck != "" {
				if out, err := exec.Command(shellcheck, "--severity=error", "--shell=bash", path).CombinedOutput(); err != nil {
					t.Errorf("shellcheck %s:\n%s", kind, out)
				}
			}
		}
		// The launcher as root's shell will see it once the heredoc expands.
		expanded := strings.NewReplacer(`\$`, "$", `\\`, `\`, "$DOCKER_UID", "999", "$DOCKER_GID", "999", "$DOCKER_HOME", DockerHome,
			"$DOCKER_RUN", "/run/user/999", "$SANDBOX_UID", "501", "$IDMAP", "u:501:999:1", "$WS_REAL", "/home/alice/workspace", "$WS", "/home/alice/workspace", "$DOCKER_ACCOUNT", DockerAccount).Replace(l)
		lp := filepath.Join(dir, name+"-launcher.sh")
		os.WriteFile(lp, []byte(expanded), 0o644)
		if out, err := exec.Command("sh", "-n", lp).CombinedOutput(); err != nil {
			t.Errorf("the launcher does not parse: %s\n%s", out, expanded)
		}
		if python != "" {
			h, err := heredocBodyDelim(s, "cat > "+DockerConfigHelper+" <<'DKEOF'\n", "DKEOF")
			if err != nil {
				t.Fatal(err)
			}
			hp := filepath.Join(dir, name+"-helper.py")
			os.WriteFile(hp, []byte(h), 0o644)
			if out, err := exec.Command(python, "-I", "-m", "py_compile", hp).CombinedOutput(); err != nil {
				t.Errorf("the helper does not compile: %s", out)
			}
		}
	})
}

// heredocBodyDelim is heredocBody for a delimiter other than EOF.
func heredocBodyDelim(s, opener, delim string) (string, error) {
	r := strings.NewReplacer("\nEOF\n", "\nEOF-\n", "\n"+delim+"\n", "\nEOF\n")
	return heredocBody(r.Replace(s), r.Replace(opener))
}

// runHelper runs the Docker client helper, as rendered for p, with home as
// $HOME, and returns the config it left.
func runHelper(t *testing.T, p Params, home string) map[string]any {
	t.Helper()
	data := runHelperRaw(t, p, home)
	if data == nil {
		return nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("helper wrote invalid JSON: %v\n%s", err, data)
	}
	return cfg
}

// runHelperRaw is runHelper returning the file as it is, or nil if absent.
func runHelperRaw(t *testing.T, p Params, home string) []byte {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	s, err := System(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := heredocBodyDelim(s, "cat > "+DockerConfigHelper+" <<'DKEOF'\n", "DKEOF")
	if err != nil {
		t.Fatal(err)
	}
	hp := filepath.Join(t.TempDir(), "helper.py")
	os.WriteFile(hp, []byte(h), 0o755)
	cmd := exec.Command(python, "-I", hp)
	cmd.Env = append(os.Environ(), "HOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return nil
	}
	return data
}

func noProxyOf(t *testing.T, cfg map[string]any) string {
	t.Helper()
	d, _ := cfg["proxies"].(map[string]any)["default"].(map[string]any)
	if d == nil {
		t.Fatalf("no proxies.default: %v", cfg)
	}
	if d["httpProxy"] != "http://10.0.2.2:3128" || d["httpsProxy"] != "http://10.0.2.2:3128" {
		t.Errorf("proxy settings: %v", d)
	}
	np, _ := d["noProxy"].(string)
	return np
}

// Compose service names reach no_proxy; anything from the repository that
// is not a plain name is dropped, and the user's other settings are kept.
func TestDockerHelperNoProxy(t *testing.T) {
	home := t.TempDir()
	ws := filepath.Join(home, WorkspaceDir)
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(ws, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("compose.yaml", `# a comment
x-common: &common
  image: busybox
services:
  web:
    image: busybox:1.36
    container_name: web-1
  "db":
    <<: *common
    environment:
      notaservice: 1
  'a b':
    image: x
  x,y:
    image: x
  $(touch /tmp/pwned):
    image: x
  "evil\nname":
    image: x
  -dash:
    image: x
  cache: # trailing comment
    container_name: "bad name"
volumes:
  data:
`)
	write("compose.override.yml", "services:\n  debug:\n    image: x\n")
	write("api/docker-compose.yml", "services:\n\n  api:\n    image: x\n    container_name: api_main\n")
	write("deep/er/compose.yaml", "services:\n  toodeep:\n    image: x\n")
	write("notcompose.yaml", "services:\n  ignored:\n    image: x\n")
	os.MkdirAll(filepath.Join(home, ".docker"), 0o700)
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"auths": {"r.example": {"auth": "x"}}, "proxies": {"default": {"ftpProxy": "ftp://f"}}}`), 0o600)

	cfg := runHelper(t, dockerParams(nil), home)
	if got, want := noProxyOf(t, cfg), "localhost,127.0.0.1,::1,api,api_main,cache,db,debug,web,web-1"; got != want {
		t.Errorf("noProxy = %q, want %q", got, want)
	}
	if _, ok := cfg["auths"]; !ok {
		t.Error("other settings must be kept")
	}
	if cfg["proxies"].(map[string]any)["default"].(map[string]any)["ftpProxy"] != "ftp://f" {
		t.Error("other proxy settings must be kept")
	}
	if fi, _ := os.Stat(filepath.Join(home, ".docker", "config.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("config.json mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Error("a service name ran a command")
	}

	// No proxy in the VM: the settings devkit wrote go, the rest stays.
	cfg = runHelper(t, dockerParams(func(c *project.Config) { c.Network.Mode = project.NetworkNone }), home)
	d := cfg["proxies"].(map[string]any)["default"].(map[string]any)
	if _, ok := d["httpProxy"]; ok || d["ftpProxy"] != "ftp://f" {
		t.Errorf("mode none should remove devkit's proxy settings only: %v", d)
	}
	if _, ok := d["noProxy"]; ok {
		t.Errorf("noProxy should be removed: %v", d)
	}

	// A file that is not JSON is left alone.
	bad := []byte("{not json")
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), bad, 0o600)
	if got := runHelperRaw(t, dockerParams(nil), home); string(got) != string(bad) {
		t.Errorf("an invalid config must not be overwritten: %q", got)
	}

	// No config and no workspace yet (the first boot's user provisioning).
	fresh := t.TempDir()
	if got := noProxyOf(t, runHelper(t, dockerParams(nil), fresh)); got != "localhost,127.0.0.1,::1" {
		t.Errorf("noProxy without a workspace = %q", got)
	}
	// Mode none with no config writes nothing.
	empty := t.TempDir()
	if cfg := runHelper(t, dockerParams(func(c *project.Config) { c.Network.Mode = project.NetworkNone }), empty); cfg != nil {
		t.Errorf("mode none should write nothing: %v", cfg)
	}
}
