package provision

import (
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func params(mod func(*project.Config)) Params {
	c := project.Default()
	c.Name = "test"
	c.Tools.Node = "22"
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
		"EXTRA_ARGS=-allowed=registry.npmjs.org,",
		`echo "abc123" > /etc/devkit/egress.sha256`,
		`NODE_MAJOR="22"`,
		"signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_${NODE_MAJOR}.x",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"/var/lib/devkit/.node",
		"--uid-owner devkit-proxy -j ACCEPT",
		"rm -f /etc/sudoers.d/90-cloud-init-users",
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
	for _, bad := range []string{"curl -fsSL \"https://deb.nodesource.com", "| bash", "sha256sum \"$f\""} {
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
		c.Tools.Node = ""
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
	if strings.Contains(s, "nodesource") {
		t.Error("node must not be installed when tools.node is empty")
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

func TestSystemScriptNone(t *testing.T) {
	s, err := System(params(func(c *project.Config) { c.Network.Mode = project.NetworkNone }))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "MODE=\"none\"") {
		t.Error("missing MODE=none")
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
	s, _ = User(params(func(c *project.Config) { c.Source = project.SourceMount }))
	if !strings.Contains(s, `ln -s "/Users/alice/proj" "$HOME/workspace"`) {
		t.Errorf("mount mode should symlink the mount: %s", s)
	}
}
