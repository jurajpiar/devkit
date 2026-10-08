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
		"deb.nodesource.com/setup_22.x",
		"--uid-owner devkit-proxy -j ACCEPT",
		"rm -f /etc/sudoers.d/90-cloud-init-users",
		"NOPASSWD: DEVKIT_LIMA",
		"/usr/bin/diff -q /run/lima-boot-done /mnt/lima-cidata/meta-data",
		"/usr/bin/diff -q /run/lima-ssh-ready /mnt/lima-cidata/meta-data",
		"/usr/bin/cat /mnt/lima-cidata/param.env",
		`gpasswd -d "$DEVKIT_USER" sudo`,
		`-d "$HOST_IP" -p udp --dport 53 -j ACCEPT`,
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
	} {
		if !strings.Contains(s, want) {
			t.Errorf("system script missing %q", want)
		}
	}
	if strings.Contains(s, "nodesource") {
		t.Error("node must not be installed when tools.node is empty")
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
