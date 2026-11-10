package project

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Source != SourceCopy || c.Network.Mode != NetworkAllowlist || c.SSHPort != 2222 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.VM.CPUs != 4 || c.VM.MemoryGB != 8 || c.VM.DiskGB != 50 {
		t.Fatalf("unexpected vm defaults: %+v", c.VM)
	}
	if len(c.Network.Allow) == 0 || len(c.Exclude) == 0 {
		t.Fatal("allowlist and exclude seeds should not be empty")
	}
	if c.Sudo || c.Tools.Containers || c.Network.AllowHost {
		t.Fatal("privileged options must default to off")
	}
}

func TestParseMinimal(t *testing.T) {
	c, err := Parse([]byte("name: my-app\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.VMName() != "devkit-my-app" || c.SSHHost() != "devkit-my-app" {
		t.Fatalf("names: %s %s", c.VMName(), c.SSHHost())
	}
	if c.Network.Mode != NetworkAllowlist {
		t.Fatalf("mode = %s", c.Network.Mode)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"bad name":        "name: My App\n",
		"unknown key":     "name: a\nbogus: 1\n",
		"git needs repo":  "name: a\nsource: git\n",
		"bad source":      "name: a\nsource: docker\n",
		"bad mode":        "name: a\nnetwork:\n  mode: paranoid\n",
		"bad port":        "name: a\nssh_port: 22\n",
		"bad node":        "name: a\ntools:\n  node: \"22; id\"\n",
		"bad manager":     "name: a\ntools:\n  manager: asdf\n",
		"nix + versions":  "name: a\ntools:\n  manager: nix\n  versions: {node: \"22\"}\n",
		"backend in key":  "name: a\ntools:\n  versions: {\"aqua:x/y\": \"1\"}\n",
		"bad distrust":    "name: a\nnetwork:\n  distrust: [\"x; rm -rf /\"]\n",
		"distrust quote":  "name: a\nnetwork:\n  distrust: ['a\"b']\n",
		"version inject":  "name: a\ntools:\n  versions: {node: \"22\\\"\\nEOF\\n\"}\n",
		"bad package":     "name: a\ntools:\n  packages: [\"rm -rf /\"]\n",
		"bad allow":       "name: a\nnetwork:\n  allow: [\"a b\"]\n",
		"allow injection": "name: a\nnetwork:\n  allow: [\"$(touch${IFS}/tmp/pwn)\"]\n",
		"allow backtick":  "name: a\nnetwork:\n  allow: [\"`id`.com\"]\n",
		"allow star":      "name: a\nnetwork:\n  allow: [\"*\"]\n",
		"bad repo":        "name: a\nsource: git\nrepo: \"https://x.com/a.git;id\"\n",
		"bad branch":      "name: a\nsource: git\nrepo: https://x.com/a.git\nbranch: \"main$(id)\"\n",
		"writable no mnt": "name: a\nmount_writable: true\n",
		"tiny disk":       "name: a\nvm:\n  disk_gb: 1\n",
	}
	for label, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error for %q", label, src)
		}
	}
}

func TestToolsDefaults(t *testing.T) {
	c, err := Parse([]byte("name: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tools.Manager != ManagerNone || len(c.Tools.Versions) != 0 {
		t.Fatalf("no versions should mean no manager: %+v", c.Tools)
	}
	c, err = Parse([]byte("name: a\ntools:\n  node: \"22\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tools.Manager != ManagerMise || c.Tools.Versions["node"] != "22" || c.Tools.Node != "" {
		t.Fatalf("tools.node should become versions.node under mise: %+v", c.Tools)
	}
	c, err = Parse([]byte("name: a\ntools:\n  node: \"20\"\n  versions: {node: \"22\", go: \"1.27\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tools.Versions["node"] != "22" {
		t.Fatal("versions.node should win over the shorthand")
	}
	if _, err := Parse([]byte("name: a\ntools:\n  manager: nix\n")); err != nil {
		t.Fatalf("nix without versions must be valid: %v", err)
	}
}

func TestExplicitEmptyAllowIsKept(t *testing.T) {
	c, err := Parse([]byte("name: a\nnetwork:\n  mode: allowlist\n  allow: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Network.Allow) != 0 {
		t.Fatalf("explicit empty allowlist was replaced by defaults: %v", c.Network.Allow)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	c := Default()
	c.Name = "round-trip"
	c.Tools.Manager = ManagerMise
	c.Tools.Versions = map[string]string{"node": "20"}
	c.Install = "make deps"
	c.Network.Mode = NetworkNone
	path := filepath.Join(t.TempDir(), "devkit.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != c.Name || got.Tools.Manager != ManagerMise || got.Tools.Versions["node"] != "20" ||
		got.Install != "make deps" || got.Network.Mode != NetworkNone {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestLockModules(t *testing.T) {
	c, err := Parse([]byte("name: x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.VM.LockModules != nil || !c.VM.LockModulesOn() {
		t.Fatal("lock_modules must default to on")
	}
	c, err = Parse([]byte("name: x\nvm:\n  lock_modules: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.VM.LockModulesOn() {
		t.Fatal("lock_modules: false must be honoured")
	}
	for _, on := range []bool{false, true} {
		c := Default()
		c.Name = "lock"
		c.VM.LockModules = &on
		path := filepath.Join(t.TempDir(), "devkit.yaml")
		if err := c.Save(path); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got.VM.LockModules == nil || *got.VM.LockModules != on {
			t.Fatalf("lock_modules: %v did not round-trip: %v", on, got.VM.LockModules)
		}
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "devkit init") {
		t.Fatalf("expected helpful error, got %v", err)
	}
}

func TestAllowGrammar(t *testing.T) {
	c, err := Parse([]byte("name: a\nnetwork:\n  allow: [Example.COM, \"*.a.io\", \"**.b.dev\", 10.0.0.1, localhost]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Network.Allow[0] != "example.com" {
		t.Errorf("entries should be lower-cased, got %q", c.Network.Allow[0])
	}
	if c, err := Parse([]byte("name: a\nnetwork:\n  distrust: [AAA Certificate Services, \"emSign ECC Root CA - G3\"]\n")); err != nil || len(c.Network.Distrust) != 2 {
		t.Errorf("ordinary distrust names rejected: %v", err)
	}
	if _, err := Parse([]byte("name: a\nsource: git\nrepo: git@github.com:org/repo.git\nbranch: feat/x.1\n")); err != nil {
		t.Errorf("ordinary git url and branch rejected: %v", err)
	}
}

func TestAllowPortsDNSAndForward(t *testing.T) {
	c := Default()
	c.Name = "x"
	c.Network.Allow = []string{"github.com", "internal.example:8443", "**.corp.example:5432"}
	c.Network.DNS = DNSResolvers
	c.Network.Forward = []int{3000, 8080}
	if err := c.Validate(); err != nil {
		t.Fatalf("ports, dns and forward should validate: %v", err)
	}
	for _, bad := range []func(*Config){
		func(c *Config) { c.Network.Allow = []string{"github.com:0"} },
		func(c *Config) { c.Network.Allow = []string{"github.com:70000"} },
		func(c *Config) { c.Network.Allow = []string{"github.com:22:22"} },
		func(c *Config) { c.Network.DNS = "open" },
		func(c *Config) { c.Network.Forward = []int{0} },
		func(c *Config) { c.Network.Forward = []int{65536} },
	} {
		c := Default()
		c.Name = "x"
		bad(c)
		if err := c.Validate(); err == nil {
			t.Errorf("should be rejected: %+v", c.Network)
		}
	}
}

func TestEnforce(t *testing.T) {
	c, err := Parse([]byte("name: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.HostEnforced() {
		t.Fatal("enforcement must default to the guest")
	}
	for _, v := range []string{"guest", "host"} {
		c, err := Parse([]byte("name: a\nnetwork:\n  enforce: " + v + "\n"))
		if err != nil {
			t.Fatalf("enforce: %s should parse: %v", v, err)
		}
		if c.HostEnforced() != (v == "host") {
			t.Errorf("enforce: %s: HostEnforced() = %v", v, c.HostEnforced())
		}
	}
	for label, c := range map[string]struct{ yaml, want string }{
		"unknown value":    {"network:\n  enforce: mac\n", "network.enforce must be guest or host"},
		"with allow_host":  {"network:\n  enforce: host\n  allow_host: true\n", "allow_host"},
		"with resolvers":   {"network:\n  enforce: host\n  dns: resolvers\n", "dns: resolvers"},
		"with mode: none":  {"network:\n  enforce: host\n  mode: none\n", "mode: none"},
		"resolvers, guest": {"network:\n  enforce: guest\n  dns: resolvers\n", ""},
		"open, host":       {"network:\n  enforce: host\n  mode: open\n", ""},
	} {
		_, err := Parse([]byte("name: a\n" + c.yaml))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: should parse: %v", label, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error naming %q, got %v", label, c.want, err)
		}
	}
}
