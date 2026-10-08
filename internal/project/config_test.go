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
		"bad node":        "name: a\ntools:\n  node: latest\n",
		"bad package":     "name: a\ntools:\n  packages: [\"rm -rf /\"]\n",
		"bad allow":       "name: a\nnetwork:\n  allow: [\"a b\"]\n",
		"writable no mnt": "name: a\nmount_writable: true\n",
		"tiny disk":       "name: a\nvm:\n  disk_gb: 1\n",
	}
	for label, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error for %q", label, src)
		}
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
	c.Tools.Node = "20"
	c.Network.Mode = NetworkNone
	path := filepath.Join(t.TempDir(), "devkit.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != c.Name || got.Tools.Node != "20" || got.Network.Mode != NetworkNone {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "devkit init") {
		t.Fatalf("expected helpful error, got %v", err)
	}
}
