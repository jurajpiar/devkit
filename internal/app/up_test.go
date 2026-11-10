package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetSecurityUpdates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devkit.yaml")
	base := "name: x\n\nvm:\n  cpus: 4\n  memory_gb: 8\n  disk_gb: 50\n\nnetwork:\n  mode: allowlist\n"
	if err := os.WriteFile(p, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setSecurityUpdates(p, false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "  disk_gb: 50\n  security_updates: false\n") {
		t.Errorf("should add the line under the vm block:\n%s", got)
	}
	if err := setSecurityUpdates(p, true); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(p)
	if strings.Count(string(got), "security_updates:") != 1 || !strings.Contains(string(got), "security_updates: true") {
		t.Errorf("should replace the existing line, not add another:\n%s", got)
	}
}

// hostYAMLWithComment is hostYAML with a comment that an edit must keep.
const hostYAMLWithComment = "# my project\nname: demo\nvm:\n  disk_gb: 50 # room for images\ntools:\n  manager: none\nnetwork:\n  mode: allowlist # allowlist | open | none\n  enforce: host\n  allow: [example.com]\n"

// A flag whose result devkit.yaml would reject must leave the file exactly
// as it was, so the project's other commands keep working.
func TestUpRejectsAnInvalidNetworkFlagWithoutChangingTheConfig(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAMLWithComment)
	fakeSandboxExec(t)
	t.Cleanup(func() { stopHostProxy("devkit-demo") })
	info, _ := os.Stat(cfgPath)

	out, err := runDevkit(t, "", "up", "--config", cfgPath, "--network", "none", "--no-sync", "--no-install")
	if err == nil || !strings.Contains(err.Error(), "enforce: host") || !strings.Contains(err.Error(), "mode: none") || !strings.Contains(err.Error(), "unchanged") {
		t.Fatalf("up must name the conflict and say the file is unchanged, got %v\n%s", err, out)
	}
	got, _ := os.ReadFile(cfgPath)
	if string(got) != hostYAMLWithComment {
		t.Errorf("devkit.yaml must be left byte-for-byte as it was:\n%s", got)
	}
	if after, _ := os.Stat(cfgPath); !os.SameFile(info, after) {
		t.Error("devkit.yaml must not be replaced when nothing changes")
	}
	for _, v := range f.Verbs() {
		if v == "create" || v == "start" {
			t.Errorf("nothing may be created or started: %v", f.Verbs())
		}
	}
	mustLoad(t, cfgPath)
	if _, err := runDevkit(t, "", "shell", "--config", cfgPath, "true"); err != nil && strings.Contains(err.Error(), "invalid devkit.yaml") {
		t.Errorf("a later command must still load the config: %v", err)
	}
}

func TestUpWritesAValidNetworkFlagAndKeepsComments(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAMLWithComment)
	fakeSandboxExec(t)
	t.Cleanup(func() { stopHostProxy("devkit-demo") })
	must(t, os.Chmod(cfgPath, 0o600))

	if out, err := runDevkit(t, "", "up", "--config", cfgPath, "--network", "open", "--no-security-updates", "--no-sync", "--no-install"); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	c := mustLoad(t, cfgPath)
	if c.Network.Mode != "open" || c.VM.SecurityUpdatesOn() {
		t.Errorf("both edits must be written: mode %s, security updates %v", c.Network.Mode, c.VM.SecurityUpdatesOn())
	}
	got, _ := os.ReadFile(cfgPath)
	for _, want := range []string{"# my project\n", "  mode: open # allowlist | open | none\n", "  disk_gb: 50 # room for images\n  security_updates: false\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("devkit.yaml should contain %q:\n%s", want, got)
		}
	}
	if info, _ := os.Stat(cfgPath); info.Mode().Perm() != 0o600 {
		t.Errorf("the file's mode must be kept, got %v", info.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(cfgPath), "*.tmp")); len(left) != 0 {
		t.Errorf("no temp file may be left: %v", left)
	}
}

// Both flags at once are validated together: one invalid edit leaves the
// other unapplied too.
func TestUpWithBothFlagsAndOneInvalidLeavesTheConfigUntouched(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAMLWithComment)
	fakeSandboxExec(t)
	t.Cleanup(func() { stopHostProxy("devkit-demo") })

	out, err := runDevkit(t, "", "up", "--config", cfgPath, "--network", "none", "--no-security-updates", "--no-sync", "--no-install")
	if err == nil || !strings.Contains(err.Error(), "mode: none") {
		t.Fatalf("up must refuse, got %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != hostYAMLWithComment {
		t.Errorf("neither edit may be applied:\n%s", got)
	}
}
