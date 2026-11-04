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
