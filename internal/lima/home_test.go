package lima

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHomeFollowsLimaHome(t *testing.T) {
	t.Setenv("LIMA_HOME", "/tmp/elsewhere")
	if got := Home(); got != "/tmp/elsewhere" {
		t.Errorf("Home() = %q, want LIMA_HOME", got)
	}
	if got := ConfigPath("x"); got != filepath.Join("/tmp/elsewhere", "x", "lima.yaml") {
		t.Errorf("ConfigPath = %q", got)
	}
	// An existing home reached through a symlink resolves to the real
	// directory, as limactl does, before any child path is joined.
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "_config"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, _ = filepath.EvalSymlinks(real) // macOS: /var is itself a symlink
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIMA_HOME", filepath.Join(link, "_config", ".."))
	if got := Home(); got != real {
		t.Errorf("Home() through a symlink = %q, want %q", got, real)
	}
	t.Setenv("LIMA_HOME", "")
	if got := Home(); filepath.Base(got) != ".lima" {
		t.Errorf("Home() without LIMA_HOME = %q, want ~/.lima", got)
	}
}
