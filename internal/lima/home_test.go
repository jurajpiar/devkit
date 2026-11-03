package lima

import (
	"os"
	"path/filepath"
	"testing"
)

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

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
	// The ".." is kept raw: filepath.Join would clean it away before the
	// symlink is ever consulted, which is exactly the bug being tested.
	t.Setenv("LIMA_HOME", link+"/_config/..")
	if got := Home(); got != real {
		t.Errorf("Home() through a symlink = %q, want %q", got, real)
	}
	// And the case that distinguishes the orders: link -> real/_config, so
	// link/.. must be real (the target's parent), not the link's directory.
	link2 := filepath.Join(filepath.Dir(link), "link2")
	if err := os.Symlink(filepath.Join(real, "_config"), link2); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIMA_HOME", link2+"/..")
	if got := Home(); got != real {
		t.Errorf("Home() with link2/.. = %q, want %q (Abs before EvalSymlinks would give %q)", got, real, filepath.Dir(link2))
	}
	// A relative LIMA_HOME is made absolute, so the path persisted in the
	// SSH config does not depend on the directory devkit up ran in.
	t.Setenv("LIMA_HOME", "rel/lima")
	if got, want := Home(), filepath.Join(mustGetwd(t), "rel", "lima"); got != want {
		t.Errorf("Home() with a relative LIMA_HOME = %q, want %q", got, want)
	}
	t.Setenv("LIMA_HOME", "")
	if got := Home(); filepath.Base(got) != ".lima" {
		t.Errorf("Home() without LIMA_HOME = %q, want ~/.lima", got)
	}
}
