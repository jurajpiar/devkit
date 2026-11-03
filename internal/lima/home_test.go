package lima

import (
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
	t.Setenv("LIMA_HOME", "")
	if got := Home(); filepath.Base(got) != ".lima" {
		t.Errorf("Home() without LIMA_HOME = %q, want ~/.lima", got)
	}
}
