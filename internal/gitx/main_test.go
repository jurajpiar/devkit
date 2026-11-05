package gitx

import (
	"os"
	"testing"
)

// The tests drive real git; the developer's global and system config (a
// global gitignore, signing, default branch, hooks) must not change them.
func TestMain(m *testing.M) {
	os.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	os.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	os.Exit(m.Run())
}
