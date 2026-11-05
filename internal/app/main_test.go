package app

import (
	"os"
	"testing"
)

// Tests that drive real git must not depend on the developer's global or
// system git config.
func TestMain(m *testing.M) {
	os.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	os.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	os.Exit(m.Run())
}
