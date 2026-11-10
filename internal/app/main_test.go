package app

import (
	"os"
	"testing"
)

// Tests that drive real git must not depend on the developer's global or
// system git config.
func TestMain(m *testing.M) {
	// devkit up starts the host proxy as "<its own executable> hostproxy
	// ...". Under test that executable is this test binary, which then
	// behaves as devkit for that one command.
	if len(os.Args) > 1 && os.Args[1] == "hostproxy" {
		rootCmd.SetArgs(os.Args[1:])
		if err := Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	os.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	os.Exit(m.Run())
}
