package app

import (
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check that this Mac can run devkit sandboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok := true
		check := func(pass bool, label, fix string) {
			mark := "ok  "
			if !pass {
				mark = "FAIL"
				ok = false
			}
			fmt.Printf("[%s] %s\n", mark, label)
			if !pass && fix != "" {
				fmt.Printf("       %s\n", fix)
			}
		}

		check(goruntime.GOOS == "darwin", "macOS host", "devkit uses Apple's Virtualization.framework and only runs on macOS")
		check(goruntime.GOARCH == "arm64", "Apple silicon", "Intel Macs are not supported by the vz backend used here")

		limaOK := lima.CheckInstalled() == nil
		check(limaOK, "Lima installed (limactl)", "brew install lima")
		if limaOK {
			v, err := lima.Version(cmd.Context())
			check(err == nil, "Lima version: "+v, "")
		}

		_, err := egressProxyBinary(cmd.Context())
		check(err == nil, "egress proxy binary available", "run 'make build' in the devkit checkout, or install Go")

		switch _, keyErr := os.Stat(filepath.Join(lima.Home(), "_config", "user")); {
		case keyErr == nil:
			check(true, "Lima SSH key present", "")
		case os.IsNotExist(keyErr):
			fmt.Println("[--  ] Lima SSH key not created yet (Lima generates it on the first VM start)")
		default:
			check(false, "Lima SSH key readable", keyErr.Error())
		}

		if !ok {
			return fmt.Errorf("some checks failed")
		}
		fmt.Println("\nAll good. Run 'devkit init' in a project directory.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
