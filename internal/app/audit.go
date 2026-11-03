package app

import (
	"fmt"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Report stale trust: roots the VM, its runtimes or the project trust that Mozilla no longer does",
	Long: `Report stale trust inside the sandbox.

The reference is Mozilla's current root store, fetched through the proxy and
cached for a day, with the system bundle as the fallback. The audit compares
it with the system bundle, Node's bundled roots, Java's cacerts, certifi
bundles in virtualenvs and toolchains, and certificate files in the project,
and names anything that is trusted but should not be. devkit up runs the
same audit shallowly after installing dependencies; --deep scans every file
in the workspace, including node_modules and vendored trees.

Exit status is 1 when something stale was found.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		if err := mustBeRunning(cmd, cfg); err != nil {
			return err
		}
		script := "devkit-audit"
		if deep, _ := cmd.Flags().GetBool("deep"); deep {
			script += " --deep"
		}
		if err := lima.ExecStream(cmd.Context(), cfg.VMName(), script); err != nil {
			return fmt.Errorf("stale trust found")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().Bool("deep", false, "scan every file in the workspace, including node_modules and vendored trees")
}
