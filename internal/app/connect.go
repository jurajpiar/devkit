package app

import (
	"fmt"

	"github.com/jurajpiar/devkit/internal/provision"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Show how to connect an IDE to the sandbox",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		if err := writeSSHConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("SSH host %q is configured in ~/.ssh/config (port %d).\n\n", cfg.SSHHost(), cfg.SSHPort)
		fmt.Printf("Terminal:\n  ssh %s\n\n", cfg.SSHHost())
		fmt.Printf("VS Code / Cursor:\n")
		fmt.Printf("  1. Install the \"Remote - SSH\" extension\n")
		fmt.Printf("  2. Command palette: \"Remote-SSH: Connect to Host...\" and pick %s\n", cfg.SSHHost())
		fmt.Printf("  3. Open folder: ~/%s\n\n", provision.WorkspaceDir)
		fmt.Printf("Ports your app listens on inside the VM appear on 127.0.0.1 automatically.\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
}
