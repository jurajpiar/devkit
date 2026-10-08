// Package app implements the devkit command line.
package app

import (
	"context"
	"fmt"
	"os"
	"os/user"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "devkit",
	Short: "Disposable sandbox VMs for untrusted code and coding agents",
	Long: `devkit runs each project in its own virtual machine on Apple's hypervisor.

The VM has no access to your files, cannot reach services on your Mac, and
can only talk to the hosts you allow. Everything is audited. When you are
done, 'devkit rm' throws the whole machine away.

Typical flow:
  devkit init        # write devkit.yaml for this directory
  devkit up          # create or start the VM, copy the code in, install deps
  devkit shell       # or: ssh devkit-<name> from VS Code / Cursor
  devkit logs        # see what the sandbox tried to reach
  devkit rm          # delete the VM`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", project.DefaultFile, "path to devkit.yaml")
}

// loadConfig reads the config named by --config.
func loadConfig(cmd *cobra.Command) (*project.Config, error) {
	path, _ := cmd.Flags().GetString("config")
	return project.Load(path)
}

// requireLima fails early with install instructions.
func requireLima() error {
	return lima.CheckInstalled()
}

// hostUser is the macOS account name, which Lima mirrors inside the guest.
func hostUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// instance fetches the project's VM, or nil if it does not exist.
func instance(ctx context.Context, cfg *project.Config) (*lima.Instance, error) {
	return lima.Get(ctx, cfg.VMName())
}
