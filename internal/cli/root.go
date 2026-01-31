package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "devkit",
	Short: "Secure local development infrastructure kit",
	Long: `Devkit orchestrates secure, rootless containers for local development.

Containers are isolated from the host filesystem and come with
pre-installed dependencies for your project. Supports VS Code
remote development via SSH.`,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "devkit.yaml", "config file path")
}

// exitWithError prints an error and exits
func exitWithError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	os.Exit(1)
}
