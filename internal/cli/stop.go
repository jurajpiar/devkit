package cli

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the development container",
	Long: `Stop the running development container.

By default, the container is only stopped and can be restarted with 'devkit start'.
Use --remove to also remove the container.

Examples:
  devkit stop           # Stop the container
  devkit stop --remove  # Stop and remove the container`,
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)

	stopCmd.Flags().Bool("remove", false, "Also remove the container after stopping")
	stopCmd.Flags().BoolP("force", "f", false, "Force stop (kill) the container")
}

func runStop(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Check podman is available
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create container manager
	mgr := container.New(cfg)

	// Check if container exists
	exists, _ := mgr.Exists(ctx)
	if !exists {
		fmt.Printf("Container %s does not exist\n", cfg.ContainerName())
		return nil
	}

	// Check if running
	running, _ := mgr.IsRunning(ctx)
	if running {
		fmt.Printf("Stopping container %s...\n", cfg.ContainerName())
		if err := mgr.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
		fmt.Println("Container stopped")
	} else {
		fmt.Printf("Container %s is not running\n", cfg.ContainerName())
	}

	// Remove if requested
	remove, _ := cmd.Flags().GetBool("remove")
	if remove {
		fmt.Println("Removing container...")
		if err := mgr.Remove(ctx); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
		fmt.Println("Container removed")
	}

	return nil
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "ps"},
	Short:   "List devkit containers",
	Long: `List all devkit-managed containers.

Shows container ID, name, image, and status.

Examples:
  devkit list     # List all devkit containers
  devkit ls       # Alias for list
  devkit ps       # Another alias for list`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().BoolP("all", "a", true, "Show all containers (default)")
	listCmd.Flags().Bool("quiet", false, "Only show container IDs")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Check podman is available
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	// Use a minimal config just for listing
	cfg := config.DefaultConfig()
	mgr := container.New(cfg)

	containers, err := mgr.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		fmt.Println("No devkit containers found")
		fmt.Println("\nRun 'devkit init' and 'devkit start' to create a container")
		return nil
	}

	quiet, _ := cmd.Flags().GetBool("quiet")
	if quiet {
		for _, c := range containers {
			fmt.Println(c.ID)
		}
		return nil
	}

	// Print header
	fmt.Printf("%-12s  %-25s  %-30s  %-10s\n", "CONTAINER ID", "NAME", "IMAGE", "STATUS")

	// Print containers
	for _, c := range containers {
		fmt.Printf("%-12s  %-25s  %-30s  %-10s\n", c.ID, c.Name, truncate(c.Image, 30), c.Status)
	}

	return nil
}

// truncate truncates a string to the given length
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Open a shell in the container",
	Long: `Open an interactive shell in the running development container.

Examples:
  devkit shell         # Open bash shell
  devkit shell -- zsh  # Open zsh shell`,
	RunE: runShell,
}

func init() {
	rootCmd.AddCommand(shellCmd)
}

func runShell(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Check podman is available
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create container manager
	mgr := container.New(cfg)

	// Check if running
	running, _ := mgr.IsRunning(ctx)
	if !running {
		return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
	}

	// Determine shell command
	shellCmd := []string{"bash"}
	if len(args) > 0 {
		shellCmd = args
	}

	return mgr.ExecInteractive(ctx, shellCmd...)
}
