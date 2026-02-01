package cli

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm"},
	Short:   "Remove the development container and its volumes",
	Long: `Remove the development container and optionally its volumes.

This stops the container if running, removes it, and by default also
removes all associated volumes (workspace, node_modules, .vscode-server, etc.).

Use --keep-volumes to preserve volumes for later use.

Examples:
  devkit remove               # Remove container and all volumes
  devkit rm                   # Alias for remove
  devkit remove --keep-volumes # Remove container but keep volumes`,
	RunE: runRemove,
}

func init() {
	rootCmd.AddCommand(removeCmd)

	removeCmd.Flags().Bool("keep-volumes", false, "Keep volumes (don't delete workspace, node_modules, etc.)")
	removeCmd.Flags().BoolP("force", "f", false, "Force removal without confirmation")
}

func runRemove(cmd *cobra.Command, args []string) error {
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
		// Still try to clean up volumes if they exist
		keepVolumes, _ := cmd.Flags().GetBool("keep-volumes")
		if !keepVolumes {
			fmt.Println("Cleaning up any orphaned volumes...")
			mgr.RemoveVolumes(ctx)
		}
		return nil
	}

	// Stop if running
	running, _ := mgr.IsRunning(ctx)
	if running {
		fmt.Printf("Stopping container %s...\n", cfg.ContainerName())
		if err := mgr.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
	}

	// Remove proxy if it exists
	proxyMgr := container.NewProxyManager(cfg)
	if proxyMgr.ProxyExists(ctx) {
		fmt.Println("Removing debug proxy...")
		proxyMgr.StopProxyContainer(ctx)
		proxyMgr.RemoveProxyContainer(ctx)
		proxyMgr.RemoveNetwork(ctx)
	}

	// Remove container
	fmt.Printf("Removing container %s...\n", cfg.ContainerName())
	if err := mgr.Remove(ctx); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	// Remove volumes unless --keep-volumes
	keepVolumes, _ := cmd.Flags().GetBool("keep-volumes")
	if !keepVolumes {
		fmt.Println("Removing volumes...")
		if err := mgr.RemoveVolumes(ctx); err != nil {
			return fmt.Errorf("failed to remove volumes: %w", err)
		}
	} else {
		fmt.Println("Keeping volumes (use 'podman volume ls' to see them)")
	}

	fmt.Println("Container removed successfully")
	return nil
}
