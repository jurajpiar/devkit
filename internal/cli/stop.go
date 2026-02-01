package cli

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/machine"
	"github.com/jurajpiar/devkit/internal/runtime"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the development container",
	Long: `Stop the running development container.

By default, the container is only stopped and can be restarted with 'devkit start'.
Use --remove to also remove the container.
Use --stop-machine to also stop the dedicated Podman machine (if total_isolation enabled).

Examples:
  devkit stop                  # Stop the container
  devkit stop --remove         # Stop and remove the container
  devkit stop --stop-machine   # Also stop the dedicated machine`,
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)

	stopCmd.Flags().Bool("remove", false, "Also remove the container after stopping")
	stopCmd.Flags().Bool("stop-machine", false, "Also stop the dedicated Podman machine (if total_isolation enabled)")
	stopCmd.Flags().BoolP("force", "f", false, "Force stop (kill) the container")
}

func runStop(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	containerName := cfg.ContainerName()
	remove, _ := cmd.Flags().GetBool("remove")

	// Handle Lima backend
	if cfg.IsLimaBackend() {
		return runStopLima(ctx, cfg, containerName, remove, cmd)
	}

	// Handle Podman backend
	return runStopPodman(ctx, cfg, containerName, remove, cmd)
}

func runStopLima(ctx context.Context, cfg *config.Config, containerName string, remove bool, cmd *cobra.Command) error {
	rc, err := SetupRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to setup runtime: %w", err)
	}

	// Check if container exists
	info, err := rc.Runtime.GetInfo(ctx, containerName)
	if err != nil {
		if _, ok := err.(runtime.ErrContainerNotFound); ok {
			fmt.Printf("Container %s does not exist\n", containerName)
			return nil
		}
		return fmt.Errorf("failed to check container: %w", err)
	}

	// Check if running
	running := info.Status == "running" || info.Status == "Up"
	if running {
		fmt.Printf("Stopping container %s...\n", containerName)
		if err := rc.Runtime.Stop(ctx, containerName); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
		fmt.Println("Container stopped")
	} else {
		fmt.Printf("Container %s is not running\n", containerName)
	}

	// Remove if requested
	if remove {
		fmt.Println("Removing container...")
		if err := rc.Runtime.Remove(ctx, containerName); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
		fmt.Println("Container removed")
	}

	// Stop VM if requested
	stopMachine, _ := cmd.Flags().GetBool("stop-machine")
	if stopMachine && rc.VMManager != nil {
		vmName := cfg.VMName()
		running, _ := rc.VMManager.IsRunning(ctx, vmName)
		if running {
			fmt.Printf("Stopping Lima VM '%s'...\n", vmName)
			if err := rc.VMManager.Stop(ctx, vmName); err != nil {
				fmt.Printf("Warning: failed to stop VM: %v\n", err)
			} else {
				fmt.Printf("Lima VM '%s' stopped\n", vmName)
			}
		}
	}

	return nil
}

func runStopPodman(ctx context.Context, cfg *config.Config, containerName string, remove bool, cmd *cobra.Command) error {
	// Check podman is available
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	// Create container manager
	mgr := container.New(cfg)

	// Check if container exists
	exists, _ := mgr.Exists(ctx)
	if !exists {
		fmt.Printf("Container %s does not exist\n", containerName)
		return nil
	}

	// Also handle proxy container
	proxyMgr := container.NewProxyManager(cfg)
	if proxyMgr.ProxyIsRunning(ctx) {
		fmt.Println("Stopping debug proxy...")
		proxyMgr.StopProxyContainer(ctx)
	}

	// Check if running
	running, _ := mgr.IsRunning(ctx)
	if running {
		fmt.Printf("Stopping container %s...\n", containerName)
		if err := mgr.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
		fmt.Println("Container stopped")
	} else {
		fmt.Printf("Container %s is not running\n", containerName)
	}

	// Remove if requested
	if remove {
		// Remove proxy resources
		if proxyMgr.ProxyExists(ctx) {
			fmt.Println("Removing debug proxy...")
			proxyMgr.RemoveProxyContainer(ctx)
			proxyMgr.RemoveNetwork(ctx)
		}

		fmt.Println("Removing container...")
		if err := mgr.Remove(ctx); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}

		fmt.Println("Removing volumes...")
		if err := mgr.RemoveVolumes(ctx); err != nil {
			return fmt.Errorf("failed to remove volumes: %w", err)
		}

		fmt.Println("Container and volumes removed")
	}

	// Stop dedicated machine if requested and total_isolation is enabled
	stopMachine, _ := cmd.Flags().GetBool("stop-machine")
	if stopMachine && cfg.Security.TotalIsolation {
		machineName := cfg.DedicatedMachineName()
		machineMgr := machine.New()

		running, _ := machineMgr.IsRunningNamed(ctx, machineName)
		if running {
			fmt.Printf("Stopping dedicated Podman machine '%s'...\n", machineName)
			if err := machineMgr.StopNamed(ctx, machineName); err != nil {
				fmt.Printf("Warning: failed to stop machine: %v\n", err)
			} else {
				fmt.Printf("Dedicated machine '%s' stopped\n", machineName)
			}
		}
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

	// Try to load config to determine backend
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		// Fall back to default config if no config file
		cfg = config.DefaultConfig()
	}

	quiet, _ := cmd.Flags().GetBool("quiet")

	// Handle Lima backend
	if cfg.IsLimaBackend() {
		rc, err := SetupRuntime(ctx, cfg)
		if err != nil {
			return fmt.Errorf("failed to setup runtime: %w", err)
		}

		containers, err := rc.Runtime.List(ctx)
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		if len(containers) == 0 {
			fmt.Println("No devkit containers found")
			fmt.Println("\nRun 'devkit init' and 'devkit start' to create a container")
			return nil
		}

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
			fmt.Printf("%-12s  %-25s  %-30s  %-10s\n", truncate(c.ID, 12), c.Name, truncate(c.Image, 30), c.Status)
		}

		return nil
	}

	// Handle Podman backend
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

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

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	containerName := cfg.ContainerName()

	// Determine shell command
	shellCmd := []string{"bash"}
	if len(args) > 0 {
		shellCmd = args
	}

	// Handle Lima backend
	if cfg.IsLimaBackend() {
		rc, err := SetupRuntime(ctx, cfg)
		if err != nil {
			return fmt.Errorf("failed to setup runtime: %w", err)
		}

		// Check if running
		info, err := rc.Runtime.GetInfo(ctx, containerName)
		if err != nil {
			if _, ok := err.(runtime.ErrContainerNotFound); ok {
				return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
			}
			return fmt.Errorf("failed to check container: %w", err)
		}

		running := info.Status == "running" || info.Status == "Up"
		if !running {
			return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
		}

		return rc.Runtime.ExecInteractive(ctx, containerName, shellCmd...)
	}

	// Handle Podman backend
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	mgr := container.New(cfg)

	// Check if running
	running, _ := mgr.IsRunning(ctx)
	if !running {
		return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
	}

	return mgr.ExecInteractive(ctx, shellCmd...)
}
