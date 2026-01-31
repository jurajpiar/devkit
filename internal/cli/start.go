package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/jurajpiar/devkit/internal/builder"
	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/detector"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the development container",
	Long: `Start the development container and prepare it for use.

This command will:
  1. Create the container if it doesn't exist
  2. Start the container
  3. Clone the git repository (if using git source method)
  4. Setup SSH keys for VS Code connection
  5. Install project dependencies

Examples:
  devkit start              # Start container from devkit.yaml
  devkit start --shell      # Start and open a shell
  devkit start --no-deps    # Start without installing dependencies`,
	RunE: runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().Bool("shell", false, "Open a shell after starting")
	startCmd.Flags().Bool("no-deps", false, "Skip dependency installation")
	startCmd.Flags().Bool("no-clone", false, "Skip git clone (use existing workspace)")
	startCmd.Flags().Bool("rebuild", false, "Remove existing container and create new one")
}

func runStart(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("failed to load config: %w\n\nRun 'devkit init' to create a configuration file", err)
	}

	// Create container manager
	mgr := container.New(cfg)

	// Check if container exists
	exists, _ := mgr.Exists(ctx)
	rebuild, _ := cmd.Flags().GetBool("rebuild")

	if exists && rebuild {
		fmt.Println("Removing existing container...")
		if err := mgr.Remove(ctx); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
		exists = false
	}

	// Check if already running
	if exists {
		running, _ := mgr.IsRunning(ctx)
		if running {
			fmt.Printf("Container %s is already running\n", cfg.ContainerName())
			fmt.Printf("SSH available at: localhost:%d\n", cfg.SSH.Port)

			// Open shell if requested
			shell, _ := cmd.Flags().GetBool("shell")
			if shell {
				return mgr.ExecInteractive(ctx, "bash")
			}
			return nil
		}
	}

	// Detect project settings
	var detection *detector.DetectionResult
	det := detector.New(".")
	detection, _ = det.Detect()

	// Create builder to get image name
	b := builder.New(cfg, detection)
	imageName := b.GetImageName()

	// Check if image exists
	imageExists, _ := b.ImageExists(ctx)
	if !imageExists {
		return fmt.Errorf("image %s not found\n\nRun 'devkit build' first to build the container image", imageName)
	}

	// Create container if it doesn't exist
	if !exists {
		fmt.Printf("Creating container %s...\n", cfg.ContainerName())
		_, err := mgr.Create(ctx, imageName)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}
	}

	// Start container
	fmt.Println("Starting container...")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to be ready
	fmt.Println("Waiting for container to be ready...")
	time.Sleep(2 * time.Second)

	// Setup SSH keys
	fmt.Println("Setting up SSH keys...")
	if err := mgr.SetupSSHKey(ctx); err != nil {
		fmt.Printf("Warning: failed to setup SSH key: %v\n", err)
		fmt.Println("You may need to manually add your SSH key to the container")
	}

	// Clone repository
	noClone, _ := cmd.Flags().GetBool("no-clone")
	if cfg.Source.Method == "git" && cfg.Source.Repo != "" && !noClone {
		fmt.Printf("Cloning repository %s...\n", cfg.Source.Repo)
		if err := mgr.CloneRepo(ctx); err != nil {
			fmt.Printf("Warning: failed to clone repository: %v\n", err)
		}
	}

	// Install dependencies
	noDeps, _ := cmd.Flags().GetBool("no-deps")
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		fmt.Printf("Installing dependencies (%s)...\n", detection.InstallCommand)
		if err := mgr.InstallDependencies(ctx, detection.InstallCommand); err != nil {
			fmt.Printf("Warning: failed to install dependencies: %v\n", err)
		}
	}

	fmt.Println("\nContainer started successfully!")
	fmt.Printf("\nSSH connection available at: localhost:%d\n", cfg.SSH.Port)
	fmt.Println("\nConnect with VS Code:")
	fmt.Printf("  1. Install 'Remote - SSH' extension\n")
	fmt.Printf("  2. Connect to: ssh -p %d developer@localhost\n", cfg.SSH.Port)
	fmt.Println("\nOr run 'devkit connect' for detailed instructions")

	// Open shell if requested
	shell, _ := cmd.Flags().GetBool("shell")
	if shell {
		fmt.Println("\nOpening shell...")
		return mgr.ExecInteractive(ctx, "bash")
	}

	return nil
}
