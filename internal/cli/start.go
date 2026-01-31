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

Security Modes:
  --paranoid      Maximum security for untrusted code:
                  - Network enabled only during clone/install
                  - Automatically air-gaps after setup
                  - Uses debug proxy with strict filtering
                  - Stricter resource limits

  --debug-proxy   Route debug traffic through filtering proxy:
                  - Blocks dangerous CDP commands (eval, compile)
                  - Rate-limits code execution
                  - Audit logs all debug activity

Examples:
  devkit start                  # Start container from devkit.yaml
  devkit start --shell          # Start and open a shell
  devkit start --paranoid       # Maximum security for untrusted code
  devkit start --debug-proxy    # Enable debug proxy filtering
  devkit start --offline        # Start with no network access`,
	RunE: runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().Bool("shell", false, "Open a shell after starting")
	startCmd.Flags().Bool("no-deps", false, "Skip dependency installation")
	startCmd.Flags().Bool("no-clone", false, "Skip git clone (use existing workspace)")
	startCmd.Flags().Bool("rebuild", false, "Remove existing container and create new one")

	// Security flags
	startCmd.Flags().Bool("paranoid", false, "Maximum security: air-gap after setup, strict debug proxy")
	startCmd.Flags().Bool("offline", false, "Start with no network access (network_mode=none)")
	startCmd.Flags().Bool("no-debug-port", false, "Disable debug port exposure entirely")
	startCmd.Flags().Bool("debug-proxy", false, "Route debug traffic through filtering proxy")
	startCmd.Flags().String("proxy-filter", "filtered", "Debug proxy filter level: strict, filtered, audit")
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

	// Parse security flags
	paranoid, _ := cmd.Flags().GetBool("paranoid")
	offline, _ := cmd.Flags().GetBool("offline")
	noDebugPort, _ := cmd.Flags().GetBool("no-debug-port")
	useDebugProxy, _ := cmd.Flags().GetBool("debug-proxy")
	proxyFilterLevel, _ := cmd.Flags().GetString("proxy-filter")

	// Apply paranoid mode settings
	if paranoid {
		fmt.Println("=== PARANOID MODE ENABLED ===")
		fmt.Println("- Network will be disabled after setup")
		fmt.Println("- Debug proxy with STRICT filtering enabled")
		fmt.Println("- Stricter resource limits applied")
		fmt.Println()

		useDebugProxy = true
		proxyFilterLevel = "strict"
		cfg.Security.MemoryLimit = "2g"    // Stricter limit
		cfg.Security.PidsLimit = 256       // Stricter limit
	}

	// Apply offline mode
	if offline {
		cfg.Security.NetworkMode = "none"
	}

	// Apply debug port setting
	if noDebugPort {
		cfg.Security.DisableDebugPort = true
		useDebugProxy = false // Can't use proxy if port is disabled
	}

	// Apply debug proxy settings
	if useDebugProxy {
		cfg.Security.UseDebugProxy = true
		cfg.Security.DebugProxyFilterLevel = proxyFilterLevel
		cfg.Security.DisableDebugPort = false // Need port for proxy
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

	// For paranoid mode, we need a two-phase startup:
	// Phase 1: Network enabled for clone/install
	// Phase 2: Recreate container with network disabled
	needsNetworkSetup := paranoid && !offline && cfg.Source.Method == "git"

	if needsNetworkSetup {
		// Phase 1: Create with restricted network for setup
		fmt.Println("[Phase 1/2] Starting with network for initial setup...")
		cfg.Security.NetworkMode = "restricted"
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

	// Fix node_modules permissions for mount method
	if cfg.Source.Method == "mount" {
		if cfg.Features.AllowWritableMount {
			fmt.Println("WARNING: Writable mount enabled - container can modify your source files!")
		}
		mgr.FixNodeModulesPermissions(ctx)
	}

	// Install dependencies
	noDeps, _ := cmd.Flags().GetBool("no-deps")
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		fmt.Printf("Installing dependencies (%s)...\n", detection.InstallCommand)
		if err := mgr.InstallDependencies(ctx, detection.InstallCommand); err != nil {
			fmt.Printf("Warning: failed to install dependencies: %v\n", err)
		}
	}

	// Phase 2: For paranoid mode, recreate container with network disabled
	if needsNetworkSetup {
		fmt.Println("\n[Phase 2/2] Air-gapping container (disabling network)...")

		// Stop current container
		if err := mgr.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop container for air-gap: %w", err)
		}

		// Commit the container state to preserve installed deps
		fmt.Println("Saving container state...")
		committedImage, err := mgr.Commit(ctx, cfg.ImageName()+"-airgapped")
		if err != nil {
			return fmt.Errorf("failed to save container state: %w", err)
		}

		// Remove old container
		if err := mgr.Remove(ctx); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}

		// Recreate with network disabled
		cfg.Security.NetworkMode = "none"
		mgr = container.New(cfg)

		fmt.Println("Creating air-gapped container...")
		_, err = mgr.Create(ctx, committedImage)
		if err != nil {
			return fmt.Errorf("failed to create air-gapped container: %w", err)
		}

		// Start the air-gapped container
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("failed to start air-gapped container: %w", err)
		}

		// Re-setup SSH keys in the new container
		time.Sleep(2 * time.Second)
		if err := mgr.SetupSSHKey(ctx); err != nil {
			fmt.Printf("Warning: failed to setup SSH key: %v\n", err)
		}

		fmt.Println("\n=== CONTAINER IS NOW AIR-GAPPED ===")
		fmt.Println("Network access is completely disabled.")
		fmt.Println("No data can be exfiltrated from this container.")
	}

	// Setup debug proxy if enabled
	if useDebugProxy && !noDebugPort {
		fmt.Println("\nSetting up debug proxy...")
		proxyMgr := container.NewProxyManager(cfg)

		// Check if proxy image exists
		if !proxyMgr.ProxyImageExists(ctx) {
			fmt.Println("Debug proxy image not found.")
			fmt.Println("Build it with: devkit build --proxy")
			fmt.Println("Continuing without proxy...")
			useDebugProxy = false
		} else {
			// Create network and connect dev container
			if err := proxyMgr.CreateNetwork(ctx); err != nil {
				fmt.Printf("Warning: failed to create proxy network: %v\n", err)
				useDebugProxy = false
			} else {
				// Connect dev container to internal network
				if err := proxyMgr.ConnectContainerToNetwork(ctx, cfg.ContainerName()); err != nil {
					fmt.Printf("Warning: failed to connect container to network: %v\n", err)
					useDebugProxy = false
				} else {
					// Remove existing proxy if any
					proxyMgr.StopProxyContainer(ctx)
					proxyMgr.RemoveProxyContainer(ctx)

					// Create and start proxy
					if err := proxyMgr.CreateProxyContainer(ctx, "devkit/debugproxy:latest", cfg.ContainerName(), proxyFilterLevel); err != nil {
						fmt.Printf("Warning: failed to create proxy container: %v\n", err)
						useDebugProxy = false
					} else {
						if err := proxyMgr.StartProxyContainer(ctx); err != nil {
							fmt.Printf("Warning: failed to start proxy container: %v\n", err)
							useDebugProxy = false
						} else {
							fmt.Printf("Debug proxy started (filter level: %s)\n", proxyFilterLevel)
						}
					}
				}
			}
		}
	}

	fmt.Println("\nContainer started successfully!")
	fmt.Printf("\nSSH connection available at: localhost:%d\n", cfg.SSH.Port)

	if cfg.Security.NetworkMode == "none" {
		fmt.Println("\nSECURITY: Network is DISABLED (air-gapped mode)")
	}
	if noDebugPort || cfg.Security.DisableDebugPort {
		fmt.Println("SECURITY: Debug port is DISABLED")
	}
	if useDebugProxy {
		fmt.Println("SECURITY: Debug traffic routed through filtering proxy")
		fmt.Printf("          Filter level: %s\n", proxyFilterLevel)
		fmt.Println("          Audit log: podman logs " + cfg.ContainerName() + "-debugproxy")
	}

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
