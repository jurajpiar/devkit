package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/builder"
	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/detector"
	"github.com/jurajpiar/devkit/internal/machine"
	"github.com/jurajpiar/devkit/internal/runtime"
	limaRuntime "github.com/jurajpiar/devkit/internal/runtime/lima"
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
  --total-isolation, -ti
                  Hypervisor-level isolation:
                  - Runs project in a dedicated Podman machine (VM)
                  - Container escape is still confined to dedicated VM
                  - No shared kernel between projects
                  - Complete network isolation from other containers

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
  devkit start                     # Start container from devkit.yaml
  devkit start --shell             # Start and open a shell
  devkit start --total-isolation   # Run in dedicated VM for max isolation
  devkit start -ti --paranoid      # Dedicated VM + paranoid mode
  devkit start --paranoid          # Maximum security for untrusted code
  devkit start --debug-proxy       # Enable debug proxy filtering
  devkit start --offline           # Start with no network access`,
	RunE: runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().Bool("shell", false, "Open a shell after starting")
	startCmd.Flags().Bool("no-deps", false, "Skip dependency installation")
	startCmd.Flags().Bool("no-clone", false, "Skip git clone (use existing workspace)")
	startCmd.Flags().Bool("rebuild", false, "Remove existing container and create new one")

	// Security flags
	startCmd.Flags().BoolP("total-isolation", "t", false, "Run in dedicated Podman machine (VM) for hypervisor-level isolation")
	startCmd.Flags().Bool("paranoid", false, "Maximum security: air-gap after setup, strict debug proxy")
	startCmd.Flags().Bool("offline", false, "Start with no network access (network_mode=none)")
	startCmd.Flags().Bool("no-debug-port", false, "Disable debug port exposure entirely")
	startCmd.Flags().Bool("debug-proxy", false, "Route debug traffic through filtering proxy")
	startCmd.Flags().String("proxy-filter", "filtered", "Debug proxy filter level: strict, filtered, audit")
}

func runStart(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

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
	totalIsolation, _ := cmd.Flags().GetBool("total-isolation")
	paranoid, _ := cmd.Flags().GetBool("paranoid")
	offline, _ := cmd.Flags().GetBool("offline")
	noDebugPort, _ := cmd.Flags().GetBool("no-debug-port")
	useDebugProxy, _ := cmd.Flags().GetBool("debug-proxy")
	proxyFilterLevel, _ := cmd.Flags().GetString("proxy-filter")

	// Apply total isolation from flag or config
	if totalIsolation {
		cfg.Security.TotalIsolation = true
	}

	// Setup runtime based on configuration
	rc, err := SetupRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to setup runtime: %w", err)
	}

	// For Lima backend, use Lima-specific start flow
	if rc.Backend == runtime.BackendLima {
		return runStartLima(ctx, cmd, cfg, rc, paranoid, offline, noDebugPort, useDebugProxy, proxyFilterLevel)
	}

	// For Podman backend with total isolation, the SetupRuntime already handled VM setup
	// For Podman backend without total isolation on macOS/Windows, ensure a machine is running
	if !cfg.Security.TotalIsolation && (goruntime.GOOS == "darwin" || goruntime.GOOS == "windows") {
		machineMgr := machine.New()
		running, name, _ := machineMgr.GetRunningMachine(ctx)
		if !running {
			fmt.Println("No Podman machine is running. Starting default machine...")
			if err := machineMgr.EnsureRunning(ctx); err != nil {
				return fmt.Errorf("failed to start Podman machine: %w\n\nTry: podman machine start", err)
			}
			fmt.Println()
		} else {
			// Ensure we're using the running machine as default
			machineMgr.SetDefaultNamed(ctx, name)
		}
	}

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

	// Calculate total steps for progress
	totalSteps := 6 // create, start, ssh, permissions, ready
	noDeps, _ := cmd.Flags().GetBool("no-deps")
	noClone, _ := cmd.Flags().GetBool("no-clone")
	if cfg.Source.Method == "git" && cfg.Source.Repo != "" && !noClone {
		totalSteps++ // clone
	} else if cfg.Source.Method == "copy" {
		totalSteps++ // copy
	}
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		totalSteps++ // install deps
	}

	progress := NewProgress(totalSteps)

	if needsNetworkSetup {
		progress.SetPrefix("[Phase 1/2] ")
		cfg.Security.NetworkMode = "restricted"
	}

	// Create container if it doesn't exist
	if !exists {
		progress.Step(fmt.Sprintf("Creating container %s", cfg.ContainerName()))
		_, err := mgr.Create(ctx, imageName)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}
	} else {
		progress.Step("Using existing container")
	}

	// Start container
	progress.Step("Starting container")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to be ready
	progress.Step("Waiting for container to be ready")
	time.Sleep(2 * time.Second)

	// Setup SSH keys
	progress.Step("Setting up SSH keys")
	if err := mgr.SetupSSHKey(ctx); err != nil {
		progress.Warn(fmt.Sprintf("Failed to setup SSH key: %v", err))
	}

	// Clone repository (git method) or copy files (copy method)
	if cfg.Source.Method == "git" && cfg.Source.Repo != "" && !noClone {
		progress.Step(fmt.Sprintf("Cloning repository %s", cfg.Source.Repo))
		if err := mgr.CloneRepo(ctx); err != nil {
			progress.Warn(fmt.Sprintf("Failed to clone: %v", err))
		}
	} else if cfg.Source.Method == "copy" {
		progress.Step("Copying source files to container")
		if len(cfg.CopyExclude) > 0 {
			progress.SubStep(fmt.Sprintf("Excluding: %v", cfg.CopyExclude))
		}

		// Progress display for file copying
		var fileCount int

		onFile := func(filename string) {
			fileCount++
			// Strip leading ./
			name := strings.TrimPrefix(filename, "./")
			
			// Truncate long filenames
			if len(name) > 50 {
				name = "..." + name[len(name)-47:]
			}
			
			// Update progress every 50 files to avoid slowdown
			if fileCount%50 == 0 || fileCount < 10 {
				fmt.Printf("\r         [%d] %s\033[K", fileCount, name)
			}
		}

		if err := mgr.CopySourceToContainerWithProgress(ctx, onFile); err != nil {
			fmt.Println() // Ensure we're on a new line after error
			return fmt.Errorf("failed to copy source files: %w", err)
		}

		// Clear the progress line and show completion
		fmt.Print("\r\033[K")
		progress.Success(fmt.Sprintf("Copied %d files to container", fileCount))

		// Fix ownership of specific paths
		if len(cfg.ChownPaths) > 0 {
			mgr.FixChownPaths(ctx)
		}
	}

	// Fix node_modules permissions for mount method
	if cfg.Source.Method == "mount" {
		if cfg.Features.AllowWritableMount {
			progress.Warn("Writable mount enabled - container can modify your source files!")
		}
		mgr.FixNodeModulesPermissions(ctx)
	}

	// Fix volume permissions (volumes are created with root ownership)
	progress.Step("Fixing volume permissions")
	mgr.FixExtraVolumePermissions(ctx)
	mgr.FixIDEServerPermissions(ctx)

	// Start port forwarders (disabled - use devkit forward instead)
	if len(cfg.Ports) > 0 {
		mgr.StartPortForwarders(ctx)
	}

	// Install dependencies
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		progress.Step(fmt.Sprintf("Installing dependencies (%s)", detection.InstallCommand))
		fmt.Println() // Empty line before output
		if err := mgr.InstallDependenciesWithOutput(ctx, detection.InstallCommand); err != nil {
			progress.Warn(fmt.Sprintf("Failed to install dependencies: %v", err))
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

	progress.Done("Container started successfully!")

	fmt.Printf("SSH: localhost:%d\n", cfg.SSH.Port)
	if len(cfg.Ports) > 0 {
		fmt.Printf("Ports: %v\n", cfg.Ports)
	}

	if cfg.Security.NetworkMode == "none" {
		fmt.Println("\n⚠ SECURITY: Network is DISABLED (air-gapped mode)")
	}
	if noDebugPort || cfg.Security.DisableDebugPort {
		fmt.Println("⚠ SECURITY: Debug port is DISABLED")
	}
	if useDebugProxy {
		fmt.Println("⚠ SECURITY: Debug traffic routed through filtering proxy")
		fmt.Printf("            Filter level: %s\n", proxyFilterLevel)
	}

	fmt.Println("\nNext steps:")
	fmt.Printf("  • Connect IDE: ssh -p %d developer@localhost\n", cfg.SSH.Port)
	fmt.Println("  • Open shell:  devkit shell")
	fmt.Println("  • View stats:  devkit stats")
	fmt.Println("  • Monitor:     devkit monitor start")
	fmt.Println("  • More info:   devkit connect")

	// Open shell if requested
	shell, _ := cmd.Flags().GetBool("shell")
	if shell {
		fmt.Println("\nOpening shell...")
		return mgr.ExecInteractive(ctx, "bash")
	}

	return nil
}

// runStartLima handles starting with Lima runtime
func runStartLima(ctx context.Context, cmd *cobra.Command, cfg *config.Config, rc *RuntimeContext,
	paranoid, offline, noDebugPort, useDebugProxy bool, proxyFilterLevel string) error {

	// Determine if we need two-phase network setup:
	// - paranoid flag is set, OR
	// - config has network_mode: none (from TUI paranoid selection)
	// AND we're not starting in offline mode (which skips setup)
	needsTwoPhaseSetup := (paranoid || cfg.Security.NetworkMode == "none") && !offline

	// Apply paranoid mode settings
	if paranoid {
		fmt.Println("=== PARANOID MODE ENABLED ===")
		fmt.Println("- Network will be disabled after setup")
		fmt.Println("- Debug proxy with STRICT filtering enabled")
		fmt.Println("- Stricter resource limits applied")
		fmt.Println()

		useDebugProxy = true
		proxyFilterLevel = "strict"
		cfg.Security.MemoryLimit = "2g"
		cfg.Security.PidsLimit = 256
	}

	// Apply offline mode
	if offline {
		cfg.Security.NetworkMode = "none"
	}

	// For two-phase setup, temporarily enable network for Phase 1
	originalNetworkMode := cfg.Security.NetworkMode
	if needsTwoPhaseSetup {
		cfg.Security.NetworkMode = "restricted"
	}

	// Apply debug port setting
	if noDebugPort {
		cfg.Security.DisableDebugPort = true
		useDebugProxy = false
	}

	// Apply debug proxy settings
	if useDebugProxy {
		cfg.Security.UseDebugProxy = true
		cfg.Security.DebugProxyFilterLevel = proxyFilterLevel
		cfg.Security.DisableDebugPort = false
	}

	containerName := cfg.ContainerName()

	// Check if container exists
	exists, _ := rc.Runtime.Exists(ctx, containerName)
	rebuild, _ := cmd.Flags().GetBool("rebuild")

	if exists && rebuild {
		fmt.Println("Removing existing container...")
		if err := rc.Runtime.Remove(ctx, containerName); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
		exists = false
	}

	// Check if already running
	if exists {
		running, _ := rc.Runtime.IsRunning(ctx, containerName)
		if running {
			fmt.Printf("Container %s is already running\n", containerName)
			fmt.Printf("SSH available at: localhost:%d\n", cfg.SSH.Port)

			shell, _ := cmd.Flags().GetBool("shell")
			if shell {
				return rc.Runtime.ExecInteractive(ctx, containerName, "bash")
			}
			return nil
		}
	}

	// Detect project settings
	var detection *detector.DetectionResult
	det := detector.New(".")
	detection, _ = det.Detect()

	// Get image name
	b := builder.New(cfg, detection)
	imageName := b.GetImageName()

	// Check if image exists
	imageExists, _ := rc.Runtime.ImageExists(ctx, imageName)
	if !imageExists {
		return fmt.Errorf("image %s not found\n\nRun 'devkit build' first to build the container image", imageName)
	}

	// Calculate total steps
	totalSteps := 6
	noDeps, _ := cmd.Flags().GetBool("no-deps")
	noClone, _ := cmd.Flags().GetBool("no-clone")
	if cfg.Source.Method == "git" && cfg.Source.Repo != "" && !noClone {
		totalSteps++
	} else if cfg.Source.Method == "copy" {
		totalSteps++
	}
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		totalSteps++
	}

	progress := NewProgress(totalSteps)

	// Set phase prefix for two-phase setup
	if needsTwoPhaseSetup {
		progress.SetPrefix("[Phase 1/2] ")
	}

	// Build CreateOpts for Lima
	createOpts := runtime.CreateOpts{
		Name:     containerName,
		Image:    imageName,
		Hostname: "devkit",
		Env: map[string]string{
			"GIT_REPO":   cfg.Source.Repo,
			"GIT_BRANCH": cfg.Source.Branch,
		},
	}

	// Security settings
	if cfg.Security.DropAllCapabilities {
		createOpts.CapDrop = []string{"ALL"}
		createOpts.CapAdd = []string{"SYS_CHROOT", "SETUID", "SETGID", "CHOWN", "FOWNER"}
	}
	if cfg.Security.NoNewPrivileges {
		createOpts.SecurityOpts = append(createOpts.SecurityOpts, "no-new-privileges:true")
	}
	if cfg.Security.ReadOnlyRootfs {
		createOpts.ReadOnly = true
	}
	createOpts.Tmpfs = []runtime.TmpfsMount{
		{Target: "/tmp", Options: "rw,nosuid,size=512m"},
		{Target: "/run", Options: "rw,noexec,nosuid,size=64m"},
	}

	// SSH port
	createOpts.Ports = []runtime.PortMapping{
		{HostIP: "127.0.0.1", HostPort: cfg.SSH.Port, ContainerPort: 2222},
	}

	// Debug port
	if cfg.Project.Type == "nodejs" && !cfg.Security.DisableDebugPort {
		createOpts.Ports = append(createOpts.Ports, runtime.PortMapping{
			HostIP: "127.0.0.1", HostPort: 9229, ContainerPort: 9229,
		})
	}

	// Application ports
	for _, port := range cfg.Ports {
		createOpts.Ports = append(createOpts.Ports, runtime.PortMapping{
			HostIP: "127.0.0.1", HostPort: port, ContainerPort: port,
		})
	}

	// Network mode
	switch cfg.Security.NetworkMode {
	case "none":
		createOpts.NetworkMode = "none"
	case "restricted":
		createOpts.NetworkMode = "bridge"
	case "full":
		createOpts.NetworkMode = "bridge"
	}

	// Resource limits
	if cfg.Security.MemoryLimit != "" {
		createOpts.Memory = cfg.Security.MemoryLimit
	}
	if cfg.Security.PidsLimit > 0 {
		createOpts.PidsLimit = cfg.Security.PidsLimit
	}

	// Volumes
	createOpts.Volumes = []runtime.VolumeMount{
		{Source: containerName + "-ssh", Target: "/home/developer/.ssh", Type: "volume"},
		{Source: containerName + "-workspace", Target: "/home/developer/workspace", Type: "volume"},
	}

	for _, extraVol := range cfg.ExtraVolumes {
		volName := strings.TrimPrefix(extraVol, ".")
		createOpts.Volumes = append(createOpts.Volumes, runtime.VolumeMount{
			Source: containerName + "-" + volName,
			Target: "/home/developer/" + extraVol,
			Type:   "volume",
		})
	}

	for _, ideServer := range cfg.IDEServers {
		volName := strings.TrimPrefix(ideServer, ".")
		createOpts.Volumes = append(createOpts.Volumes, runtime.VolumeMount{
			Source: containerName + "-" + volName,
			Target: "/home/developer/" + ideServer,
			Type:   "volume",
		})
	}

	// Create container if it doesn't exist
	if !exists {
		progress.Step(fmt.Sprintf("Creating container %s", containerName))
		_, err := rc.Runtime.Create(ctx, createOpts)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}
	} else {
		progress.Step("Using existing container")
	}

	// Start container
	progress.Step("Starting container")
	if err := rc.Runtime.Start(ctx, containerName); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to be ready
	progress.Step("Waiting for container to be ready")
	time.Sleep(2 * time.Second)

	// Setup SSH keys using runtime exec
	progress.Step("Setting up SSH keys")
	setupSSHInContainer(ctx, rc.Runtime, containerName, cfg)

	// Clone repository or copy files
	if cfg.Source.Method == "git" && cfg.Source.Repo != "" && !noClone {
		progress.Step(fmt.Sprintf("Cloning repository %s", cfg.Source.Repo))
		cloneCmd := fmt.Sprintf("git clone --branch %s %s /home/developer/workspace", cfg.Source.Branch, cfg.Source.Repo)
		_, err := rc.Runtime.ExecAsUser(ctx, containerName, "developer", "bash", "-c", cloneCmd)
		if err != nil {
			progress.Warn(fmt.Sprintf("Failed to clone: %v", err))
		}
	} else if cfg.Source.Method == "copy" {
		progress.Step("Copying source files to container")
		// Copy source files to container using Lima runtime
		if err := copySourceToContainerLima(ctx, rc, cfg, containerName); err != nil {
			return fmt.Errorf("failed to copy source files: %w", err)
		}
		progress.Success("Copied files to container")
	}

	// Fix volume permissions
	progress.Step("Fixing volume permissions")
	for _, extraVol := range cfg.ExtraVolumes {
		rc.Runtime.Exec(ctx, containerName, "chown", "-R", "developer:developer", "/home/developer/"+extraVol)
	}
	for _, ideServer := range cfg.IDEServers {
		rc.Runtime.Exec(ctx, containerName, "chown", "-R", "developer:developer", "/home/developer/"+ideServer)
	}

	// Install dependencies (with streaming output)
	if !noDeps && detection != nil && detection.InstallCommand != "" {
		progress.Step(fmt.Sprintf("Installing dependencies (%s)", detection.InstallCommand))
		fmt.Println()
		installCmd := fmt.Sprintf("cd /home/developer/workspace && %s", detection.InstallCommand)
		// Use streaming exec if available
		if limaRT, ok := rc.Runtime.(*limaRuntime.Runtime); ok {
			err := limaRT.ExecAsUserWithOutput(ctx, containerName, "developer", "bash", "-c", installCmd)
			if err != nil {
				progress.Warn(fmt.Sprintf("Failed to install dependencies: %v", err))
			}
		} else {
			_, err := rc.Runtime.ExecAsUser(ctx, containerName, "developer", "bash", "-c", installCmd)
			if err != nil {
				progress.Warn(fmt.Sprintf("Failed to install dependencies: %v", err))
			}
		}
	}

	// Phase 2: Air-gap the container (disable network)
	if needsTwoPhaseSetup {
		fmt.Println("\n[Phase 2/2] Air-gapping container (disabling network)...")

		// Stop current container
		if err := rc.Runtime.Stop(ctx, containerName); err != nil {
			return fmt.Errorf("failed to stop container for air-gap: %w", err)
		}

		// Commit the container state to preserve installed deps
		// Use a proper image name format that nerdctl can reference
		airgappedImageName := cfg.ImageName() + "-airgapped"
		fmt.Printf("Saving container state as %s...\n", airgappedImageName)
		limaRT := rc.Runtime.(*limaRuntime.Runtime)
		_, err := limaRT.Commit(ctx, containerName, airgappedImageName)
		if err != nil {
			return fmt.Errorf("failed to save container state: %w", err)
		}

		// Remove old container
		fmt.Println("Removing network-enabled container...")
		if err := rc.Runtime.Remove(ctx, containerName); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}

		// Update network mode to none
		cfg.Security.NetworkMode = originalNetworkMode
		if cfg.Security.NetworkMode != "none" {
			cfg.Security.NetworkMode = "none"
		}

		// Update createOpts for air-gapped container
		createOpts.NetworkMode = "none"
		createOpts.Image = airgappedImageName

		fmt.Println("Creating air-gapped container...")
		_, err = rc.Runtime.Create(ctx, createOpts)
		if err != nil {
			return fmt.Errorf("failed to create air-gapped container: %w", err)
		}

		// Start the air-gapped container
		if err := rc.Runtime.Start(ctx, containerName); err != nil {
			return fmt.Errorf("failed to start air-gapped container: %w", err)
		}

		// Re-setup SSH keys in the new container
		time.Sleep(2 * time.Second)
		setupSSHInContainer(ctx, rc.Runtime, containerName, cfg)

		fmt.Println("\n=== CONTAINER IS NOW AIR-GAPPED ===")
		fmt.Println("Network access is completely disabled.")
		fmt.Println("To re-enable network, recreate the container:")
		fmt.Println("  devkit start --rebuild")
	}

	progress.Done("Container started successfully!")

	fmt.Printf("SSH: localhost:%d\n", cfg.SSH.Port)
	if len(cfg.Ports) > 0 {
		fmt.Printf("Ports: %v\n", cfg.Ports)
	}

	if cfg.Security.NetworkMode == "none" {
		fmt.Println("\n⚠ SECURITY: Network is DISABLED (air-gapped mode)")
	}

	fmt.Println("\nNext steps:")
	fmt.Printf("  • Connect IDE: ssh -p %d developer@localhost\n", cfg.SSH.Port)
	fmt.Println("  • Open shell:  devkit shell")
	fmt.Println("  • View stats:  devkit stats")

	// Open shell if requested
	shell, _ := cmd.Flags().GetBool("shell")
	if shell {
		fmt.Println("\nOpening shell...")
		return rc.Runtime.ExecInteractive(ctx, containerName, "bash")
	}

	return nil
}

// copySourceToContainerLima copies source files to container using Lima runtime
func copySourceToContainerLima(ctx context.Context, rc *RuntimeContext, cfg *config.Config, containerName string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Create a temporary tarball (excluding configured paths)
	tmpFile, err := os.CreateTemp("", "devkit-source-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Build tar command with exclusions
	tarArgs := []string{"-cf", tmpPath}
	for _, exclude := range cfg.CopyExclude {
		tarArgs = append(tarArgs, "--exclude="+exclude)
	}
	tarArgs = append(tarArgs, ".")

	// Create tarball
	tarCmd := exec.CommandContext(ctx, "tar", tarArgs...)
	tarCmd.Dir = cwd
	tarCmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1") // Disable macOS metadata

	if err := tarCmd.Run(); err != nil {
		return fmt.Errorf("failed to create tarball: %w", err)
	}

	// Copy tarball to container
	if err := rc.Runtime.CopyTo(ctx, containerName, tmpPath, "/tmp/source.tar"); err != nil {
		return fmt.Errorf("failed to copy tarball to container: %w", err)
	}

	// Fix tarball ownership and extract as developer user
	rc.Runtime.Exec(ctx, containerName, "chown", "developer:developer", "/tmp/source.tar")
	_, err = rc.Runtime.ExecAsUser(ctx, containerName, "developer", "tar", "-xf", "/tmp/source.tar", "-C", "/home/developer/workspace/")
	if err != nil {
		return fmt.Errorf("failed to extract tarball: %w", err)
	}

	// Clean up and fix ownership
	rc.Runtime.Exec(ctx, containerName, "rm", "-f", "/tmp/source.tar")
	rc.Runtime.Exec(ctx, containerName, "chown", "-R", "developer:developer", "/home/developer/workspace")

	return nil
}

// setupSSHInContainer sets up SSH keys inside the container
func setupSSHInContainer(ctx context.Context, rt runtime.Runtime, containerName string, cfg *config.Config) error {
	// Read user's public SSH key
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	// Try common SSH key locations
	keyPaths := []string{
		homeDir + "/.ssh/id_ed25519.pub",
		homeDir + "/.ssh/id_rsa.pub",
	}

	var pubKey string
	for _, keyPath := range keyPaths {
		if data, err := os.ReadFile(keyPath); err == nil {
			pubKey = strings.TrimSpace(string(data))
			break
		}
	}

	if pubKey == "" {
		return fmt.Errorf("no SSH public key found in ~/.ssh/")
	}

	// Setup authorized_keys in container
	cmd := fmt.Sprintf(`mkdir -p /home/developer/.ssh && echo '%s' >> /home/developer/.ssh/authorized_keys && chmod 700 /home/developer/.ssh && chmod 600 /home/developer/.ssh/authorized_keys`, pubKey)
	_, err = rt.ExecAsUser(ctx, containerName, "developer", "bash", "-c", cmd)
	return err
}
