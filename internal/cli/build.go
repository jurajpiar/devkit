package cli

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/builder"
	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/detector"
	"github.com/jurajpiar/devkit/internal/runtime"
	"github.com/spf13/cobra"
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build the development container image",
	Long: `Build a container image with all dependencies pre-installed.

The image includes:
  - Base runtime (e.g., Node.js)
  - SSH server for VS Code Remote connection
  - Git for repository cloning
  - Project-specific tools and global packages

Examples:
  devkit build              # Build from devkit.yaml
  devkit build --proxy      # Also build the debug proxy image
  devkit build --no-cache   # Build without cache
  devkit build --save-containerfile  # Save generated Containerfile`,
	RunE: runBuild,
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().Bool("no-cache", false, "Build without using cache")
	buildCmd.Flags().Bool("save-containerfile", false, "Save the generated Containerfile to current directory")
	buildCmd.Flags().Bool("force", false, "Force rebuild even if image exists")
	buildCmd.Flags().Bool("proxy", false, "Also build the debug proxy image")
}

func runBuild(cmd *cobra.Command, args []string) error {
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

	// Setup runtime based on configuration
	rc, err := SetupRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to setup runtime: %w", err)
	}

	// For Lima, we use a different build path
	if rc.Backend == runtime.BackendLima {
		return runBuildLima(ctx, cmd, cfg, rc)
	}

	// For Podman, continue with existing logic (uses container.CheckPodman indirectly via builder)

	fmt.Printf("Building image for project: %s\n", cfg.Project.Name)
	fmt.Printf("Project type: %s\n", cfg.Project.Type)
	fmt.Printf("Runtime: %s\n", cfg.Dependencies.Runtime)

	// Detect project settings (might override some config values)
	var detection *detector.DetectionResult
	det := detector.New(".")
	detection, _ = det.Detect()

	if detection != nil && detection.Type != detector.TypeUnknown {
		fmt.Printf("Detected package manager: %s\n", detection.PackageManager)
	}

	// Create builder
	b := builder.New(cfg, detection)

	// Check if image exists
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		exists, _ := b.ImageExists(ctx)
		if exists {
			fmt.Printf("Image %s already exists. Use --force to rebuild.\n", b.GetImageName())
			return nil
		}
	}

	// Save Containerfile if requested
	saveContainerfile, _ := cmd.Flags().GetBool("save-containerfile")
	if saveContainerfile {
		if err := b.SaveContainerfile("Containerfile"); err != nil {
			return fmt.Errorf("failed to save Containerfile: %w", err)
		}
		fmt.Println("Saved Containerfile to current directory")
	}

	// Build image
	fmt.Println("\nBuilding container image...")
	if err := b.Build(ctx); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Printf("\nSuccessfully built image: %s\n", b.GetImageName())

	// Build proxy image if requested
	buildProxy, _ := cmd.Flags().GetBool("proxy")
	if buildProxy {
		fmt.Println("\nBuilding debug proxy image...")
		proxyMgr := container.NewProxyManager(cfg)

		// Get the path to the devkit source (where templates are)
		// For now, assume current directory has the templates
		proxyImage, err := proxyMgr.BuildProxyImage(ctx, ".")
		if err != nil {
			fmt.Printf("Warning: failed to build proxy image: %v\n", err)
			fmt.Println("Debug proxy will not be available.")
		} else {
			fmt.Printf("Successfully built proxy image: %s\n", proxyImage)
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  devkit start    - Start the development container")
	if buildProxy {
		fmt.Println("  devkit start --debug-proxy  - Start with debug proxy filtering")
	}

	return nil
}

// runBuildLima handles building with Lima runtime
func runBuildLima(ctx context.Context, cmd *cobra.Command, cfg *config.Config, rc *RuntimeContext) error {
	fmt.Printf("Building image for project: %s (using Lima)\n", cfg.Project.Name)
	fmt.Printf("Project type: %s\n", cfg.Project.Type)
	fmt.Printf("Runtime: %s\n", cfg.Dependencies.Runtime)
	fmt.Printf("Lima VM: %s\n", rc.VMName)

	// Detect project settings
	var detection *detector.DetectionResult
	det := detector.New(".")
	detection, _ = det.Detect()

	if detection != nil && detection.Type != detector.TypeUnknown {
		fmt.Printf("Detected package manager: %s\n", detection.PackageManager)
	}

	// Create builder to generate Containerfile
	b := builder.New(cfg, detection)
	imageName := b.GetImageName()

	// Check if image exists
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		exists, _ := rc.Runtime.ImageExists(ctx, imageName)
		if exists {
			fmt.Printf("Image %s already exists. Use --force to rebuild.\n", imageName)
			return nil
		}
	}

	// Save Containerfile if requested
	saveContainerfile, _ := cmd.Flags().GetBool("save-containerfile")
	if saveContainerfile {
		if err := b.SaveContainerfile("Containerfile"); err != nil {
			return fmt.Errorf("failed to save Containerfile: %w", err)
		}
		fmt.Println("Saved Containerfile to current directory")
	}

	// Generate Containerfile content
	containerfileContent, err := b.GenerateContainerfile()
	if err != nil {
		return fmt.Errorf("failed to generate Containerfile: %w", err)
	}

	// Save to temp file for building
	if err := b.SaveContainerfile(".devkit-Containerfile"); err != nil {
		return fmt.Errorf("failed to save Containerfile: %w", err)
	}
	defer func() {
		// Clean up temp file
		_ = containerfileContent // Used to generate the file
	}()

	// Build using Lima runtime
	fmt.Println("\nBuilding container image...")
	noCache, _ := cmd.Flags().GetBool("no-cache")

	buildOpts := runtime.BuildOpts{
		ContextDir: ".",
		Dockerfile: ".devkit-Containerfile",
		ImageName:  imageName,
		NoCache:    noCache,
	}

	if err := rc.Runtime.Build(ctx, buildOpts); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Printf("\nSuccessfully built image: %s\n", imageName)
	fmt.Println("\nNext steps:")
	fmt.Println("  devkit start    - Start the development container")

	return nil
}
