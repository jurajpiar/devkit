package cli

import (
	"context"
	"fmt"

	"github.com/jurajpiar/devkit/internal/builder"
	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/detector"
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
  devkit build --no-cache   # Build without cache
  devkit build --save-containerfile  # Save generated Containerfile`,
	RunE: runBuild,
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().Bool("no-cache", false, "Build without using cache")
	buildCmd.Flags().Bool("save-containerfile", false, "Save the generated Containerfile to current directory")
	buildCmd.Flags().Bool("force", false, "Force rebuild even if image exists")
}

func runBuild(cmd *cobra.Command, args []string) error {
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
	fmt.Println("\nNext steps:")
	fmt.Println("  devkit start    - Start the development container")

	return nil
}
