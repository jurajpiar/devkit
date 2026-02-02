package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"

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
	buildCmd.Flags().Bool("egress-proxy", false, "Also build the egress proxy image for domain filtering")
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

	// Build egress proxy image if requested
	buildEgressProxy, _ := cmd.Flags().GetBool("egress-proxy")
	if buildEgressProxy {
		fmt.Println("\nBuilding egress proxy image...")
		if err := buildEgressProxyImage(ctx); err != nil {
			fmt.Printf("Warning: failed to build egress proxy image: %v\n", err)
			fmt.Println("Egress proxy will not be available.")
		} else {
			fmt.Println("Successfully built egress proxy image: devkit/egressproxy:latest")
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  devkit start    - Start the development container")
	if buildProxy {
		fmt.Println("  devkit start --debug-proxy  - Start with debug proxy filtering")
	}
	if buildEgressProxy {
		fmt.Println("  Configure egress_proxy in devkit.yaml to use domain filtering")
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

	// Build egress proxy if enabled in config or explicitly requested
	buildEgressProxy, _ := cmd.Flags().GetBool("egress-proxy")
	if buildEgressProxy || cfg.Security.EgressProxy.Enabled {
		fmt.Println("\nBuilding egress proxy image...")
		if err := buildEgressProxyImageLima(ctx, rc.VMName); err != nil {
			fmt.Printf("Warning: failed to build egress proxy image: %v\n", err)
		} else {
			fmt.Println("Successfully built egress proxy image: devkit/egressproxy:latest")
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  devkit start    - Start the development container")

	return nil
}

// buildEgressProxyImage builds the egress proxy image using Podman
func buildEgressProxyImage(ctx context.Context) error {
	// Create a minimal Containerfile for the egress proxy
	containerfile := `FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /devkit-egressproxy ./cmd/egressproxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /devkit-egressproxy /usr/local/bin/devkit-egressproxy
ENTRYPOINT ["/usr/local/bin/devkit-egressproxy"]
`

	// Write to temp file
	if err := os.WriteFile(".devkit-egressproxy-Containerfile", []byte(containerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Containerfile: %w", err)
	}
	defer os.Remove(".devkit-egressproxy-Containerfile")

	// Build the image using podman
	args := []string{
		"build",
		"-t", "devkit/egressproxy:latest",
		"-f", ".devkit-egressproxy-Containerfile",
		".",
	}

	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// buildEgressProxyImageLima builds the egress proxy image inside the Lima VM
func buildEgressProxyImageLima(ctx context.Context, vmName string) error {
	// Check if image already exists
	checkCmd := exec.CommandContext(ctx, "limactl", "shell", vmName, "--",
		"nerdctl", "image", "inspect", "devkit/egressproxy:latest")
	if checkCmd.Run() == nil {
		fmt.Println("  Egress proxy image already exists")
		return nil
	}

	// Create a temp directory for the build context
	tmpDir, err := os.MkdirTemp("", "devkit-egressproxy-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write Containerfile
	containerfile := `FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /egressproxy ./cmd/egressproxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /egressproxy /usr/local/bin/egressproxy
EXPOSE 3128
ENTRYPOINT ["/usr/local/bin/egressproxy"]
CMD ["-listen", ":3128"]
`
	containerfilePath := tmpDir + "/Containerfile"
	if err := os.WriteFile(containerfilePath, []byte(containerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Containerfile: %w", err)
	}

	// Copy devkit source to temp dir (we need go.mod, go.sum, and the egressproxy code)
	// Find devkit source dir
	sourceDir, err := findDevkitSource()
	if err != nil {
		return err
	}

	// Copy required files
	filesToCopy := []string{"go.mod", "go.sum"}
	for _, f := range filesToCopy {
		src := sourceDir + "/" + f
		dst := tmpDir + "/" + f
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", f, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", f, err)
		}
	}

	// Copy source directories
	dirsToCreate := []string{"cmd/egressproxy", "internal/egressproxy"}
	for _, d := range dirsToCreate {
		if err := os.MkdirAll(tmpDir+"/"+d, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", d, err)
		}
	}

	// Copy egressproxy source files
	srcFiles := []struct{ src, dst string }{
		{sourceDir + "/cmd/egressproxy/main.go", tmpDir + "/cmd/egressproxy/main.go"},
		{sourceDir + "/internal/egressproxy/proxy.go", tmpDir + "/internal/egressproxy/proxy.go"},
		{sourceDir + "/internal/egressproxy/filter.go", tmpDir + "/internal/egressproxy/filter.go"},
		{sourceDir + "/internal/egressproxy/audit.go", tmpDir + "/internal/egressproxy/audit.go"},
	}
	for _, f := range srcFiles {
		data, err := os.ReadFile(f.src)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", f.src, err)
		}
		if err := os.WriteFile(f.dst, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", f.dst, err)
		}
	}

	// Copy to VM
	vmTmpDir := "/tmp/egressproxy-build"
	fmt.Println("  Copying build context to VM...")
	
	// Remove old build dir if exists
	exec.CommandContext(ctx, "limactl", "shell", vmName, "--", "rm", "-rf", vmTmpDir).Run()
	
	// Copy using limactl
	copyCmd := exec.CommandContext(ctx, "limactl", "copy", "-r", tmpDir, vmName+":"+vmTmpDir)
	if out, err := copyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy to VM: %w\n%s", err, string(out))
	}

	// Build in VM
	fmt.Println("  Building image in VM...")
	buildCmd := exec.CommandContext(ctx, "limactl", "shell", vmName, "--",
		"nerdctl", "build",
		"-t", "devkit/egressproxy:latest",
		"-f", vmTmpDir+"/Containerfile",
		vmTmpDir)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	// Cleanup
	exec.CommandContext(ctx, "limactl", "shell", vmName, "--", "rm", "-rf", vmTmpDir).Run()

	return nil
}

// findDevkitSource finds the devkit source directory
func findDevkitSource() (string, error) {
	// Check common locations
	candidates := []string{}

	// Current directory
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}

	// Home directory locations
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			home+"/src/jurajpiar/dev_setup",
			home+"/src/devkit",
			home+"/go/src/github.com/jurajpiar/devkit",
		)
	}

	for _, dir := range candidates {
		// Check if it has the egressproxy source
		if _, err := os.Stat(dir + "/cmd/egressproxy/main.go"); err == nil {
			return dir, nil
		}
	}

	return "", fmt.Errorf("cannot find devkit source directory with egressproxy code")
}
