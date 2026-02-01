package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/detector"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [repo-url]",
	Short: "Initialize a devkit configuration",
	Long: `Initialize a new devkit.yaml configuration file.

If a repository URL is provided, it will be used as the source.
Otherwise, devkit will attempt to detect project settings from the current directory.

Examples:
  devkit init                                  # Initialize from current directory
  devkit init git@github.com:user/repo.git    # Initialize with a git repository
  devkit init https://github.com/user/repo    # Initialize with HTTPS URL`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringP("name", "n", "", "Project name (defaults to directory name)")
	initCmd.Flags().StringP("type", "t", "", "Project type (e.g., nodejs)")
	initCmd.Flags().StringP("branch", "b", "main", "Git branch to clone")
	initCmd.Flags().IntP("port", "p", 2222, "SSH port for VS Code connection")
	initCmd.Flags().Bool("force", false, "Overwrite existing devkit.yaml")
}

func runInit(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	// Check if config already exists
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(configPath); err == nil && !force {
		return fmt.Errorf("devkit.yaml already exists (use --force to overwrite)")
	}

	// Start with default config
	cfg := config.DefaultConfig()

	// Get project name
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		// Use current directory name
		cwd, err := os.Getwd()
		if err == nil {
			name = filepath.Base(cwd)
		}
	}
	cfg.Project.Name = name

	// Handle repository URL if provided
	if len(args) > 0 {
		repoURL := args[0]
		cfg.Source.Repo = repoURL
		cfg.Source.Method = "git"

		// Extract project name from repo URL if not specified
		if name == "" {
			cfg.Project.Name = extractRepoName(repoURL)
		}
	} else {
		// No repo URL - use copy for secure local development
		// Copy method: files copied into isolated container, host never accessed after
		cfg.Source.Method = "copy"
		cfg.Features.AllowCopy = true
	}

	// Set branch
	branch, _ := cmd.Flags().GetString("branch")
	cfg.Source.Branch = branch

	// Set SSH port (check availability)
	port, _ := cmd.Flags().GetInt("port")
	if !isPortAvailable(port) {
		originalPort := port
		port = findAvailablePort(port)
		fmt.Printf("⚠ Port %d is in use, using port %d instead\n", originalPort, port)
	}
	cfg.SSH.Port = port

	// Try to detect project type
	projectType, _ := cmd.Flags().GetString("type")
	if projectType != "" {
		cfg.Project.Type = projectType
	} else {
		// Auto-detect from current directory
		det := detector.New(".")
		result, err := det.Detect()
		if err == nil && result.Type != detector.TypeUnknown {
			cfg.Project.Type = string(result.Type)
			cfg.Dependencies.Runtime = result.Runtime

			fmt.Printf("Detected project type: %s\n", result.Type)
			fmt.Printf("Detected runtime: %s\n", result.Runtime)

			if result.PackageManager != "" {
				fmt.Printf("Detected package manager: %s\n", result.PackageManager)
			}
		}
	}

	// Save config
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\nCreated %s\n", configPath)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Review and edit devkit.yaml as needed")
	fmt.Println("  2. Run 'devkit build' to build the container image")
	fmt.Println("  3. Run 'devkit start' to start the development container")
	fmt.Println("  4. Run 'devkit connect' to get VS Code connection instructions")

	return nil
}

// extractRepoName extracts the project name from a git repository URL
func extractRepoName(url string) string {
	// Remove trailing .git
	url = strings.TrimSuffix(url, ".git")

	// Handle SSH URLs (git@github.com:user/repo)
	if strings.Contains(url, ":") && !strings.Contains(url, "://") {
		parts := strings.Split(url, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}

	// Handle HTTPS URLs (https://github.com/user/repo)
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return "project"
}

// isPortAvailable checks if a port is available for binding
func isPortAvailable(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// findAvailablePort finds the next available port starting from the given port
func findAvailablePort(startPort int) int {
	for port := startPort; port < startPort+100; port++ {
		if isPortAvailable(port) {
			return port
		}
	}
	// Fallback: return a high port
	return 22222
}
