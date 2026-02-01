package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
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
  devkit init                                  # Initialize from current directory (interactive)
  devkit init git@github.com:user/repo.git    # Initialize with a git repository
  devkit init https://github.com/user/repo    # Initialize with HTTPS URL
  devkit init --no-tui                        # Non-interactive mode`,
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
	initCmd.Flags().Bool("no-tui", false, "Disable interactive TUI wizard")
}

// initWizardState holds the state for the init wizard
type initWizardState struct {
	// Project basics
	ProjectName string
	ProjectType string

	// Runtime
	Backend         string
	DoubleIsolation bool

	// Source & Ports
	SourceMethod string
	SSHPort      string
	ExtraPorts   string

	// Security
	SecurityLevel string

	// Internal
	RepoURL      string
	DetectedType string
	DetectedPM   string
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

	// Check if TUI is disabled
	noTUI, _ := cmd.Flags().GetBool("no-tui")
	if noTUI {
		return runInitNonInteractive(cmd, args, configPath)
	}

	// Run TUI wizard
	return runInitWizard(cmd, args, configPath)
}

func runInitWizard(cmd *cobra.Command, args []string, configPath string) error {
	// Initialize state with defaults and auto-detection
	state := &initWizardState{
		Backend:       "podman",
		SourceMethod:  "copy",
		SecurityLevel: "standard",
	}

	// Get project name from directory
	cwd, err := os.Getwd()
	if err == nil {
		state.ProjectName = filepath.Base(cwd)
	}

	// Handle repo URL if provided
	if len(args) > 0 {
		state.RepoURL = args[0]
		state.SourceMethod = "git"
		if state.ProjectName == "" {
			state.ProjectName = extractRepoName(state.RepoURL)
		}
	}

	// Auto-detect project type
	det := detector.New(".")
	result, err := det.Detect()
	if err == nil && result.Type != detector.TypeUnknown {
		state.ProjectType = string(result.Type)
		state.DetectedType = string(result.Type)
		state.DetectedPM = result.PackageManager
	} else {
		state.ProjectType = "nodejs" // Default
	}

	// Find available port
	port := 2222
	if !isPortAvailable(port) {
		port = findAvailablePort(port)
	}
	state.SSHPort = strconv.Itoa(port)

	// Build and run the form
	form := buildInitForm(state)

	err = form.Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			fmt.Println("Setup cancelled.")
			return nil
		}
		return fmt.Errorf("wizard error: %w", err)
	}

	// Build config from state
	cfg := buildConfigFromState(state)

	// Save config
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Print summary
	printInitSummary(configPath, state)

	return nil
}

func buildInitForm(state *initWizardState) *huh.Form {
	// Project type options
	projectTypes := []huh.Option[string]{
		huh.NewOption("Node.js", "nodejs"),
		huh.NewOption("Python", "python"),
		huh.NewOption("Go", "go"),
		huh.NewOption("Rust", "rust"),
		huh.NewOption("Other", "unknown"),
	}

	// Backend options with descriptions
	backendOptions := []huh.Option[string]{
		huh.NewOption("Podman (recommended, fast startup)", "podman"),
		huh.NewOption("Lima (per-project VMs, stronger isolation)", "lima"),
	}

	// Source method options
	sourceOptions := []huh.Option[string]{
		huh.NewOption("Copy files (secure, files copied once)", "copy"),
		huh.NewOption("Git clone (clone repo inside container)", "git"),
	}

	// Security level options
	securityOptions := []huh.Option[string]{
		huh.NewOption("Standard (network access, safe defaults)", "standard"),
		huh.NewOption("Paranoid (air-gapped after setup)", "paranoid"),
	}

	// Determine detected info text
	detectedInfo := ""
	if state.DetectedType != "" {
		detectedInfo = fmt.Sprintf("Detected: %s", state.DetectedType)
		if state.DetectedPM != "" {
			detectedInfo += fmt.Sprintf(" with %s", state.DetectedPM)
		}
	}

	return huh.NewForm(
		// Group 1: Project Basics
		huh.NewGroup(
			huh.NewNote().
				Title("Welcome to Devkit").
				Description("Let's set up your development container.\nPress Enter to continue, Ctrl+C to cancel."),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("Project Name").
				Description("Name for your project and container").
				Value(&state.ProjectName).
				Placeholder(state.ProjectName),

			huh.NewSelect[string]().
				Title("Project Type").
				Description(detectedInfo).
				Options(projectTypes...).
				Value(&state.ProjectType),
		).Title("Project Basics"),

		// Group 2: Runtime
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Runtime Backend").
				Description("Podman is faster; Lima provides VM-level isolation").
				Options(backendOptions...).
				Value(&state.Backend),

			huh.NewConfirm().
				Title("Enable double isolation?").
				Description("Run each project in its own dedicated VM (Lima only)").
				Value(&state.DoubleIsolation).
				Affirmative("Yes").
				Negative("No"),
		).Title("Runtime").WithHideFunc(func() bool {
			return false // Always show
		}),

		// Group 3: Source & Ports
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Source Method").
				Description("How to get your code into the container").
				Options(sourceOptions...).
				Value(&state.SourceMethod),

			huh.NewInput().
				Title("SSH Port").
				Description("Port for VS Code Remote-SSH connection").
				Value(&state.SSHPort).
				Validate(validatePort),

			huh.NewInput().
				Title("Additional Ports").
				Description("Comma-separated ports to expose (e.g., 3000,8080)").
				Value(&state.ExtraPorts).
				Placeholder("3000,8080"),
		).Title("Source & Ports"),

		// Group 4: Security
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Security Level").
				Description("Standard allows network; Paranoid disables network after setup").
				Options(securityOptions...).
				Value(&state.SecurityLevel),
		).Title("Security"),
	).WithTheme(huh.ThemeDracula())
}

func buildConfigFromState(state *initWizardState) *config.Config {
	cfg := config.DefaultConfig()

	// Project basics
	cfg.Project.Name = state.ProjectName
	cfg.Project.Type = state.ProjectType

	// Runtime
	cfg.Runtime.Backend = state.Backend
	if state.Backend == "lima" {
		cfg.Runtime.Lima.PerProjectVM = state.DoubleIsolation
	}

	// Source
	cfg.Source.Method = state.SourceMethod
	if state.RepoURL != "" {
		cfg.Source.Repo = state.RepoURL
	}
	if state.SourceMethod == "copy" {
		cfg.Features.AllowCopy = true
	}

	// Ports
	if port, err := strconv.Atoi(state.SSHPort); err == nil {
		cfg.SSH.Port = port
	}

	if state.ExtraPorts != "" {
		ports := strings.Split(state.ExtraPorts, ",")
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if port, err := strconv.Atoi(p); err == nil {
				cfg.Ports = append(cfg.Ports, port)
			}
		}
	}

	// Security
	if state.SecurityLevel == "paranoid" {
		cfg.Security.NetworkMode = "none"
		cfg.Security.TotalIsolation = true
	}

	return cfg
}

func printInitSummary(configPath string, state *initWizardState) {
	fmt.Println()
	fmt.Println("Configuration Summary")
	fmt.Println("─────────────────────")
	fmt.Printf("  Project:  %s (%s)\n", state.ProjectName, state.ProjectType)
	fmt.Printf("  Backend:  %s\n", state.Backend)
	fmt.Printf("  Source:   %s\n", state.SourceMethod)
	fmt.Printf("  SSH Port: %s\n", state.SSHPort)
	if state.ExtraPorts != "" {
		fmt.Printf("  Ports:    %s\n", state.ExtraPorts)
	}
	fmt.Printf("  Security: %s\n", state.SecurityLevel)
	fmt.Println()
	fmt.Printf("Created %s\n", configPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. devkit build   - Build the container image")
	fmt.Println("  2. devkit start   - Start the development container")
	fmt.Println("  3. devkit connect - Get VS Code connection instructions")
}

func validatePort(s string) error {
	if s == "" {
		return fmt.Errorf("port is required")
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid port number")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if !isPortAvailable(port) {
		nextAvailable := findAvailablePort(port)
		return fmt.Errorf("port %d is in use (try %d)", port, nextAvailable)
	}
	return nil
}

// runInitNonInteractive runs init without TUI (original behavior)
func runInitNonInteractive(cmd *cobra.Command, args []string, configPath string) error {
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
		fmt.Printf("Port %d is in use, using port %d instead\n", originalPort, port)
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
