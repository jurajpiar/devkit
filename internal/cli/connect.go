package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Show VS Code connection instructions",
	Long: `Display instructions for connecting VS Code to the development container.

This command shows:
  - SSH connection details
  - VS Code Remote-SSH configuration
  - SSH config snippet for easy connection

Examples:
  devkit connect              # Show connection instructions
  devkit connect --ssh-config # Output SSH config snippet only`,
	RunE: runConnect,
}

func init() {
	rootCmd.AddCommand(connectCmd)

	connectCmd.Flags().Bool("ssh-config", false, "Output SSH config snippet only")
	connectCmd.Flags().Bool("add-to-config", false, "Add SSH config to ~/.ssh/config")
}

func runConnect(cmd *cobra.Command, args []string) error {
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

	// Create container manager and check status
	mgr := container.New(cfg)

	running, _ := mgr.IsRunning(ctx)
	if !running {
		return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
	}

	// Generate SSH config snippet
	sshConfig := generateSSHConfig(cfg)

	// If --ssh-config flag, output only the config snippet
	sshConfigOnly, _ := cmd.Flags().GetBool("ssh-config")
	if sshConfigOnly {
		fmt.Print(sshConfig)
		return nil
	}

	// If --add-to-config flag, add to SSH config
	addToConfig, _ := cmd.Flags().GetBool("add-to-config")
	if addToConfig {
		if err := addSSHConfig(cfg, sshConfig); err != nil {
			return fmt.Errorf("failed to add SSH config: %w", err)
		}
		fmt.Println("Added SSH config to ~/.ssh/config")
		fmt.Printf("\nYou can now connect with: ssh devkit-%s\n", cfg.Project.Name)
		return nil
	}

	// Show full connection instructions
	fmt.Println("=== VS Code Connection Instructions ===")
	fmt.Println()
	fmt.Printf("Container: %s\n", cfg.ContainerName())
	fmt.Printf("SSH Port:  %d\n", cfg.SSH.Port)
	fmt.Printf("User:      developer\n")
	fmt.Println()

	fmt.Println("--- Method 1: Direct SSH ---")
	fmt.Println()
	fmt.Printf("  ssh -p %d developer@localhost\n", cfg.SSH.Port)
	fmt.Println()

	fmt.Println("--- Method 2: VS Code Remote-SSH Extension ---")
	fmt.Println()
	fmt.Println("  1. Install the 'Remote - SSH' extension in VS Code")
	fmt.Println("  2. Press Cmd+Shift+P (or Ctrl+Shift+P)")
	fmt.Println("  3. Type 'Remote-SSH: Connect to Host...'")
	fmt.Printf("  4. Enter: ssh://developer@localhost:%d\n", cfg.SSH.Port)
	fmt.Println("  5. Select Linux as the remote platform")
	fmt.Println("  6. Open folder: /home/developer/workspace")
	fmt.Println()

	fmt.Println("--- Method 3: Add to SSH Config ---")
	fmt.Println()
	fmt.Println("Add this to your ~/.ssh/config:")
	fmt.Println()
	fmt.Println(sshConfig)
	fmt.Println()
	fmt.Printf("Then connect with: ssh devkit-%s\n", cfg.Project.Name)
	fmt.Println()
	fmt.Println("Or run: devkit connect --add-to-config")
	fmt.Println()

	fmt.Println("--- Debugging Node.js ---")
	fmt.Println()
	fmt.Println("  Debug port 9229 is forwarded for Node.js debugging.")
	fmt.Println("  In VS Code, create a launch.json with:")
	fmt.Println()
	fmt.Println(`  {
    "type": "node",
    "request": "attach",
    "name": "Attach to Container",
    "port": 9229,
    "restart": true,
    "localRoot": "${workspaceFolder}",
    "remoteRoot": "/home/developer/workspace"
  }`)
	fmt.Println()

	return nil
}

// generateSSHConfig creates an SSH config snippet for the container
func generateSSHConfig(cfg *config.Config) string {
	return fmt.Sprintf(`Host devkit-%s
    HostName localhost
    Port %d
    User developer
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
`, cfg.Project.Name, cfg.SSH.Port)
}

// addSSHConfig adds the SSH config to the user's ~/.ssh/config
func addSSHConfig(cfg *config.Config, sshConfig string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	configPath := filepath.Join(sshDir, "config")

	// Ensure .ssh directory exists
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing config
	var existingConfig []byte
	if data, err := os.ReadFile(configPath); err == nil {
		existingConfig = data
	}

	// Check if entry already exists
	hostName := fmt.Sprintf("Host devkit-%s", cfg.Project.Name)
	if len(existingConfig) > 0 && contains(string(existingConfig), hostName) {
		return fmt.Errorf("SSH config entry for %s already exists", cfg.Project.Name)
	}

	// Append new config
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer f.Close()

	// Add newline if file doesn't end with one
	if len(existingConfig) > 0 && existingConfig[len(existingConfig)-1] != '\n' {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}

	// Add devkit marker comment
	if _, err := f.WriteString("\n# Devkit managed entry\n"); err != nil {
		return err
	}

	if _, err := f.WriteString(sshConfig); err != nil {
		return err
	}

	return nil
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
