package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/spf13/cobra"
)

var forwardCmd = &cobra.Command{
	Use:   "forward [ports...]",
	Short: "Forward ports from the container via SSH tunnel",
	Long: `Forward one or more ports from the container to localhost via SSH tunnel.

This creates secure SSH tunnels for accessing applications running in the container.
The tunnels run in the foreground - press Ctrl+C to stop them.

Use --save to persist the ports to devkit.yaml so they're automatically
published when the container is recreated.

Examples:
  devkit forward 3000           # Forward port 3000
  devkit forward 3000 8080      # Forward multiple ports
  devkit forward 3000 --save    # Forward and save to config
  devkit forward --list         # Show currently forwarded/configured ports`,
	RunE: runForward,
}

func init() {
	rootCmd.AddCommand(forwardCmd)

	forwardCmd.Flags().Bool("save", false, "Save ports to devkit.yaml for automatic publishing")
	forwardCmd.Flags().Bool("list", false, "List configured ports")
}

func runForward(cmd *cobra.Command, args []string) error {
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

	// Handle --list flag
	listOnly, _ := cmd.Flags().GetBool("list")
	if listOnly {
		return listPorts(cfg)
	}

	// Parse port arguments
	if len(args) == 0 {
		return fmt.Errorf("at least one port is required\n\nUsage: devkit forward <port> [port...]\n\nExamples:\n  devkit forward 3000\n  devkit forward 3000 8080")
	}

	ports := make([]int, 0, len(args))
	for _, arg := range args {
		port, err := strconv.Atoi(arg)
		if err != nil {
			return fmt.Errorf("invalid port '%s': must be a number", arg)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
		}
		ports = append(ports, port)
	}

	// Check if container is running
	mgr := container.New(cfg)
	running, _ := mgr.IsRunning(ctx)
	if !running {
		return fmt.Errorf("container is not running\n\nRun 'devkit start' first")
	}

	// Handle --save flag
	save, _ := cmd.Flags().GetBool("save")
	if save {
		cfg.AddPorts(ports...)
		if err := cfg.Save(configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("Saved ports %v to %s\n", ports, configPath)
		fmt.Println("Note: Run 'devkit remove && devkit start' to apply port publishing")
		fmt.Println()
	}

	// Build SSH command with port forwarding
	return runSSHTunnel(cfg, ports)
}

func listPorts(cfg *config.Config) error {
	if len(cfg.Ports) == 0 {
		fmt.Println("No ports configured in devkit.yaml")
		fmt.Println("\nTo forward ports dynamically:")
		fmt.Println("  devkit forward 3000")
		fmt.Println("\nTo save ports to config:")
		fmt.Println("  devkit forward 3000 --save")
		return nil
	}

	fmt.Println("Configured ports (published on container start):")
	for _, port := range cfg.Ports {
		fmt.Printf("  - %d (localhost:%d -> container:%d)\n", port, port, port)
	}
	fmt.Println("\nThese ports are automatically published when the container starts.")
	fmt.Println("To forward additional ports dynamically, use: devkit forward <port>")
	return nil
}

func runSSHTunnel(cfg *config.Config, ports []int) error {
	// Build -L arguments for each port
	var localForwards []string
	for _, port := range ports {
		localForwards = append(localForwards, "-L", fmt.Sprintf("%d:localhost:%d", port, port))
	}

	// Build SSH command
	sshArgs := []string{
		"-N", // Don't execute remote command
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(cfg.SSH.Port),
	}
	sshArgs = append(sshArgs, localForwards...)
	sshArgs = append(sshArgs, "developer@localhost")

	// Print info
	fmt.Println("Starting SSH port forwarding...")
	fmt.Printf("Container: %s\n", cfg.ContainerName())
	fmt.Println("Forwarded ports:")
	for _, port := range ports {
		fmt.Printf("  localhost:%d -> container:%d\n", port, port)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop forwarding")
	fmt.Println()

	// Create command
	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start SSH process
	if err := sshCmd.Start(); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %w", err)
	}

	// Wait for signal or process exit
	done := make(chan error, 1)
	go func() {
		done <- sshCmd.Wait()
	}()

	select {
	case <-sigChan:
		fmt.Println("\nStopping port forwarding...")
		sshCmd.Process.Signal(syscall.SIGTERM)
		<-done
	case err := <-done:
		if err != nil {
			// Check if it's just a normal termination
			if exitErr, ok := err.(*exec.ExitError); ok {
				if exitErr.ExitCode() == 255 {
					return fmt.Errorf("SSH connection failed - is the container running?")
				}
			}
			return fmt.Errorf("SSH tunnel error: %w", err)
		}
	}

	return nil
}

// FormatPortList formats a list of ports for display
func FormatPortList(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ", ")
}
