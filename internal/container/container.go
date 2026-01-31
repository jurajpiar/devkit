package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/config"
)

// Manager handles container lifecycle via Podman CLI
type Manager struct {
	config *config.Config
}

// New creates a new container Manager
func New(cfg *config.Config) *Manager {
	return &Manager{config: cfg}
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	Status  string
	Created time.Time
	Ports   []PortMapping
}

// PortMapping represents a port mapping
type PortMapping struct {
	HostPort      int
	ContainerPort int
	Protocol      string
}

// Create creates a new container but doesn't start it
func (m *Manager) Create(ctx context.Context, imageName string) (string, error) {
	containerName := m.config.ContainerName()

	args := []string{
		"create",
		"--name", containerName,
		"--userns=keep-id", // Rootless: map current user
		"--hostname", "devkit",
		"--publish", fmt.Sprintf("%d:22", m.config.SSH.Port), // SSH port
	}

	// Add debug port for Node.js
	if m.config.Project.Type == "nodejs" {
		args = append(args, "--publish", "9229:9229")
	}

	// Handle source method
	switch m.config.Source.Method {
	case "mount":
		if !m.config.Features.AllowMount {
			return "", fmt.Errorf("mount method requires features.allow_mount to be enabled")
		}
		// Mount current directory as workspace (read-only by default for security)
		cwd, _ := os.Getwd()
		args = append(args, "--volume", fmt.Sprintf("%s:/home/developer/workspace:ro", cwd))
	case "copy":
		if !m.config.Features.AllowCopy {
			return "", fmt.Errorf("copy method requires features.allow_copy to be enabled")
		}
		// Copy will be handled after container creation
	}

	// Set environment variables
	args = append(args,
		"--env", fmt.Sprintf("GIT_REPO=%s", m.config.Source.Repo),
		"--env", fmt.Sprintf("GIT_BRANCH=%s", m.config.Source.Branch),
	)

	args = append(args, imageName)

	output, err := m.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// Start starts an existing container
func (m *Manager) Start(ctx context.Context) error {
	containerName := m.config.ContainerName()

	_, err := m.runPodman(ctx, "start", containerName)
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

// Stop stops a running container
func (m *Manager) Stop(ctx context.Context) error {
	containerName := m.config.ContainerName()

	_, err := m.runPodman(ctx, "stop", containerName)
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

// Remove removes a container
func (m *Manager) Remove(ctx context.Context) error {
	containerName := m.config.ContainerName()

	_, err := m.runPodman(ctx, "rm", "-f", containerName)
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	return nil
}

// Exec executes a command inside the container
func (m *Manager) Exec(ctx context.Context, command ...string) (string, error) {
	containerName := m.config.ContainerName()

	args := append([]string{"exec", containerName}, command...)
	output, err := m.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %w", err)
	}

	return output, nil
}

// ExecInteractive runs an interactive command in the container
func (m *Manager) ExecInteractive(ctx context.Context, command ...string) error {
	containerName := m.config.ContainerName()

	args := append([]string{"exec", "-it", containerName}, command...)
	return m.runPodmanInteractive(ctx, args...)
}

// CloneRepo clones the git repository inside the container
func (m *Manager) CloneRepo(ctx context.Context) error {
	if m.config.Source.Method != "git" {
		return nil
	}

	if m.config.Source.Repo == "" {
		return fmt.Errorf("no git repository configured")
	}

	// Clone the repository
	cloneCmd := fmt.Sprintf("git clone --branch %s %s /home/developer/workspace",
		m.config.Source.Branch, m.config.Source.Repo)

	_, err := m.Exec(ctx, "bash", "-c", cloneCmd)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	return nil
}

// InstallDependencies installs project dependencies
func (m *Manager) InstallDependencies(ctx context.Context, installCmd string) error {
	if installCmd == "" {
		return nil
	}

	_, err := m.Exec(ctx, "bash", "-c", fmt.Sprintf("cd /home/developer/workspace && %s", installCmd))
	if err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	return nil
}

// SetupSSHKey copies the user's SSH public key to the container
func (m *Manager) SetupSSHKey(ctx context.Context) error {
	// Read user's SSH public key
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Try common SSH key locations
	keyPaths := []string{
		homeDir + "/.ssh/id_ed25519.pub",
		homeDir + "/.ssh/id_rsa.pub",
	}

	var pubKey []byte
	for _, keyPath := range keyPaths {
		if data, err := os.ReadFile(keyPath); err == nil {
			pubKey = data
			break
		}
	}

	if pubKey == nil {
		return fmt.Errorf("no SSH public key found in ~/.ssh/")
	}

	// Add key to container's authorized_keys
	containerName := m.config.ContainerName()
	keyStr := strings.TrimSpace(string(pubKey))

	cmd := fmt.Sprintf("mkdir -p /home/developer/.ssh && echo '%s' >> /home/developer/.ssh/authorized_keys && chmod 600 /home/developer/.ssh/authorized_keys", keyStr)
	_, err = m.runPodman(ctx, "exec", containerName, "bash", "-c", cmd)
	if err != nil {
		return fmt.Errorf("failed to setup SSH key: %w", err)
	}

	return nil
}

// IsRunning checks if the container is running
func (m *Manager) IsRunning(ctx context.Context) (bool, error) {
	containerName := m.config.ContainerName()

	output, err := m.runPodman(ctx, "inspect", "--format", "{{.State.Running}}", containerName)
	if err != nil {
		// Container doesn't exist
		return false, nil
	}

	return strings.TrimSpace(output) == "true", nil
}

// Exists checks if the container exists
func (m *Manager) Exists(ctx context.Context) (bool, error) {
	containerName := m.config.ContainerName()

	_, err := m.runPodman(ctx, "inspect", containerName)
	return err == nil, nil
}

// GetInfo returns information about the container
func (m *Manager) GetInfo(ctx context.Context) (*ContainerInfo, error) {
	containerName := m.config.ContainerName()

	output, err := m.runPodman(ctx, "inspect", containerName)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}

	var inspectData []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse container info: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no container data found")
	}

	data := inspectData[0]
	state := data["State"].(map[string]interface{})

	info := &ContainerInfo{
		ID:     data["Id"].(string)[:12],
		Name:   containerName,
		Status: state["Status"].(string),
	}

	if image, ok := data["ImageName"].(string); ok {
		info.Image = image
	}

	return info, nil
}

// List returns all devkit containers
func (m *Manager) List(ctx context.Context) ([]ContainerInfo, error) {
	output, err := m.runPodman(ctx, "ps", "-a", "--filter", "name=devkit-", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "[]" {
		return []ContainerInfo{}, nil
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	result := make([]ContainerInfo, len(containers))
	for i, c := range containers {
		var name string
		if names, ok := c["Names"].([]interface{}); ok && len(names) > 0 {
			name = names[0].(string)
		}
		result[i] = ContainerInfo{
			ID:     c["Id"].(string)[:12],
			Name:   name,
			Image:  c["Image"].(string),
			Status: c["State"].(string),
		}
	}

	return result, nil
}

// CopyToContainer copies files from host to container
func (m *Manager) CopyToContainer(ctx context.Context, src, dst string) error {
	containerName := m.config.ContainerName()

	_, err := m.runPodman(ctx, "cp", src, fmt.Sprintf("%s:%s", containerName, dst))
	if err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}

	return nil
}

// runPodman executes a podman command and returns output
func (m *Manager) runPodman(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// runPodmanInteractive runs podman with interactive terminal
func (m *Manager) runPodmanInteractive(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// CheckPodman verifies that podman is available
func CheckPodman() error {
	cmd := exec.Command("podman", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman not found: %w", err)
	}
	return nil
}
