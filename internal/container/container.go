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

// buildCreateArgs builds the argument list for container creation
// This is exported (via method) for testing purposes
func (m *Manager) buildCreateArgs() []string {
	containerName := m.config.ContainerName()

	args := []string{
		"create",
		"--name", containerName,
		"--hostname", "devkit",
	}

	// === SECURITY HARDENING (configurable) ===

	// Capability dropping (keep minimal caps for sshd and container operations)
	if m.config.Security.DropAllCapabilities {
		args = append(args,
			"--cap-drop=ALL",
			"--cap-add=SYS_CHROOT",   // For sshd privilege separation
			"--cap-add=SETUID",       // For sshd to switch to user
			"--cap-add=SETGID",       // For sshd to set groups
			"--cap-add=CHOWN",        // For file ownership changes
			"--cap-add=FOWNER",       // For file permission changes
		)
	}

	// Privilege escalation prevention
	if m.config.Security.NoNewPrivileges {
		args = append(args, "--security-opt=no-new-privileges:true")
	}

	// Read-only root filesystem
	if m.config.Security.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}

	// Writable tmpfs for system paths
	args = append(args,
		"--tmpfs", "/tmp:rw,nosuid,size=512m",
		"--tmpfs", "/run:rw,noexec,nosuid,size=64m",
	)

	// Use named volume for .ssh (works better with user namespaces)
	args = append(args, "--volume", fmt.Sprintf("%s-ssh:/home/developer/.ssh:rw", containerName))

	// Extra volumes (configurable, e.g., .npm, .cache)
	for _, extraVol := range m.config.ExtraVolumes {
		volumeName := sanitizeVolumeName(extraVol)
		args = append(args, "--volume", fmt.Sprintf("%s-%s:/home/developer/%s:rw", containerName, volumeName, extraVol))
	}

	// IDE remote servers need writable directories (configurable)
	for _, ideServer := range m.config.IDEServers {
		volumeName := sanitizeVolumeName(ideServer)
		args = append(args, "--volume", fmt.Sprintf("%s-%s:/home/developer/%s:rw", containerName, volumeName, ideServer))
	}

	// Network mode
	switch m.config.Security.NetworkMode {
	case "none":
		// Complete network isolation - most secure
		args = append(args, "--network=none")
	case "restricted":
		// Block access to host's localhost services (prevent lateral movement)
		args = append(args, "--network=slirp4netns:allow_host_loopback=false")
	case "full":
		// Full network access (dangerous, but user explicitly requested)
		args = append(args, "--network=slirp4netns")
	}

	// Resource limits
	if m.config.Security.MemoryLimit != "" {
		args = append(args, "--memory="+m.config.Security.MemoryLimit)
	}
	if m.config.Security.PidsLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", m.config.Security.PidsLimit))
	}

	// SSH port - bind to localhost only, not all interfaces
	args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:2222", m.config.SSH.Port))

	// Add debug port for Node.js - localhost only (unless disabled)
	if m.config.Project.Type == "nodejs" && !m.config.Security.DisableDebugPort {
		args = append(args, "--publish", "127.0.0.1:9229:9229")
	}

	// Application ports - bound to localhost only for security
	for _, port := range m.config.Ports {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d", port, port))
	}

	// Workspace volume - only for git/copy methods, not mount
	if m.config.Source.Method != "mount" {
		args = append(args, "--volume", fmt.Sprintf("%s-workspace:/home/developer/workspace:rw", containerName))
	}

	// SSH agent forwarding for secure git operations (key never enters container)
	if sshAuthSock := os.Getenv("SSH_AUTH_SOCK"); sshAuthSock != "" && m.config.Source.Method == "git" {
		// Mount the SSH agent socket (read-only for extra safety)
		args = append(args,
			"--volume", sshAuthSock+":/run/ssh-agent.sock:ro",
			"--env", "SSH_AUTH_SOCK=/run/ssh-agent.sock",
		)
	}

	return args
}

// Create creates a new container but doesn't start it
func (m *Manager) Create(ctx context.Context, imageName string) (string, error) {
	args := m.buildCreateArgs()

	// Handle source method
	switch m.config.Source.Method {
	case "mount":
		if !m.config.Features.AllowMount {
			return "", fmt.Errorf("mount method requires features.allow_mount to be enabled")
		}
		cwd, _ := os.Getwd()
		// Default: READ-ONLY mount for security (prevents container from injecting backdoors)
		// Writable mount requires explicit opt-in via allow_writable_mount
		mountOpts := "ro"
		if m.config.Features.AllowWritableMount {
			mountOpts = "rw"
		}
		args = append(args, "--volume", fmt.Sprintf("%s:/home/developer/workspace:%s", cwd, mountOpts))
		// node_modules is always a separate writable volume (container-local)
		args = append(args, "--volume", fmt.Sprintf("%s-node_modules:/home/developer/workspace/node_modules:rw", m.config.ContainerName()))
	case "copy":
		if !m.config.Features.AllowCopy {
			return "", fmt.Errorf("copy method requires features.allow_copy to be enabled")
		}
		// Copy method uses a workspace volume, files are copied after start
		// This is the most secure method - container has isolated copy, host never touched
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

// ExecAsUser executes a command inside the container as a specific user
func (m *Manager) ExecAsUser(ctx context.Context, user string, command ...string) (string, error) {
	containerName := m.config.ContainerName()

	args := append([]string{"exec", "-u", user, containerName}, command...)
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

	// First, ensure workspace directory has proper ownership (fix for user namespace issues)
	_, _ = m.Exec(ctx, "bash", "-c", "chown -R developer:developer /home/developer/workspace 2>/dev/null || true")

	// Clone the repository (run as developer user for proper permissions)
	cloneCmd := fmt.Sprintf("git clone --branch %s %s /home/developer/workspace",
		m.config.Source.Branch, m.config.Source.Repo)

	_, err := m.ExecAsUser(ctx, "developer", "bash", "-c", cloneCmd)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	return nil
}

// FixNodeModulesPermissions fixes ownership of node_modules volume for mount method
func (m *Manager) FixNodeModulesPermissions(ctx context.Context) {
	// The node_modules volume may be created with root ownership
	// Fix it so developer user can write to it
	m.Exec(ctx, "chown", "-R", "developer:developer", "/home/developer/workspace/node_modules")
}

// FixExtraVolumePermissions fixes ownership of extra volumes (e.g., .npm, .cache)
// Named volumes are created with root ownership, but apps need developer ownership
func (m *Manager) FixExtraVolumePermissions(ctx context.Context) {
	for _, extraVol := range m.config.ExtraVolumes {
		m.Exec(ctx, "chown", "-R", "developer:developer", "/home/developer/"+extraVol)
	}
}

// FixIDEServerPermissions fixes ownership of IDE server directories
// Named volumes are created with root ownership, but IDEs need developer ownership
func (m *Manager) FixIDEServerPermissions(ctx context.Context) {
	for _, ideServer := range m.config.IDEServers {
		m.Exec(ctx, "chown", "-R", "developer:developer", "/home/developer/"+ideServer)
	}
}

// FixChownPaths fixes ownership of specified paths in workspace
// For paths that need explicit chown after copying
func (m *Manager) FixChownPaths(ctx context.Context) {
	for _, path := range m.config.ChownPaths {
		m.Exec(ctx, "chown", "-R", "developer:developer", "/home/developer/workspace/"+path)
	}
}

// StartPortForwarders is deprecated - socat forwarders conflict with app port binding
// Use SSH port forwarding via 'devkit forward' instead, or configure apps to bind to 0.0.0.0
func (m *Manager) StartPortForwarders(ctx context.Context) {
	// Disabled: socat binds the port before the app can, causing conflicts
	// The published ports work fine when apps bind to 0.0.0.0
	// For apps binding to localhost, use 'devkit forward <port>' which creates SSH tunnels
}

// CopySourceToContainer copies the current directory into the container's workspace
// This is the most secure method - container gets isolated copy, host is never touched again
func (m *Manager) CopySourceToContainer(ctx context.Context) error {
	return m.CopySourceToContainerWithProgress(ctx, nil)
}

// CopySourceToContainerWithProgress copies with optional progress callback
func (m *Manager) CopySourceToContainerWithProgress(ctx context.Context, onFile func(filename string)) error {
	containerName := m.config.ContainerName()
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Create a temporary tarball
	tmpFile, err := os.CreateTemp("", "devkit-source-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Build tar command with exclusions from config
	tarArgs := []string{"-cf", tmpPath}
	for _, exclude := range m.config.CopyExclude {
		tarArgs = append(tarArgs, "--exclude="+exclude)
	}
	tarArgs = append(tarArgs, ".")

	// Create tarball
	tarCmd := exec.CommandContext(ctx, "tar", tarArgs...)
	tarCmd.Dir = cwd
	// Disable macOS Apple Double files (._* metadata) at the tar level
	tarCmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	var tarStderr bytes.Buffer
	tarCmd.Stderr = &tarStderr

	if err := tarCmd.Run(); err != nil {
		return fmt.Errorf("failed to create tarball: %w (stderr: %s)", err, tarStderr.String())
	}

	// Get file count for progress (optional)
	if onFile != nil {
		listCmd := exec.CommandContext(ctx, "tar", "-tf", tmpPath)
		listOut, err := listCmd.Output()
		if err == nil {
			lines := strings.Split(string(listOut), "\n")
			for i, line := range lines {
				if line != "" {
					onFile(line)
					// Only call periodically to avoid slowdown
					if i%100 == 0 {
						// Allow UI to update
					}
				}
			}
		}
	}

	// Copy tarball to container
	_, err = m.runPodman(ctx, "cp", tmpPath, containerName+":/tmp/source.tar")
	if err != nil {
		return fmt.Errorf("failed to copy tarball to container: %w", err)
	}

	// Extract tarball in container
	_, err = m.Exec(ctx, "tar", "-xf", "/tmp/source.tar", "-C", "/home/developer/workspace/")
	if err != nil {
		return fmt.Errorf("failed to extract tarball in container: %w", err)
	}

	// Clean up tarball in container
	m.Exec(ctx, "rm", "-f", "/tmp/source.tar")

	// Fix ownership so developer user can access the files
	_, err = m.Exec(ctx, "chown", "-R", "developer:developer", "/home/developer/workspace")
	if err != nil {
		return fmt.Errorf("failed to fix workspace ownership: %w", err)
	}

	return nil
}

// InstallDependencies installs project dependencies
func (m *Manager) InstallDependencies(ctx context.Context, installCmd string) error {
	if installCmd == "" {
		return nil
	}

	// Run as developer user for proper permissions
	_, err := m.ExecAsUser(ctx, "developer", "bash", "-c", fmt.Sprintf("cd /home/developer/workspace && %s", installCmd))
	if err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	return nil
}

// SetupSSHKey sets up SSH for the container:
// - Copies user's public key to authorized_keys (for SSH login)
// - Adds known_hosts for common git providers (safe - just public host keys)
// Note: Private key is NOT copied - we use SSH agent forwarding instead
func (m *Manager) SetupSSHKey(ctx context.Context) error {
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

	containerName := m.config.ContainerName()
	keyStr := strings.TrimSpace(string(pubKey))

	// Create .ssh directory, add authorized_keys for SSH login
	cmd := fmt.Sprintf(`mkdir -p /home/developer/.ssh && \
echo '%s' >> /home/developer/.ssh/authorized_keys && \
chmod 700 /home/developer/.ssh && \
chmod 600 /home/developer/.ssh/authorized_keys`, keyStr)

	_, err = m.runPodman(ctx, "exec", "-u", "developer", containerName, "bash", "-c", cmd)
	if err != nil {
		return fmt.Errorf("failed to setup SSH authorized_keys: %w", err)
	}

	// Add known_hosts for common git providers (these are public host keys - safe to include)
	knownHosts := `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=`

	cmd = fmt.Sprintf(`cat >> /home/developer/.ssh/known_hosts << 'EOF'
%s
EOF
chmod 644 /home/developer/.ssh/known_hosts`, knownHosts)

	_, _ = m.runPodman(ctx, "exec", "-u", "developer", containerName, "bash", "-c", cmd)
	// Non-fatal if this fails

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

// Commit saves the current container state as a new image
// This is used for paranoid mode to preserve installed dependencies before air-gapping
func (m *Manager) Commit(ctx context.Context, imageName string) (string, error) {
	containerName := m.config.ContainerName()

	// Commit with security-focused options
	args := []string{
		"commit",
		"--change", "CMD [\"sudo\", \"/usr/sbin/sshd\", \"-D\", \"-e\"]",
		containerName,
		imageName,
	}

	output, err := m.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to commit container: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// RemoveVolumes removes the named volumes associated with this container
func (m *Manager) RemoveVolumes(ctx context.Context) error {
	containerName := m.config.ContainerName()

	// Remove core volumes
	m.runPodman(ctx, "volume", "rm", "-f", containerName+"-workspace")
	m.runPodman(ctx, "volume", "rm", "-f", containerName+"-ssh")
	m.runPodman(ctx, "volume", "rm", "-f", containerName+"-node_modules")

	// Remove extra volumes (from config)
	for _, extraVol := range m.config.ExtraVolumes {
		volumeName := sanitizeVolumeName(extraVol)
		m.runPodman(ctx, "volume", "rm", "-f", containerName+"-"+volumeName)
	}

	// Remove IDE server volumes (from config)
	for _, ideServer := range m.config.IDEServers {
		volumeName := sanitizeVolumeName(ideServer)
		m.runPodman(ctx, "volume", "rm", "-f", containerName+"-"+volumeName)
	}

	return nil
}

// sanitizeVolumeName removes leading dots from volume names
func sanitizeVolumeName(name string) string {
	if len(name) > 0 && name[0] == '.' {
		return name[1:]
	}
	return name
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
