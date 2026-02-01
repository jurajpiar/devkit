// Package podman provides a Podman-based implementation of the runtime interfaces.
package podman

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jurajpiar/devkit/internal/runtime"
)

// Runtime implements the runtime.Runtime interface using Podman
type Runtime struct {
	// Connection is the Podman connection/machine to use (empty for default)
	Connection string
}

// NewRuntime creates a new Podman runtime
func NewRuntime(connection string) *Runtime {
	return &Runtime{
		Connection: connection,
	}
}

// Name returns the runtime backend name
func (r *Runtime) Name() runtime.Backend {
	return runtime.BackendPodman
}

// Create creates a new container
func (r *Runtime) Create(ctx context.Context, opts runtime.CreateOpts) (string, error) {
	args := []string{"create", "--name", opts.Name}

	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}

	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}

	if opts.WorkDir != "" {
		args = append(args, "--workdir", opts.WorkDir)
	}

	// Capabilities
	for _, cap := range opts.CapDrop {
		args = append(args, "--cap-drop="+cap)
	}
	for _, cap := range opts.CapAdd {
		args = append(args, "--cap-add="+cap)
	}

	// Security options
	for _, opt := range opts.SecurityOpts {
		args = append(args, "--security-opt="+opt)
	}

	// Read-only filesystem
	if opts.ReadOnly {
		args = append(args, "--read-only")
	}

	// Tmpfs mounts
	for _, tmpfs := range opts.Tmpfs {
		args = append(args, "--tmpfs", fmt.Sprintf("%s:%s", tmpfs.Target, tmpfs.Options))
	}

	// Volume mounts
	for _, vol := range opts.Volumes {
		mountStr := fmt.Sprintf("%s:%s", vol.Source, vol.Target)
		if vol.ReadOnly {
			mountStr += ":ro"
		} else {
			mountStr += ":rw"
		}
		args = append(args, "--volume", mountStr)
	}

	// Port mappings
	for _, port := range opts.Ports {
		hostIP := port.HostIP
		if hostIP == "" {
			hostIP = "127.0.0.1"
		}
		args = append(args, "--publish", fmt.Sprintf("%s:%d:%d", hostIP, port.HostPort, port.ContainerPort))
	}

	// Network mode
	if opts.NetworkMode != "" {
		args = append(args, "--network="+opts.NetworkMode)
	}

	// Resource limits
	if opts.Memory != "" {
		args = append(args, "--memory="+opts.Memory)
	}
	if opts.PidsLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", opts.PidsLimit))
	}

	// Environment variables
	for k, v := range opts.Env {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	// Labels
	for k, v := range opts.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	// Image
	args = append(args, opts.Image)

	output, err := r.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// Start starts an existing container
func (r *Runtime) Start(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "start", name)
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	return nil
}

// Stop stops a running container
func (r *Runtime) Stop(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "stop", name)
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}
	return nil
}

// Remove removes a container
func (r *Runtime) Remove(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}
	return nil
}

// Kill forcefully stops a container
func (r *Runtime) Kill(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "kill", name)
	if err != nil {
		return fmt.Errorf("failed to kill container: %w", err)
	}
	return nil
}

// Exec executes a command inside the container
func (r *Runtime) Exec(ctx context.Context, name string, cmd ...string) (string, error) {
	args := append([]string{"exec", name}, cmd...)
	output, err := r.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %w", err)
	}
	return output, nil
}

// ExecAsUser executes a command as a specific user
func (r *Runtime) ExecAsUser(ctx context.Context, name, user string, cmd ...string) (string, error) {
	args := append([]string{"exec", "-u", user, name}, cmd...)
	output, err := r.runPodman(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %w", err)
	}
	return output, nil
}

// ExecInteractive runs an interactive command in the container
func (r *Runtime) ExecInteractive(ctx context.Context, name string, cmd ...string) error {
	args := append([]string{"exec", "-it", name}, cmd...)
	return r.runPodmanInteractive(ctx, args...)
}

// Exists checks if the container exists
func (r *Runtime) Exists(ctx context.Context, name string) (bool, error) {
	_, err := r.runPodman(ctx, "inspect", name)
	return err == nil, nil
}

// IsRunning checks if the container is running
func (r *Runtime) IsRunning(ctx context.Context, name string) (bool, error) {
	output, err := r.runPodman(ctx, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(output) == "true", nil
}

// GetInfo returns information about the container
func (r *Runtime) GetInfo(ctx context.Context, name string) (*runtime.ContainerInfo, error) {
	output, err := r.runPodman(ctx, "inspect", name)
	if err != nil {
		return nil, runtime.ErrContainerNotFound{Name: name}
	}

	var inspectData []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse container info: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, runtime.ErrContainerNotFound{Name: name}
	}

	data := inspectData[0]
	state := data["State"].(map[string]interface{})

	info := &runtime.ContainerInfo{
		ID:      data["Id"].(string)[:12],
		Name:    name,
		Status:  state["Status"].(string),
		Running: state["Running"].(bool),
	}

	if image, ok := data["ImageName"].(string); ok {
		info.Image = image
	}

	return info, nil
}

// List returns all containers matching the devkit prefix
func (r *Runtime) List(ctx context.Context) ([]runtime.ContainerInfo, error) {
	output, err := r.runPodman(ctx, "ps", "-a", "--filter", "name=devkit-", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "[]" {
		return []runtime.ContainerInfo{}, nil
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	result := make([]runtime.ContainerInfo, len(containers))
	for i, c := range containers {
		var name string
		if names, ok := c["Names"].([]interface{}); ok && len(names) > 0 {
			name = names[0].(string)
		}
		result[i] = runtime.ContainerInfo{
			ID:      c["Id"].(string)[:12],
			Name:    name,
			Image:   c["Image"].(string),
			Status:  c["State"].(string),
			Running: c["State"].(string) == "running",
		}
	}

	return result, nil
}

// CopyTo copies files from host to container
func (r *Runtime) CopyTo(ctx context.Context, name, src, dst string) error {
	_, err := r.runPodman(ctx, "cp", src, fmt.Sprintf("%s:%s", name, dst))
	if err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}
	return nil
}

// CopyFrom copies files from container to host
func (r *Runtime) CopyFrom(ctx context.Context, name, src, dst string) error {
	_, err := r.runPodman(ctx, "cp", fmt.Sprintf("%s:%s", name, src), dst)
	if err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}
	return nil
}

// Build builds a container image
func (r *Runtime) Build(ctx context.Context, opts runtime.BuildOpts) error {
	args := []string{"build"}

	if opts.Dockerfile != "" {
		args = append(args, "-f", opts.Dockerfile)
	}

	if opts.ImageName != "" {
		args = append(args, "-t", opts.ImageName)
	}

	for _, tag := range opts.Tags {
		args = append(args, "-t", tag)
	}

	for k, v := range opts.BuildArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}

	if opts.NoCache {
		args = append(args, "--no-cache")
	}

	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	args = append(args, opts.ContextDir)

	_, err := r.runPodman(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	return nil
}

// ImageExists checks if an image exists
func (r *Runtime) ImageExists(ctx context.Context, image string) (bool, error) {
	_, err := r.runPodman(ctx, "image", "exists", image)
	return err == nil, nil
}

// RemoveImage removes an image
func (r *Runtime) RemoveImage(ctx context.Context, image string) error {
	_, err := r.runPodman(ctx, "rmi", "-f", image)
	if err != nil {
		return fmt.Errorf("failed to remove image: %w", err)
	}
	return nil
}

// CreateVolume creates a named volume
func (r *Runtime) CreateVolume(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "volume", "create", name)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}
	return nil
}

// RemoveVolume removes a named volume
func (r *Runtime) RemoveVolume(ctx context.Context, name string) error {
	_, err := r.runPodman(ctx, "volume", "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("failed to remove volume: %w", err)
	}
	return nil
}

// ListVolumes lists volumes with the given prefix
func (r *Runtime) ListVolumes(ctx context.Context, prefix string) ([]string, error) {
	output, err := r.runPodman(ctx, "volume", "ls", "--format", "{{.Name}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	var volumes []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, prefix) {
			volumes = append(volumes, line)
		}
	}

	return volumes, nil
}

// Commit saves the current container state as a new image
func (r *Runtime) Commit(ctx context.Context, container, image string) (string, error) {
	output, err := r.runPodman(ctx, "commit", container, image)
	if err != nil {
		return "", fmt.Errorf("failed to commit container: %w", err)
	}
	return strings.TrimSpace(output), nil
}

// runPodman executes a podman command and returns output
func (r *Runtime) runPodman(ctx context.Context, args ...string) (string, error) {
	// Prepend connection if specified
	if r.Connection != "" {
		args = append([]string{"--connection", r.Connection}, args...)
	}

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
func (r *Runtime) runPodmanInteractive(ctx context.Context, args ...string) error {
	if r.Connection != "" {
		args = append([]string{"--connection", r.Connection}, args...)
	}

	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// CheckInstalled verifies that podman is available
func CheckInstalled() error {
	cmd := exec.Command("podman", "--version")
	if err := cmd.Run(); err != nil {
		return runtime.ErrNotInstalled{Runtime: runtime.BackendPodman}
	}
	return nil
}
