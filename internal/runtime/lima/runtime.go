package lima

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

// Runtime implements the runtime.Runtime interface using Lima VMs with nerdctl
type Runtime struct {
	// VMName is the Lima VM to use
	VMName string
	// vm is the VM manager
	vm *VMManager
}

// NewRuntime creates a new Lima runtime for a specific VM
func NewRuntime(vmName string) *Runtime {
	return &Runtime{
		VMName: vmName,
		vm:     NewVMManager(),
	}
}

// Name returns the runtime backend name
func (r *Runtime) Name() runtime.Backend {
	return runtime.BackendLima
}

// Create creates a new container in the Lima VM
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

	output, err := r.runNerdctl(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// Start starts an existing container
func (r *Runtime) Start(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "start", name)
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	return nil
}

// Stop stops a running container
func (r *Runtime) Stop(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "stop", name)
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}
	return nil
}

// Remove removes a container
func (r *Runtime) Remove(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}
	return nil
}

// Kill forcefully stops a container
func (r *Runtime) Kill(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "kill", name)
	if err != nil {
		return fmt.Errorf("failed to kill container: %w", err)
	}
	return nil
}

// Exec executes a command inside the container
func (r *Runtime) Exec(ctx context.Context, name string, cmd ...string) (string, error) {
	args := append([]string{"exec", name}, cmd...)
	output, err := r.runNerdctl(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %w", err)
	}
	return output, nil
}

// ExecAsUser executes a command as a specific user
func (r *Runtime) ExecAsUser(ctx context.Context, name, user string, cmd ...string) (string, error) {
	args := append([]string{"exec", "-u", user, name}, cmd...)
	output, err := r.runNerdctl(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %w", err)
	}
	return output, nil
}

// ExecInteractive runs an interactive command in the container
func (r *Runtime) ExecInteractive(ctx context.Context, name string, cmd ...string) error {
	args := append([]string{"exec", "-it", name}, cmd...)
	return r.runNerdctlInteractive(ctx, args...)
}

// Exists checks if the container exists
func (r *Runtime) Exists(ctx context.Context, name string) (bool, error) {
	_, err := r.runNerdctl(ctx, "inspect", name)
	return err == nil, nil
}

// IsRunning checks if the container is running
func (r *Runtime) IsRunning(ctx context.Context, name string) (bool, error) {
	output, err := r.runNerdctl(ctx, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(output) == "true", nil
}

// GetInfo returns information about the container
func (r *Runtime) GetInfo(ctx context.Context, name string) (*runtime.ContainerInfo, error) {
	output, err := r.runNerdctl(ctx, "inspect", name)
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

	if image, ok := data["Image"].(string); ok {
		info.Image = image
	}

	return info, nil
}

// List returns all containers matching the devkit prefix
func (r *Runtime) List(ctx context.Context) ([]runtime.ContainerInfo, error) {
	output, err := r.runNerdctl(ctx, "ps", "-a", "--filter", "name=devkit-", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if strings.TrimSpace(output) == "" {
		return []runtime.ContainerInfo{}, nil
	}

	// nerdctl outputs one JSON object per line
	var result []runtime.ContainerInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var c map[string]interface{}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}

		info := runtime.ContainerInfo{
			ID:     c["ID"].(string)[:12],
			Name:   c["Names"].(string),
			Image:  c["Image"].(string),
			Status: c["Status"].(string),
		}
		result = append(result, info)
	}

	return result, nil
}

// CopyTo copies files from host to container
func (r *Runtime) CopyTo(ctx context.Context, name, src, dst string) error {
	// First copy to VM, then to container using exec pipe
	// nerdctl cp doesn't work well with read-only containers
	vmTempPath := "/tmp/devkit-copy-" + fmt.Sprintf("%d", os.Getpid())

	// Copy to VM
	if err := r.copyToVM(ctx, src, vmTempPath); err != nil {
		return fmt.Errorf("failed to copy to VM: %w", err)
	}

	// Copy from VM to container using cat pipe through exec
	// This works with read-only containers since we're writing to tmpfs
	shellCmd := fmt.Sprintf("cat %s | sudo nerdctl exec -i %s sh -c 'cat > %s'", vmTempPath, name, dst)
	_, err := r.vm.Shell(ctx, r.VMName, "bash", "-c", shellCmd)
	if err != nil {
		r.vm.Shell(ctx, r.VMName, "rm", "-rf", vmTempPath)
		return fmt.Errorf("failed to copy to container: %w", err)
	}

	// Cleanup VM temp
	r.vm.Shell(ctx, r.VMName, "rm", "-rf", vmTempPath)

	return nil
}

// CopyFrom copies files from container to host
func (r *Runtime) CopyFrom(ctx context.Context, name, src, dst string) error {
	vmTempPath := "/tmp/devkit-copy-" + fmt.Sprintf("%d", os.Getpid())

	// Copy from container to VM
	_, err := r.runNerdctl(ctx, "cp", fmt.Sprintf("%s:%s", name, src), vmTempPath)
	if err != nil {
		return fmt.Errorf("failed to copy from container: %w", err)
	}

	// Copy from VM to host
	if err := r.copyFromVM(ctx, vmTempPath, dst); err != nil {
		return fmt.Errorf("failed to copy from VM: %w", err)
	}

	// Cleanup VM temp
	r.vm.Shell(ctx, r.VMName, "rm", "-rf", vmTempPath)

	return nil
}

// Build builds a container image
func (r *Runtime) Build(ctx context.Context, opts runtime.BuildOpts) error {
	// First, copy context to VM
	vmContextPath := "/tmp/devkit-build-" + fmt.Sprintf("%d", os.Getpid())
	if err := r.copyToVM(ctx, opts.ContextDir, vmContextPath); err != nil {
		return fmt.Errorf("failed to copy build context to VM: %w", err)
	}
	defer r.vm.Shell(ctx, r.VMName, "rm", "-rf", vmContextPath)

	args := []string{"build"}

	if opts.Dockerfile != "" {
		// Adjust Dockerfile path relative to VM context
		args = append(args, "-f", vmContextPath+"/"+opts.Dockerfile)
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

	args = append(args, vmContextPath)

	_, err := r.runNerdctl(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	return nil
}

// ImageExists checks if an image exists
func (r *Runtime) ImageExists(ctx context.Context, image string) (bool, error) {
	_, err := r.runNerdctl(ctx, "image", "inspect", image)
	return err == nil, nil
}

// RemoveImage removes an image
func (r *Runtime) RemoveImage(ctx context.Context, image string) error {
	_, err := r.runNerdctl(ctx, "rmi", "-f", image)
	if err != nil {
		return fmt.Errorf("failed to remove image: %w", err)
	}
	return nil
}

// CreateVolume creates a named volume
func (r *Runtime) CreateVolume(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "volume", "create", name)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}
	return nil
}

// RemoveVolume removes a named volume
func (r *Runtime) RemoveVolume(ctx context.Context, name string) error {
	_, err := r.runNerdctl(ctx, "volume", "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("failed to remove volume: %w", err)
	}
	return nil
}

// ListVolumes lists volumes with the given prefix
func (r *Runtime) ListVolumes(ctx context.Context, prefix string) ([]string, error) {
	output, err := r.runNerdctl(ctx, "volume", "ls", "--format", "{{.Name}}")
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
	output, err := r.runNerdctl(ctx, "commit", container, image)
	if err != nil {
		return "", fmt.Errorf("failed to commit container: %w", err)
	}
	return strings.TrimSpace(output), nil
}

// runNerdctl executes a nerdctl command inside the Lima VM
func (r *Runtime) runNerdctl(ctx context.Context, args ...string) (string, error) {
	// Ensure VM is running
	running, err := r.vm.IsRunning(ctx, r.VMName)
	if err != nil {
		return "", err
	}
	if !running {
		return "", runtime.ErrVMNotRunning{Name: r.VMName}
	}

	// Build the full command to run in the VM
	// Use sudo for system containerd
	nerdctlCmd := append([]string{"sudo", "nerdctl"}, args...)
	shellArgs := append([]string{"shell", r.VMName, "--"}, nerdctlCmd...)

	cmd := exec.CommandContext(ctx, "limactl", shellArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// runNerdctlInteractive runs nerdctl with interactive terminal
func (r *Runtime) runNerdctlInteractive(ctx context.Context, args ...string) error {
	// Ensure VM is running
	running, err := r.vm.IsRunning(ctx, r.VMName)
	if err != nil {
		return err
	}
	if !running {
		return runtime.ErrVMNotRunning{Name: r.VMName}
	}

	// Use sudo for system containerd
	nerdctlCmd := append([]string{"sudo", "nerdctl"}, args...)
	shellArgs := append([]string{"shell", r.VMName, "--"}, nerdctlCmd...)

	cmd := exec.CommandContext(ctx, "limactl", shellArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// copyToVM copies a file/directory from host to VM
func (r *Runtime) copyToVM(ctx context.Context, src, dst string) error {
	// Check if source is a directory
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}

	if info.IsDir() {
		// For directories, use tar to copy
		// First create the destination directory in VM
		_, err := r.vm.Shell(ctx, r.VMName, "mkdir", "-p", dst)
		if err != nil {
			return fmt.Errorf("failed to create directory in VM: %w", err)
		}

		// Create tarball and pipe to VM
		// tar -C <src> -cf - . | limactl shell <vm> tar -C <dst> -xf -
		tarCmd := exec.CommandContext(ctx, "tar", "-C", src, "-cf", "-", ".")
		limaCmd := exec.CommandContext(ctx, "limactl", "shell", r.VMName, "tar", "-C", dst, "-xf", "-")

		// Pipe tar output to lima
		pipe, err := tarCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create pipe: %w", err)
		}
		limaCmd.Stdin = pipe

		var tarStderr, limaStderr bytes.Buffer
		tarCmd.Stderr = &tarStderr
		limaCmd.Stderr = &limaStderr

		// Start tar
		if err := tarCmd.Start(); err != nil {
			return fmt.Errorf("failed to start tar: %w", err)
		}

		// Start lima
		if err := limaCmd.Start(); err != nil {
			tarCmd.Process.Kill()
			return fmt.Errorf("failed to start lima: %w", err)
		}

		// Wait for both
		tarErr := tarCmd.Wait()
		limaErr := limaCmd.Wait()

		if tarErr != nil {
			return fmt.Errorf("tar failed: %w: %s", tarErr, tarStderr.String())
		}
		if limaErr != nil {
			return fmt.Errorf("lima failed: %w: %s", limaErr, limaStderr.String())
		}

		return nil
	}

	// For files, use limactl copy directly
	cmd := exec.CommandContext(ctx, "limactl", "copy", src, r.VMName+":"+dst)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", err, stderr.String())
	}

	return nil
}

// copyFromVM copies a file/directory from VM to host
func (r *Runtime) copyFromVM(ctx context.Context, src, dst string) error {
	// Use limactl copy
	cmd := exec.CommandContext(ctx, "limactl", "copy", r.VMName+":"+src, dst)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", err, stderr.String())
	}

	return nil
}

// EnsureVMRunning ensures the Lima VM is running
func (r *Runtime) EnsureVMRunning(ctx context.Context, opts runtime.VMOpts) error {
	return r.vm.EnsureRunning(ctx, r.VMName, opts)
}
