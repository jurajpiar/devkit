package container

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jurajpiar/devkit/internal/config"
)

// EgressProxyManager handles the egress proxy container lifecycle
type EgressProxyManager struct {
	config      *config.Config
	networkName string
}

// NewEgressProxyManager creates a new EgressProxyManager
func NewEgressProxyManager(cfg *config.Config) *EgressProxyManager {
	return &EgressProxyManager{
		config:      cfg,
		networkName: cfg.ContainerName() + "-egress-network",
	}
}

// ProxyContainerName returns the name of the egress proxy container
func (e *EgressProxyManager) ProxyContainerName() string {
	return e.config.ContainerName() + "-egressproxy"
}

// NetworkName returns the name of the egress network
func (e *EgressProxyManager) NetworkName() string {
	return e.networkName
}

// ProxyPort returns the proxy port (inside the container)
func (e *EgressProxyManager) ProxyPort() int {
	if e.config.Security.EgressProxy.Port > 0 {
		return e.config.Security.EgressProxy.Port
	}
	return 3128 // Default Squid/proxy port
}

// CreateNetwork creates the egress network for proxy <-> dev container communication
func (e *EgressProxyManager) CreateNetwork(ctx context.Context) error {
	// Check if network already exists
	cmd := exec.CommandContext(ctx, "podman", "network", "exists", e.networkName)
	if err := cmd.Run(); err == nil {
		return nil // Network already exists
	}

	// Create network - NOT internal, so proxy can reach the internet
	cmd = exec.CommandContext(ctx, "podman", "network", "create", e.networkName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create egress network: %s", stderr.String())
	}

	return nil
}

// RemoveNetwork removes the egress network
func (e *EgressProxyManager) RemoveNetwork(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "rm", "-f", e.networkName)
	return cmd.Run()
}

// CreateProxyContainer creates the egress proxy container
func (e *EgressProxyManager) CreateProxyContainer(ctx context.Context, proxyImage string) error {
	proxyName := e.ProxyContainerName()
	proxyPort := e.ProxyPort()

	// Build allowed hosts argument
	allowedHosts := strings.Join(e.config.Security.EgressProxy.AllowedHosts, ",")

	args := []string{
		"create",
		"--name", proxyName,

		// Security hardening for proxy container
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",

		// Connect to egress network (allows internet access)
		"--network", e.networkName,

		// Resource limits (proxy is lightweight)
		"--memory=256m",
		"--pids-limit=64",

		// Image and command
		proxyImage,
		"-listen", fmt.Sprintf(":%d", proxyPort),
		"-allowed", allowedHosts,
	}

	// Add audit flag if enabled
	if e.config.Security.EgressProxy.AuditLog {
		args = append(args, "-audit")
	}

	cmd := exec.CommandContext(ctx, "podman", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create egress proxy container: %s", stderr.String())
	}

	return nil
}

// StartProxyContainer starts the egress proxy container
func (e *EgressProxyManager) StartProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "start", e.ProxyContainerName())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start egress proxy container: %s", stderr.String())
	}
	return nil
}

// StopProxyContainer stops the egress proxy container
func (e *EgressProxyManager) StopProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "stop", e.ProxyContainerName())
	return cmd.Run()
}

// RemoveProxyContainer removes the egress proxy container
func (e *EgressProxyManager) RemoveProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "rm", "-f", e.ProxyContainerName())
	return cmd.Run()
}

// ProxyExists checks if the proxy container exists
func (e *EgressProxyManager) ProxyExists(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "podman", "container", "exists", e.ProxyContainerName())
	return cmd.Run() == nil
}

// ProxyIsRunning checks if the proxy container is running
func (e *EgressProxyManager) ProxyIsRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{.State.Running}}", e.ProxyContainerName())
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return false
	}
	return strings.TrimSpace(stdout.String()) == "true"
}

// ConnectContainerToNetwork connects a container to the egress network
func (e *EgressProxyManager) ConnectContainerToNetwork(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "connect", e.networkName, containerName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		// Ignore if already connected
		if strings.Contains(errStr, "already") {
			return nil
		}
		return fmt.Errorf("failed to connect container to egress network: %s", errStr)
	}
	return nil
}

// DisconnectContainerFromNetwork disconnects a container from the egress network
func (e *EgressProxyManager) DisconnectContainerFromNetwork(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "disconnect", e.networkName, containerName)
	return cmd.Run()
}

// GetProxyAddress returns the proxy address for use in HTTP_PROXY environment variable
func (e *EgressProxyManager) GetProxyAddress() string {
	return fmt.Sprintf("http://%s:%d", e.ProxyContainerName(), e.ProxyPort())
}

// GetProxyEnvVars returns environment variables to configure the dev container to use the proxy
func (e *EgressProxyManager) GetProxyEnvVars() map[string]string {
	proxyAddr := e.GetProxyAddress()
	return map[string]string{
		"HTTP_PROXY":  proxyAddr,
		"HTTPS_PROXY": proxyAddr,
		"http_proxy":  proxyAddr,
		"https_proxy": proxyAddr,
		// Don't proxy localhost connections
		"NO_PROXY":  "localhost,127.0.0.1",
		"no_proxy":  "localhost,127.0.0.1",
	}
}

// ProxyImageExists checks if the egress proxy image exists
func (e *EgressProxyManager) ProxyImageExists(ctx context.Context) bool {
	imageName := e.ProxyImageName()
	cmd := exec.CommandContext(ctx, "podman", "image", "exists", imageName)
	return cmd.Run() == nil
}

// ProxyImageName returns the egress proxy image name
func (e *EgressProxyManager) ProxyImageName() string {
	return "devkit/egressproxy:latest"
}

// Cleanup removes all egress proxy resources
func (e *EgressProxyManager) Cleanup(ctx context.Context) error {
	// Stop and remove proxy container
	_ = e.StopProxyContainer(ctx)
	_ = e.RemoveProxyContainer(ctx)

	// Remove network
	return e.RemoveNetwork(ctx)
}
