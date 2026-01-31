package container

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jurajpiar/devkit/internal/config"
)

// ProxyManager handles the debug proxy container lifecycle
type ProxyManager struct {
	config      *config.Config
	networkName string
}

// NewProxyManager creates a new ProxyManager
func NewProxyManager(cfg *config.Config) *ProxyManager {
	return &ProxyManager{
		config:      cfg,
		networkName: cfg.ContainerName() + "-network",
	}
}

// ProxyContainerName returns the name of the proxy container
func (p *ProxyManager) ProxyContainerName() string {
	return p.config.ContainerName() + "-debugproxy"
}

// NetworkName returns the name of the internal network
func (p *ProxyManager) NetworkName() string {
	return p.networkName
}

// CreateNetwork creates the internal network for proxy <-> dev container communication
func (p *ProxyManager) CreateNetwork(ctx context.Context) error {
	// Check if network already exists
	cmd := exec.CommandContext(ctx, "podman", "network", "exists", p.networkName)
	if err := cmd.Run(); err == nil {
		return nil // Network already exists
	}

	// Create internal network (no external access)
	cmd = exec.CommandContext(ctx, "podman", "network", "create", "--internal", p.networkName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create network: %s", stderr.String())
	}

	return nil
}

// RemoveNetwork removes the internal network
func (p *ProxyManager) RemoveNetwork(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "rm", "-f", p.networkName)
	return cmd.Run()
}

// CreateProxyContainer creates the debug proxy container
func (p *ProxyManager) CreateProxyContainer(ctx context.Context, proxyImage, targetContainer string, filterLevel string) error {
	proxyName := p.ProxyContainerName()

	// Target address is the dev container's name on the internal network
	targetAddr := fmt.Sprintf("%s:9229", targetContainer)

	args := []string{
		"create",
		"--name", proxyName,

		// Security hardening for proxy container
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",

		// Connect to internal network (to reach dev container)
		"--network", p.networkName,

		// Expose proxy port to host (localhost only)
		"--publish", "127.0.0.1:9229:9229",

		// Resource limits (proxy is lightweight)
		"--memory=256m",
		"--pids-limit=64",

		// Image and command
		proxyImage,
		"-listen", ":9229",
		"-target", targetAddr,
		"-filter", filterLevel,
		"-audit",
	}

	cmd := exec.CommandContext(ctx, "podman", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create proxy container: %s", stderr.String())
	}

	return nil
}

// StartProxyContainer starts the debug proxy container
func (p *ProxyManager) StartProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "start", p.ProxyContainerName())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start proxy container: %s", stderr.String())
	}
	return nil
}

// StopProxyContainer stops the debug proxy container
func (p *ProxyManager) StopProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "stop", p.ProxyContainerName())
	return cmd.Run()
}

// RemoveProxyContainer removes the debug proxy container
func (p *ProxyManager) RemoveProxyContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "podman", "rm", "-f", p.ProxyContainerName())
	return cmd.Run()
}

// ProxyExists checks if the proxy container exists
func (p *ProxyManager) ProxyExists(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "podman", "container", "exists", p.ProxyContainerName())
	return cmd.Run() == nil
}

// ProxyIsRunning checks if the proxy container is running
func (p *ProxyManager) ProxyIsRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{.State.Running}}", p.ProxyContainerName())
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return false
	}
	return strings.TrimSpace(stdout.String()) == "true"
}

// ConnectContainerToNetwork connects a container to the internal network
func (p *ProxyManager) ConnectContainerToNetwork(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "connect", p.networkName, containerName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		// Ignore if already connected
		if strings.Contains(errStr, "already exists") || strings.Contains(errStr, "already connected") {
			return nil
		}
		return fmt.Errorf("failed to connect container to network: %s", errStr)
	}
	return nil
}

// DisconnectContainerFromNetwork disconnects a container from the internal network
func (p *ProxyManager) DisconnectContainerFromNetwork(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, "podman", "network", "disconnect", p.networkName, containerName)
	return cmd.Run()
}

// BuildProxyImage builds the debug proxy container image
func (p *ProxyManager) BuildProxyImage(ctx context.Context, contextPath string) (string, error) {
	imageName := "devkit/debugproxy:latest"

	args := []string{
		"build",
		"-t", imageName,
		"-f", contextPath + "/templates/debugproxy.Containerfile",
		contextPath,
	}

	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdout = nil // Could redirect to show progress
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to build proxy image: %s", stderr.String())
	}

	return imageName, nil
}

// ProxyImageExists checks if the proxy image exists
func (p *ProxyManager) ProxyImageExists(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "podman", "image", "exists", "devkit/debugproxy:latest")
	return cmd.Run() == nil
}

// SetupProxyEnvironment sets up the complete proxy environment
func (p *ProxyManager) SetupProxyEnvironment(ctx context.Context, devContainerName, filterLevel string) error {
	// Create internal network
	if err := p.CreateNetwork(ctx); err != nil {
		return fmt.Errorf("failed to create network: %w", err)
	}

	// Check if proxy image exists
	if !p.ProxyImageExists(ctx) {
		return fmt.Errorf("proxy image not found. Run 'devkit build --proxy' first")
	}

	// Create proxy container
	if err := p.CreateProxyContainer(ctx, "devkit/debugproxy:latest", devContainerName, filterLevel); err != nil {
		return fmt.Errorf("failed to create proxy container: %w", err)
	}

	return nil
}

// CleanupProxyEnvironment removes all proxy-related resources
func (p *ProxyManager) CleanupProxyEnvironment(ctx context.Context) error {
	// Stop and remove proxy container (ignore errors)
	p.StopProxyContainer(ctx)
	p.RemoveProxyContainer(ctx)

	// Remove network (ignore errors)
	p.RemoveNetwork(ctx)

	return nil
}

// GetProxyStats retrieves statistics from the running proxy
func (p *ProxyManager) GetProxyStats(ctx context.Context) (string, error) {
	// Execute curl inside the proxy container to get stats
	cmd := exec.CommandContext(ctx, "podman", "exec", p.ProxyContainerName(),
		"wget", "-q", "-O-", "http://localhost:9229/stats")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get proxy stats: %w", err)
	}

	return stdout.String(), nil
}
