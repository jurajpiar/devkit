package runtime

import (
	"context"
	"fmt"
	"os/exec"
	goruntime "runtime"
	"strings"
)

// Factory creates runtime and VM manager instances based on configuration
type Factory struct {
	backend      Backend
	vmName       string
	limaOpts     VMOpts
	podmanMachine string
}

// NewFactory creates a new runtime factory with the given backend
func NewFactory(backend Backend) *Factory {
	return &Factory{
		backend: backend,
	}
}

// WithVMName sets the VM name
func (f *Factory) WithVMName(name string) *Factory {
	f.vmName = name
	return f
}

// WithLimaOpts sets Lima-specific options
func (f *Factory) WithLimaOpts(opts VMOpts) *Factory {
	f.limaOpts = opts
	return f
}

// WithPodmanMachine sets the Podman machine name
func (f *Factory) WithPodmanMachine(name string) *Factory {
	f.podmanMachine = name
	return f
}

// Backend returns the configured backend
func (f *Factory) Backend() Backend {
	return f.backend
}

// VMName returns the configured VM name
func (f *Factory) VMName() string {
	return f.vmName
}

// GetInstaller returns the appropriate Installer implementation
func (f *Factory) GetInstaller(ctx context.Context) (Installer, error) {
	switch f.backend {
	case BackendPodman:
		return &PodmanInstaller{}, nil
	case BackendLima:
		return &LimaInstaller{}, nil
	case BackendDocker:
		return nil, fmt.Errorf("docker installer not yet implemented")
	default:
		return nil, fmt.Errorf("unknown runtime backend: %s", f.backend)
	}
}

// DetectBestBackend detects the best available runtime backend
func DetectBestBackend(ctx context.Context) Backend {
	// Prefer Lima if installed (better isolation)
	if isLimaInstalled() {
		return BackendLima
	}
	// Fall back to Podman
	if isPodmanInstalled() {
		return BackendPodman
	}
	// Default to Lima (will prompt for install)
	return BackendLima
}

// EnsureRuntime ensures the runtime is installed, prompting if needed
func EnsureRuntime(ctx context.Context, backend Backend) error {
	var installer Installer
	switch backend {
	case BackendPodman:
		installer = &PodmanInstaller{}
	case BackendLima:
		installer = &LimaInstaller{}
	default:
		return fmt.Errorf("unsupported backend: %s", backend)
	}

	if installer.IsInstalled(ctx) {
		return nil
	}

	return ErrNotInstalled{Runtime: backend}
}

// IsInstalled checks if the given backend is installed
func IsInstalled(backend Backend) bool {
	switch backend {
	case BackendPodman:
		return isPodmanInstalled()
	case BackendLima:
		return isLimaInstalled()
	default:
		return false
	}
}

// isLimaInstalled checks if Lima is installed
func isLimaInstalled() bool {
	_, err := exec.LookPath("limactl")
	return err == nil
}

// isPodmanInstalled checks if Podman is installed
func isPodmanInstalled() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

// PodmanInstaller handles Podman installation
type PodmanInstaller struct{}

func (i *PodmanInstaller) Name() Backend { return BackendPodman }

func (i *PodmanInstaller) IsInstalled(ctx context.Context) bool {
	return isPodmanInstalled()
}

func (i *PodmanInstaller) Install(ctx context.Context) error {
	if goruntime.GOOS != "darwin" {
		return fmt.Errorf("auto-install only supported on macOS")
	}
	// Check for Homebrew
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("homebrew not found. Install it first: https://brew.sh")
	}
	cmd := exec.CommandContext(ctx, "brew", "install", "podman")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func (i *PodmanInstaller) Uninstall(ctx context.Context) error {
	if goruntime.GOOS != "darwin" {
		return fmt.Errorf("auto-uninstall only supported on macOS")
	}
	cmd := exec.CommandContext(ctx, "brew", "uninstall", "podman")
	return cmd.Run()
}

func (i *PodmanInstaller) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (i *PodmanInstaller) Doctor(ctx context.Context) []DiagnosticResult {
	results := make([]DiagnosticResult, 0)

	// Check podman installed
	if !i.IsInstalled(ctx) {
		results = append(results, DiagnosticResult{
			Check:   "Podman installed",
			Status:  DiagnosticError,
			Message: "Podman is not installed",
			Fix:     "devkit setup --runtime podman",
		})
		return results
	}
	results = append(results, DiagnosticResult{
		Check:  "Podman installed",
		Status: DiagnosticOK,
	})

	// Check podman machine
	cmd := exec.CommandContext(ctx, "podman", "machine", "list", "--format", "{{.Name}}")
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		results = append(results, DiagnosticResult{
			Check:   "Podman machine exists",
			Status:  DiagnosticError,
			Message: "No Podman machine found",
			Fix:     "devkit start",
		})
	} else {
		results = append(results, DiagnosticResult{
			Check:  "Podman machine exists",
			Status: DiagnosticOK,
		})
	}

	return results
}

// LimaInstaller handles Lima installation
type LimaInstaller struct{}

func (i *LimaInstaller) Name() Backend { return BackendLima }

func (i *LimaInstaller) IsInstalled(ctx context.Context) bool {
	return isLimaInstalled()
}

func (i *LimaInstaller) Install(ctx context.Context) error {
	if goruntime.GOOS != "darwin" {
		return fmt.Errorf("Lima is only supported on macOS")
	}
	// Check for Homebrew
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("homebrew not found. Install it first: https://brew.sh")
	}
	cmd := exec.CommandContext(ctx, "brew", "install", "lima")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func (i *LimaInstaller) Uninstall(ctx context.Context) error {
	if goruntime.GOOS != "darwin" {
		return fmt.Errorf("Lima is only supported on macOS")
	}
	cmd := exec.CommandContext(ctx, "brew", "uninstall", "lima")
	return cmd.Run()
}

func (i *LimaInstaller) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "limactl", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (i *LimaInstaller) Doctor(ctx context.Context) []DiagnosticResult {
	results := make([]DiagnosticResult, 0)

	// Check lima installed
	if !i.IsInstalled(ctx) {
		results = append(results, DiagnosticResult{
			Check:   "Lima installed",
			Status:  DiagnosticError,
			Message: "Lima is not installed",
			Fix:     "devkit setup --runtime lima",
		})
		return results
	}
	results = append(results, DiagnosticResult{
		Check:  "Lima installed",
		Status: DiagnosticOK,
	})

	// Check lima VMs
	cmd := exec.CommandContext(ctx, "limactl", "list", "--format", "{{.Name}}")
	out, err := cmd.Output()
	if err != nil {
		results = append(results, DiagnosticResult{
			Check:   "Lima accessible",
			Status:  DiagnosticError,
			Message: "Cannot access Lima: " + err.Error(),
			Fix:     "Check Lima installation",
		})
	} else {
		results = append(results, DiagnosticResult{
			Check:   "Lima accessible",
			Status:  DiagnosticOK,
			Message: fmt.Sprintf("Found %d VMs", len(strings.Split(strings.TrimSpace(string(out)), "\n"))),
		})
	}

	return results
}
