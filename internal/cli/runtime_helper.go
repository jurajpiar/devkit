package cli

import (
	"context"
	"fmt"
	goruntime "runtime"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/machine"
	"github.com/jurajpiar/devkit/internal/runtime"
	"github.com/jurajpiar/devkit/internal/runtime/lima"
	"github.com/jurajpiar/devkit/internal/runtime/podman"
)

// RuntimeContext holds the runtime and VM manager for CLI operations
type RuntimeContext struct {
	Backend   runtime.Backend
	Runtime   runtime.Runtime
	VMManager runtime.VMManager
	VMName    string
	Config    *config.Config
}

// SetupRuntime sets up the appropriate runtime based on configuration
// Returns a RuntimeContext that can be used for container operations
func SetupRuntime(ctx context.Context, cfg *config.Config) (*RuntimeContext, error) {
	backend := runtime.Backend(cfg.Runtime.Backend)
	if backend == "" {
		backend = runtime.BackendPodman // Default
	}

	rc := &RuntimeContext{
		Backend: backend,
		Config:  cfg,
		VMName:  cfg.VMName(),
	}

	switch backend {
	case runtime.BackendLima:
		return setupLimaRuntime(ctx, cfg, rc)
	case runtime.BackendPodman:
		return setupPodmanRuntime(ctx, cfg, rc)
	default:
		return nil, fmt.Errorf("unsupported runtime backend: %s", backend)
	}
}

// setupLimaRuntime sets up Lima runtime
func setupLimaRuntime(ctx context.Context, cfg *config.Config, rc *RuntimeContext) (*RuntimeContext, error) {
	// Check Lima is installed
	if err := lima.CheckInstalled(); err != nil {
		return nil, fmt.Errorf("Lima is not installed. Run: devkit runtime install lima")
	}

	vmMgr := lima.NewVMManager()
	rc.VMManager = vmMgr

	// Ensure VM exists and is running
	vmName := cfg.VMName()
	rc.VMName = vmName

	opts := runtime.VMOpts{
		CPUs:       cfg.Runtime.Lima.CPUs,
		MemoryMB:   cfg.Runtime.Lima.MemoryGB * 1024,
		DiskSizeGB: cfg.Runtime.Lima.DiskGB,
		VMType:     cfg.Runtime.Lima.VMType,
	}

	fmt.Printf("Using Lima VM: %s\n", vmName)
	if err := vmMgr.EnsureRunning(ctx, vmName, opts); err != nil {
		return nil, fmt.Errorf("failed to setup Lima VM: %w", err)
	}

	// Create Lima runtime
	rc.Runtime = lima.NewRuntime(vmName)

	return rc, nil
}

// setupPodmanRuntime sets up Podman runtime
func setupPodmanRuntime(ctx context.Context, cfg *config.Config, rc *RuntimeContext) (*RuntimeContext, error) {
	// Check Podman is installed
	if err := podman.CheckInstalled(); err != nil {
		return nil, fmt.Errorf("Podman is not installed. Run: devkit runtime install podman")
	}

	// On macOS/Windows, need a Podman machine
	if goruntime.GOOS == "darwin" || goruntime.GOOS == "windows" {
		vmMgr := podman.NewVMManager()
		rc.VMManager = vmMgr

		// Handle total isolation (dedicated machine per project)
		if cfg.Security.TotalIsolation {
			vmName := cfg.DedicatedMachineName()
			rc.VMName = vmName

			fmt.Println("=== TOTAL ISOLATION MODE ===")
			fmt.Printf("Running project in dedicated VM: %s\n", vmName)
			fmt.Println("- Container escape confined to dedicated VM")
			fmt.Println("- No shared kernel with other projects")
			fmt.Println()

			opts := runtime.VMOpts{
				CPUs:       cfg.Runtime.Lima.CPUs, // Reuse Lima opts
				MemoryMB:   cfg.Runtime.Lima.MemoryGB * 1024,
				DiskSizeGB: cfg.Runtime.Lima.DiskGB,
			}

			if err := vmMgr.EnsureRunning(ctx, vmName, opts); err != nil {
				return nil, fmt.Errorf("failed to setup dedicated machine: %w", err)
			}
			fmt.Printf("Dedicated machine '%s' is ready\n\n", vmName)
		} else {
			// Use shared Podman machine
			machineMgr := machine.New()
			running, name, _ := machineMgr.GetRunningMachine(ctx)
			if !running {
				fmt.Println("No Podman machine is running. Starting default machine...")
				if err := machineMgr.EnsureRunning(ctx); err != nil {
					return nil, fmt.Errorf("failed to start Podman machine: %w\n\nTry: podman machine start", err)
				}
				fmt.Println()
			} else {
				// Ensure we're using the running machine as default
				machineMgr.SetDefaultNamed(ctx, name)
				rc.VMName = name
			}
		}
	}

	// Create Podman runtime
	rc.Runtime = podman.NewRuntime(rc.VMName)

	return rc, nil
}

// EnsureRuntimeReady ensures the runtime is ready for operations
// This is a lighter check that doesn't start VMs
func EnsureRuntimeReady(ctx context.Context, cfg *config.Config) error {
	backend := runtime.Backend(cfg.Runtime.Backend)
	if backend == "" {
		backend = runtime.BackendPodman
	}

	switch backend {
	case runtime.BackendLima:
		return lima.CheckInstalled()
	case runtime.BackendPodman:
		return podman.CheckInstalled()
	default:
		return fmt.Errorf("unsupported runtime backend: %s", backend)
	}
}
