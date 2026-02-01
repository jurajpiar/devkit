package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/runtime"
	"github.com/jurajpiar/devkit/internal/runtime/lima"
	"github.com/jurajpiar/devkit/internal/runtime/podman"
	"github.com/spf13/cobra"
)

var runtimeCmd = &cobra.Command{
	Use:   "runtime",
	Short: "Manage container runtime backend",
	Long: `Manage the container runtime backend (Podman, Lima).

Examples:
  devkit runtime status     Show current runtime status
  devkit runtime switch     Switch between backends
  devkit runtime doctor     Diagnose runtime issues
  devkit runtime install    Install the configured runtime`,
}

var runtimeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current runtime status",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := config.LoadOrDefault(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Determine backend
		backend := runtime.Backend(cfg.Runtime.Backend)
		if backend == "" {
			backend = runtime.BackendPodman
		}

		fmt.Printf("Runtime Backend: %s\n", backend)
		fmt.Printf("Double Isolation: %v\n", cfg.RequiresDoubleIsolation())
		fmt.Println()

		// Check installation status
		podmanInstalled := runtime.IsInstalled(runtime.BackendPodman)
		limaInstalled := runtime.IsInstalled(runtime.BackendLima)

		fmt.Println("Available Backends:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  Backend\tInstalled\tStatus\n")
		fmt.Fprintf(w, "  ------\t---------\t------\n")

		// Podman status
		podmanStatus := "not installed"
		if podmanInstalled {
			podmanStatus = "ready"
			if backend == runtime.BackendPodman {
				// Check VM status
				vmMgr := podman.NewVMManager()
				vms, _ := vmMgr.List(ctx)
				runningCount := 0
				for _, vm := range vms {
					if vm.Status == "running" {
						runningCount++
					}
				}
				if runningCount > 0 {
					podmanStatus = fmt.Sprintf("ready (%d VMs running)", runningCount)
				}
			}
		}
		currentMark := ""
		if backend == runtime.BackendPodman {
			currentMark = " (current)"
		}
		fmt.Fprintf(w, "  podman\t%v\t%s%s\n", podmanInstalled, podmanStatus, currentMark)

		// Lima status
		limaStatus := "not installed"
		if limaInstalled {
			limaStatus = "ready"
			if backend == runtime.BackendLima {
				vmMgr := lima.NewVMManager()
				vms, _ := vmMgr.List(ctx)
				runningCount := 0
				for _, vm := range vms {
					if vm.Status == "Running" {
						runningCount++
					}
				}
				if runningCount > 0 {
					limaStatus = fmt.Sprintf("ready (%d VMs running)", runningCount)
				}
			}
		}
		currentMark = ""
		if backend == runtime.BackendLima {
			currentMark = " (current)"
		}
		fmt.Fprintf(w, "  lima\t%v\t%s%s\n", limaInstalled, limaStatus, currentMark)

		w.Flush()
	},
}

var runtimeSwitchCmd = &cobra.Command{
	Use:   "switch [podman|lima]",
	Short: "Switch runtime backend",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		newBackend := args[0]
		if newBackend != "podman" && newBackend != "lima" {
			fmt.Fprintf(os.Stderr, "Error: invalid backend '%s' (must be 'podman' or 'lima')\n", newBackend)
			os.Exit(1)
		}

		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := config.LoadOrDefault(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Check if runtime is installed
		backend := runtime.Backend(newBackend)
		if !runtime.IsInstalled(backend) {
			fmt.Printf("Runtime '%s' is not installed.\n", newBackend)
			fmt.Printf("Run: devkit runtime install %s\n", newBackend)
			os.Exit(1)
		}

		// Update config
		cfg.Runtime.Backend = newBackend
		if err := cfg.Save(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Switched runtime backend to: %s\n", newBackend)
		fmt.Println()
		fmt.Println("Note: Existing containers may need to be recreated.")
		fmt.Println("Run: devkit rm && devkit start")
	},
}

var runtimeDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose runtime issues",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := config.LoadOrDefault(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		backend := runtime.Backend(cfg.Runtime.Backend)
		if backend == "" {
			backend = runtime.BackendPodman
		}

		factory := runtime.NewFactory(backend)
		installer, err := factory.GetInstaller(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Running diagnostics for: %s\n\n", backend)

		results := installer.Doctor(ctx)
		hasErrors := false

		for _, result := range results {
			var statusIcon string
			switch result.Status {
			case runtime.DiagnosticOK:
				statusIcon = "✓"
			case runtime.DiagnosticWarning:
				statusIcon = "⚠"
			case runtime.DiagnosticError:
				statusIcon = "✗"
				hasErrors = true
			}

			fmt.Printf("%s %s", statusIcon, result.Check)
			if result.Message != "" {
				fmt.Printf(": %s", result.Message)
			}
			fmt.Println()

			if result.Fix != "" && result.Status != runtime.DiagnosticOK {
				fmt.Printf("  Fix: %s\n", result.Fix)
			}
		}

		if hasErrors {
			os.Exit(1)
		}
	},
}

var runtimeInstallCmd = &cobra.Command{
	Use:   "install [podman|lima]",
	Short: "Install a runtime backend",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		var backend runtime.Backend
		if len(args) > 0 {
			backend = runtime.Backend(args[0])
		} else {
			// Use configured backend or detect best
			configPath, _ := cmd.Flags().GetString("config")
			cfg, _ := config.LoadOrDefault(configPath)
			if cfg != nil && cfg.Runtime.Backend != "" {
				backend = runtime.Backend(cfg.Runtime.Backend)
			} else {
				backend = runtime.DetectBestBackend(ctx)
			}
		}

		if backend != runtime.BackendPodman && backend != runtime.BackendLima {
			fmt.Fprintf(os.Stderr, "Error: invalid backend '%s'\n", backend)
			os.Exit(1)
		}

		factory := runtime.NewFactory(backend)
		installer, err := factory.GetInstaller(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if installer.IsInstalled(ctx) {
			version, _ := installer.Version(ctx)
			fmt.Printf("%s is already installed: %s\n", backend, version)
			return
		}

		fmt.Printf("Installing %s...\n", backend)
		if err := installer.Install(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing %s: %v\n", backend, err)
			os.Exit(1)
		}

		version, _ := installer.Version(ctx)
		fmt.Printf("Successfully installed %s: %s\n", backend, version)
	},
}

func init() {
	rootCmd.AddCommand(runtimeCmd)
	runtimeCmd.AddCommand(runtimeStatusCmd)
	runtimeCmd.AddCommand(runtimeSwitchCmd)
	runtimeCmd.AddCommand(runtimeDoctorCmd)
	runtimeCmd.AddCommand(runtimeInstallCmd)
}
