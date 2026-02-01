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

var vmCmd = &cobra.Command{
	Use:   "vm",
	Short: "Manage virtual machines",
	Long: `Manage devkit virtual machines (abstracted across Podman and Lima).

Examples:
  devkit vm list       List all devkit VMs
  devkit vm start      Start a VM
  devkit vm stop       Stop a VM
  devkit vm remove     Remove a VM`,
}

var vmListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all devkit VMs",
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

		var vms []runtime.VMInfo

		switch backend {
		case runtime.BackendPodman:
			vmMgr := podman.NewVMManager()
			vms, err = vmMgr.List(ctx)
		case runtime.BackendLima:
			vmMgr := lima.NewVMManager()
			vms, err = vmMgr.List(ctx)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported backend '%s'\n", backend)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing VMs: %v\n", err)
			os.Exit(1)
		}

		if len(vms) == 0 {
			fmt.Printf("No devkit VMs found (backend: %s)\n", backend)
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "NAME\tSTATUS\tCPUS\tMEMORY\tDISK\tTYPE\n")
		for _, vm := range vms {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
				vm.Name, vm.Status, vm.CPUs, vm.Memory, vm.Disk, vm.VMType)
		}
		w.Flush()
	},
}

var vmStartCmd = &cobra.Command{
	Use:   "start [name]",
	Short: "Start a VM",
	Args:  cobra.MaximumNArgs(1),
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

		var vmName string
		if len(args) > 0 {
			vmName = args[0]
		} else {
			vmName = cfg.VMName()
		}

		fmt.Printf("Starting VM '%s'...\n", vmName)

		switch backend {
		case runtime.BackendPodman:
			vmMgr := podman.NewVMManager()
			err = vmMgr.Start(ctx, vmName)
		case runtime.BackendLima:
			vmMgr := lima.NewVMManager()
			err = vmMgr.Start(ctx, vmName)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported backend '%s'\n", backend)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting VM: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("VM '%s' started\n", vmName)
	},
}

var vmStopCmd = &cobra.Command{
	Use:   "stop [name]",
	Short: "Stop a VM",
	Args:  cobra.MaximumNArgs(1),
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

		var vmName string
		if len(args) > 0 {
			vmName = args[0]
		} else {
			vmName = cfg.VMName()
		}

		fmt.Printf("Stopping VM '%s'...\n", vmName)

		switch backend {
		case runtime.BackendPodman:
			vmMgr := podman.NewVMManager()
			err = vmMgr.Stop(ctx, vmName)
		case runtime.BackendLima:
			vmMgr := lima.NewVMManager()
			err = vmMgr.Stop(ctx, vmName)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported backend '%s'\n", backend)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping VM: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("VM '%s' stopped\n", vmName)
	},
}

var vmRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a VM",
	Aliases: []string{"rm"},
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		force, _ := cmd.Flags().GetBool("force")

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

		var vmName string
		if len(args) > 0 {
			vmName = args[0]
		} else {
			vmName = cfg.VMName()
		}

		fmt.Printf("Removing VM '%s'...\n", vmName)

		switch backend {
		case runtime.BackendPodman:
			vmMgr := podman.NewVMManager()
			err = vmMgr.Remove(ctx, vmName, force)
		case runtime.BackendLima:
			vmMgr := lima.NewVMManager()
			err = vmMgr.Remove(ctx, vmName, force)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported backend '%s'\n", backend)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error removing VM: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("VM '%s' removed\n", vmName)
	},
}

var vmCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new VM",
	Args:  cobra.MaximumNArgs(1),
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

		var vmName string
		if len(args) > 0 {
			vmName = args[0]
		} else {
			vmName = cfg.VMName()
		}

		// Build VM options from config
		opts := runtime.VMOpts{
			CPUs:       cfg.Runtime.Lima.CPUs,
			MemoryMB:   cfg.Runtime.Lima.MemoryGB * 1024,
			DiskSizeGB: cfg.Runtime.Lima.DiskGB,
			VMType:     cfg.Runtime.Lima.VMType,
		}

		fmt.Printf("Creating VM '%s'...\n", vmName)

		switch backend {
		case runtime.BackendPodman:
			vmMgr := podman.NewVMManager()
			err = vmMgr.Create(ctx, vmName, opts)
		case runtime.BackendLima:
			vmMgr := lima.NewVMManager()
			err = vmMgr.Create(ctx, vmName, opts)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported backend '%s'\n", backend)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating VM: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("VM '%s' created\n", vmName)
	},
}

func init() {
	rootCmd.AddCommand(vmCmd)
	vmCmd.AddCommand(vmListCmd)
	vmCmd.AddCommand(vmStartCmd)
	vmCmd.AddCommand(vmStopCmd)
	vmCmd.AddCommand(vmRemoveCmd)
	vmCmd.AddCommand(vmCreateCmd)

	vmRemoveCmd.Flags().BoolP("force", "f", false, "Force remove even if running")
}
