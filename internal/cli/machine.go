package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/jurajpiar/devkit/internal/machine"
	"github.com/spf13/cobra"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage the devkit Podman machine",
	Long:  `Manage the dedicated Podman machine used by devkit for container isolation.`,
}

var machineInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the devkit Podman machine",
	Long: `Initialize a dedicated Podman machine for devkit.

This creates an isolated VM for running devkit containers with:
- Rootless operation by default (more secure)
- Configurable CPU, memory, and disk resources
- Dedicated environment separate from your other containers`,
	RunE: runMachineInit,
}

var machineStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the devkit Podman machine",
	RunE:  runMachineStart,
}

var machineStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the devkit Podman machine",
	RunE:  runMachineStop,
}

var machineRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm"},
	Short:   "Remove the devkit Podman machine",
	RunE:    runMachineRemove,
}

var machineStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of the devkit Podman machine",
	RunE:  runMachineStatus,
}

var machineSSHCmd = &cobra.Command{
	Use:   "ssh [command]",
	Short: "SSH into the devkit Podman machine",
	Long:  `Open an SSH session to the devkit Podman machine, or run a command.`,
	RunE:  runMachineSSH,
}

// Machine init flags
var (
	machineCPUs     int
	machineMemoryMB int
	machineDiskGB   int
	machineRootful  bool
	machineForce    bool
)

func init() {
	rootCmd.AddCommand(machineCmd)

	machineCmd.AddCommand(machineInitCmd)
	machineCmd.AddCommand(machineStartCmd)
	machineCmd.AddCommand(machineStopCmd)
	machineCmd.AddCommand(machineRemoveCmd)
	machineCmd.AddCommand(machineStatusCmd)
	machineCmd.AddCommand(machineSSHCmd)

	// Init flags
	machineInitCmd.Flags().IntVar(&machineCPUs, "cpus", machine.DefaultCPUs, "Number of CPUs")
	machineInitCmd.Flags().IntVar(&machineMemoryMB, "memory", machine.DefaultMemoryMB, "Memory in MB")
	machineInitCmd.Flags().IntVar(&machineDiskGB, "disk-size", machine.DefaultDiskSizeGB, "Disk size in GB")
	machineInitCmd.Flags().BoolVar(&machineRootful, "rootful", false, "Create a rootful machine (less secure)")

	// Remove flags
	machineRemoveCmd.Flags().BoolVarP(&machineForce, "force", "f", false, "Force removal even if running")
}

func runMachineInit(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		return err
	}

	if exists {
		fmt.Println("Devkit machine already exists.")
		fmt.Println("Use 'devkit machine remove' to delete it first, or 'devkit machine start' to start it.")
		return nil
	}

	opts := machine.InitOptions{
		CPUs:       machineCPUs,
		MemoryMB:   machineMemoryMB,
		DiskSizeGB: machineDiskGB,
		Rootful:    machineRootful,
	}

	fmt.Printf("Initializing devkit Podman machine...\n")
	fmt.Printf("  CPUs: %d\n", opts.CPUs)
	fmt.Printf("  Memory: %d MB\n", opts.MemoryMB)
	fmt.Printf("  Disk: %d GB\n", opts.DiskSizeGB)
	fmt.Printf("  Rootful: %v\n", opts.Rootful)
	fmt.Println()

	if err := mgr.Init(ctx, opts); err != nil {
		return fmt.Errorf("failed to initialize machine: %w", err)
	}

	fmt.Println("Devkit machine initialized successfully!")
	fmt.Println()
	fmt.Println("Start the machine with: devkit machine start")

	return nil
}

func runMachineStart(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("devkit machine does not exist. Run 'devkit machine init' first")
	}

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		return err
	}

	if running {
		fmt.Println("Devkit machine is already running.")
		return nil
	}

	fmt.Println("Starting devkit Podman machine...")

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start machine: %w", err)
	}

	// Set as default connection
	if err := mgr.SetDefault(ctx); err != nil {
		fmt.Printf("Warning: could not set as default connection: %v\n", err)
	}

	fmt.Println("Devkit machine started successfully!")

	return nil
}

func runMachineStop(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Println("Devkit machine does not exist.")
		return nil
	}

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		return err
	}

	if !running {
		fmt.Println("Devkit machine is already stopped.")
		return nil
	}

	fmt.Println("Stopping devkit Podman machine...")

	if err := mgr.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop machine: %w", err)
	}

	fmt.Println("Devkit machine stopped.")

	return nil
}

func runMachineRemove(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Println("Devkit machine does not exist.")
		return nil
	}

	if !machineForce {
		running, err := mgr.IsRunning(ctx)
		if err != nil {
			return err
		}

		if running {
			return fmt.Errorf("devkit machine is running. Stop it first or use --force")
		}
	}

	fmt.Println("Removing devkit Podman machine...")

	if err := mgr.Remove(ctx, machineForce); err != nil {
		return fmt.Errorf("failed to remove machine: %w", err)
	}

	fmt.Println("Devkit machine removed.")

	return nil
}

func runMachineStatus(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		fmt.Println("Devkit machine: NOT INITIALIZED")
		fmt.Println()
		fmt.Println("Run 'devkit machine init' to create the machine.")
		return nil
	}

	info, err := mgr.GetInfo(ctx)
	if err != nil {
		return err
	}

	status := "STOPPED"
	if info.Running {
		status = "RUNNING"
	} else if info.Starting {
		status = "STARTING"
	}

	fmt.Printf("Devkit Machine Status\n")
	fmt.Printf("=====================\n")
	fmt.Printf("Name:      %s\n", info.Name)
	fmt.Printf("Status:    %s\n", status)
	fmt.Printf("CPUs:      %d\n", info.CPUs)
	fmt.Printf("Memory:    %s\n", info.Memory)
	fmt.Printf("Disk:      %s\n", info.DiskSize)
	fmt.Printf("VM Type:   %s\n", info.VMType)
	fmt.Printf("Default:   %v\n", info.Default)

	if info.LastUp != "" {
		fmt.Printf("Last Up:   %s\n", info.LastUp)
	}

	return nil
}

func runMachineSSH(cmd *cobra.Command, args []string) error {
	if err := machine.CheckPodmanInstalled(); err != nil {
		return fmt.Errorf("podman is required: %w", err)
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		return err
	}

	if !running {
		return fmt.Errorf("devkit machine is not running. Start it with 'devkit machine start'")
	}

	output, err := mgr.SSH(ctx, args...)
	if err != nil {
		return fmt.Errorf("SSH failed: %w", err)
	}

	fmt.Print(output)

	return nil
}
