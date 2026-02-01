// Package runtime provides abstracted container runtime interfaces
// supporting multiple backends (Podman, Lima, Docker).
package runtime

import (
	"context"
	"time"
)

// Backend represents a container runtime backend
type Backend string

const (
	BackendPodman Backend = "podman"
	BackendLima   Backend = "lima"
	BackendDocker Backend = "docker"
)

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID        string
	Name      string
	Image     string
	Status    string
	Created   time.Time
	Running   bool
	IPAddress string
	Ports     []PortMapping
}

// PortMapping represents a port mapping
type PortMapping struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Protocol      string
}

// VMInfo holds information about a virtual machine
type VMInfo struct {
	Name     string
	Status   string // running, stopped, starting
	CPUs     int
	Memory   string
	Disk     string
	Arch     string
	VMType   string // vz, qemu, libkrun
	Default  bool
}

// CreateOpts holds options for container creation
type CreateOpts struct {
	Name            string
	Image           string
	Hostname        string
	WorkDir         string
	User            string
	Env             map[string]string
	Volumes         []VolumeMount
	Ports           []PortMapping
	CapDrop         []string
	CapAdd          []string
	SecurityOpts    []string
	ReadOnly        bool
	Tmpfs           []TmpfsMount
	NetworkMode     string
	Memory          string
	PidsLimit       int
	Labels          map[string]string
}

// VolumeMount represents a volume mount
type VolumeMount struct {
	Source   string
	Target   string
	ReadOnly bool
	Type     string // bind, volume, tmpfs
}

// TmpfsMount represents a tmpfs mount
type TmpfsMount struct {
	Target  string
	Options string // e.g., "rw,nosuid,size=512m"
}

// BuildOpts holds options for image building
type BuildOpts struct {
	ContextDir     string
	Dockerfile     string
	ImageName      string
	Tags           []string
	BuildArgs      map[string]string
	NoCache        bool
	Platform       string
}

// VMOpts holds options for VM creation
type VMOpts struct {
	CPUs       int
	MemoryMB   int
	DiskSizeGB int
	VMType     string // vz, qemu for Lima; libkrun for Podman
	Arch       string
	// Lima-specific
	Image      string   // VM base image URL
	Provision  []string // Provisioning scripts
	// Port forwarding
	SSHPort    int   // SSH port for container (e.g., 2222)
	Ports      []int // Additional ports to forward
}

// DefaultVMOpts returns sensible defaults for VM creation
func DefaultVMOpts() VMOpts {
	return VMOpts{
		CPUs:       4,
		MemoryMB:   4096,
		DiskSizeGB: 50,
		VMType:     "vz", // Fast on Apple Silicon
		Arch:       "aarch64",
	}
}

// Runtime abstracts container operations across different backends
type Runtime interface {
	// Name returns the runtime backend name
	Name() Backend

	// Lifecycle
	Create(ctx context.Context, opts CreateOpts) (string, error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	Kill(ctx context.Context, name string) error

	// Execution
	Exec(ctx context.Context, name string, cmd ...string) (string, error)
	ExecAsUser(ctx context.Context, name, user string, cmd ...string) (string, error)
	ExecInteractive(ctx context.Context, name string, cmd ...string) error

	// Info
	Exists(ctx context.Context, name string) (bool, error)
	IsRunning(ctx context.Context, name string) (bool, error)
	GetInfo(ctx context.Context, name string) (*ContainerInfo, error)
	List(ctx context.Context) ([]ContainerInfo, error)

	// File operations
	CopyTo(ctx context.Context, name, src, dst string) error
	CopyFrom(ctx context.Context, name, src, dst string) error

	// Build
	Build(ctx context.Context, opts BuildOpts) error
	ImageExists(ctx context.Context, image string) (bool, error)
	RemoveImage(ctx context.Context, image string) error

	// Volume operations
	CreateVolume(ctx context.Context, name string) error
	RemoveVolume(ctx context.Context, name string) error
	ListVolumes(ctx context.Context, prefix string) ([]string, error)

	// Commit container to image
	Commit(ctx context.Context, container, image string) (string, error)
}

// VMManager abstracts VM operations (for Lima/Podman machines)
type VMManager interface {
	// Name returns the VM manager name
	Name() Backend

	// Lifecycle
	Create(ctx context.Context, name string, opts VMOpts) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string, force bool) error

	// Info
	Exists(ctx context.Context, name string) (bool, error)
	IsRunning(ctx context.Context, name string) (bool, error)
	GetInfo(ctx context.Context, name string) (*VMInfo, error)
	List(ctx context.Context) ([]VMInfo, error)

	// Get the currently running VM (if any)
	GetRunning(ctx context.Context) (*VMInfo, error)

	// Set as default connection/context
	SetDefault(ctx context.Context, name string) error

	// Shell access to VM
	Shell(ctx context.Context, name string, cmd ...string) (string, error)
}

// Installer handles runtime installation
type Installer interface {
	// Name returns the installer name
	Name() Backend

	// IsInstalled checks if the runtime is installed
	IsInstalled(ctx context.Context) bool

	// Install installs the runtime (e.g., via brew)
	Install(ctx context.Context) error

	// Uninstall removes the runtime
	Uninstall(ctx context.Context) error

	// Version returns the installed version
	Version(ctx context.Context) (string, error)

	// Doctor diagnoses common issues
	Doctor(ctx context.Context) []DiagnosticResult
}

// DiagnosticResult represents a diagnostic check result
type DiagnosticResult struct {
	Check   string
	Status  DiagnosticStatus
	Message string
	Fix     string // Suggested fix command
}

// DiagnosticStatus represents the status of a diagnostic check
type DiagnosticStatus string

const (
	DiagnosticOK      DiagnosticStatus = "ok"
	DiagnosticWarning DiagnosticStatus = "warning"
	DiagnosticError   DiagnosticStatus = "error"
)

// ErrNotInstalled is returned when a runtime is not installed
type ErrNotInstalled struct {
	Runtime Backend
}

func (e ErrNotInstalled) Error() string {
	return string(e.Runtime) + " is not installed. Run: devkit setup"
}

// ErrVMNotRunning is returned when the VM is not running
type ErrVMNotRunning struct {
	Name string
}

func (e ErrVMNotRunning) Error() string {
	return "VM '" + e.Name + "' is not running. Run: devkit start"
}

// ErrContainerNotFound is returned when a container doesn't exist
type ErrContainerNotFound struct {
	Name string
}

func (e ErrContainerNotFound) Error() string {
	return "container '" + e.Name + "' not found"
}

// ErrContainerNotRunning is returned when a container is not running
type ErrContainerNotRunning struct {
	Name string
}

func (e ErrContainerNotRunning) Error() string {
	return "container '" + e.Name + "' is not running. Run: devkit start"
}
