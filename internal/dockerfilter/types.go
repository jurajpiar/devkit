package dockerfilter

import "encoding/json"

// The request bodies the filter decodes, written by hand from the Docker
// Engine API 1.52 reference. Field names and JSON names are the daemon's:
// the filter refuses any key that is not one of these byte for byte, so a
// field missing here is a refusal, never a pass. Fields the daemon has
// dropped in recent versions stay, because older clients may still send
// them and each is validated like the rest.

// StrSlice is a string or a list of strings, as the daemon reads Cmd,
// Entrypoint, Shell and the capability lists. null stays nil and [] stays
// empty, because the daemon tells the two apart for Entrypoint.
type StrSlice []string

// UnmarshalJSON mirrors the daemon's: a list, or else a single string.
func (s *StrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	p := make([]string, 0, 1)
	if err := json.Unmarshal(b, &p); err != nil {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		p = append(p, one)
	}
	*s = p
	return nil
}

// HealthConfig is a container's health check.
type HealthConfig struct {
	Test          []string `json:"Test,omitempty"`
	Interval      int64    `json:"Interval,omitempty"`
	Timeout       int64    `json:"Timeout,omitempty"`
	StartPeriod   int64    `json:"StartPeriod,omitempty"`
	StartInterval int64    `json:"StartInterval,omitempty"`
	Retries       int      `json:"Retries,omitempty"`
}

// ContainerConfig is the image-level part of a container's configuration
// (container.Config). It is also the body of POST /commit.
type ContainerConfig struct {
	Hostname        string              `json:"Hostname"`
	Domainname      string              `json:"Domainname"`
	User            string              `json:"User"`
	AttachStdin     bool                `json:"AttachStdin"`
	AttachStdout    bool                `json:"AttachStdout"`
	AttachStderr    bool                `json:"AttachStderr"`
	ExposedPorts    map[string]struct{} `json:"ExposedPorts,omitempty"`
	Tty             bool                `json:"Tty"`
	OpenStdin       bool                `json:"OpenStdin"`
	StdinOnce       bool                `json:"StdinOnce"`
	Env             []string            `json:"Env"`
	Cmd             StrSlice            `json:"Cmd"`
	Healthcheck     *HealthConfig       `json:"Healthcheck,omitempty"`
	ArgsEscaped     bool                `json:"ArgsEscaped,omitempty"`
	Image           string              `json:"Image"`
	Volumes         map[string]struct{} `json:"Volumes"`
	WorkingDir      string              `json:"WorkingDir"`
	Entrypoint      StrSlice            `json:"Entrypoint"`
	NetworkDisabled bool                `json:"NetworkDisabled,omitempty"`
	MacAddress      string              `json:"MacAddress,omitempty"`
	OnBuild         []string            `json:"OnBuild"`
	Labels          map[string]string   `json:"Labels"`
	StopSignal      string              `json:"StopSignal,omitempty"`
	StopTimeout     *int                `json:"StopTimeout,omitempty"`
	Shell           StrSlice            `json:"Shell,omitempty"`
}

// LogConfig names a container's log driver and its options.
type LogConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// PortBinding is one host address and port a container port is published on.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// RestartPolicy says when the daemon restarts a container.
type RestartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount"`
}

// WeightDevice and ThrottleDevice are block I/O settings for one device.
type WeightDevice struct {
	Path   string `json:"Path"`
	Weight uint16 `json:"Weight"`
}

// ThrottleDevice limits the rate of block I/O to one device.
type ThrottleDevice struct {
	Path string `json:"Path"`
	Rate uint64 `json:"Rate"`
}

// DeviceMapping is a device node from the VM made available in a container.
type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

// DeviceRequest asks a device driver (a GPU, for one) for devices.
type DeviceRequest struct {
	Driver       string            `json:"Driver"`
	Count        int               `json:"Count"`
	DeviceIDs    []string          `json:"DeviceIDs"`
	Capabilities [][]string        `json:"Capabilities"`
	Options      map[string]string `json:"Options"`
}

// Ulimit is one resource limit.
type Ulimit struct {
	Name string `json:"Name"`
	Hard int64  `json:"Hard"`
	Soft int64  `json:"Soft"`
}

// Resources are a container's cgroup and ulimit settings
// (container.Resources), embedded in HostConfig.
type Resources struct {
	CPUShares            int64             `json:"CpuShares"`
	Memory               int64             `json:"Memory"`
	NanoCPUs             int64             `json:"NanoCpus"`
	CgroupParent         string            `json:"CgroupParent"`
	BlkioWeight          uint16            `json:"BlkioWeight"`
	BlkioWeightDevice    []*WeightDevice   `json:"BlkioWeightDevice"`
	BlkioDeviceReadBps   []*ThrottleDevice `json:"BlkioDeviceReadBps"`
	BlkioDeviceWriteBps  []*ThrottleDevice `json:"BlkioDeviceWriteBps"`
	BlkioDeviceReadIOps  []*ThrottleDevice `json:"BlkioDeviceReadIOps"`
	BlkioDeviceWriteIOps []*ThrottleDevice `json:"BlkioDeviceWriteIOps"`
	CPUPeriod            int64             `json:"CpuPeriod"`
	CPUQuota             int64             `json:"CpuQuota"`
	CPURealtimePeriod    int64             `json:"CpuRealtimePeriod"`
	CPURealtimeRuntime   int64             `json:"CpuRealtimeRuntime"`
	CpusetCpus           string            `json:"CpusetCpus"`
	CpusetMems           string            `json:"CpusetMems"`
	Devices              []DeviceMapping   `json:"Devices"`
	DeviceCgroupRules    []string          `json:"DeviceCgroupRules"`
	DeviceRequests       []DeviceRequest   `json:"DeviceRequests"`
	KernelMemory         int64             `json:"KernelMemory,omitempty"`
	KernelMemoryTCP      int64             `json:"KernelMemoryTCP,omitempty"`
	MemoryReservation    int64             `json:"MemoryReservation"`
	MemorySwap           int64             `json:"MemorySwap"`
	MemorySwappiness     *int64            `json:"MemorySwappiness"`
	OomKillDisable       *bool             `json:"OomKillDisable"`
	PidsLimit            *int64            `json:"PidsLimit"`
	Ulimits              []*Ulimit         `json:"Ulimits"`
	CPUCount             int64             `json:"CpuCount"`
	CPUPercent           int64             `json:"CpuPercent"`
	IOMaximumIOps        uint64            `json:"IOMaximumIOps"`
	IOMaximumBandwidth   uint64            `json:"IOMaximumBandwidth"`
}

// BindOptions are the options of a bind mount.
type BindOptions struct {
	Propagation            string `json:"Propagation,omitempty"`
	NonRecursive           bool   `json:"NonRecursive,omitempty"`
	CreateMountpoint       bool   `json:"CreateMountpoint,omitempty"`
	ReadOnlyNonRecursive   bool   `json:"ReadOnlyNonRecursive,omitempty"`
	ReadOnlyForceRecursive bool   `json:"ReadOnlyForceRecursive,omitempty"`
}

// MountDriver is a volume driver and its options.
type MountDriver struct {
	Name    string            `json:"Name,omitempty"`
	Options map[string]string `json:"Options,omitempty"`
}

// VolumeOptions are the options of a volume mount.
type VolumeOptions struct {
	NoCopy       bool              `json:"NoCopy,omitempty"`
	Labels       map[string]string `json:"Labels,omitempty"`
	Subpath      string            `json:"Subpath,omitempty"`
	DriverConfig *MountDriver      `json:"DriverConfig,omitempty"`
}

// ImageOptions are the options of an image mount.
type ImageOptions struct {
	Subpath string `json:"Subpath,omitempty"`
}

// TmpfsOptions are the options of a tmpfs mount.
type TmpfsOptions struct {
	SizeBytes int64      `json:"SizeBytes,omitempty"`
	Mode      uint32     `json:"Mode,omitempty"`
	Options   [][]string `json:"Options,omitempty"`
}

// Mount is one entry of HostConfig.Mounts.
type Mount struct {
	Type           string          `json:"Type,omitempty"`
	Source         string          `json:"Source,omitempty"`
	Target         string          `json:"Target,omitempty"`
	ReadOnly       bool            `json:"ReadOnly,omitempty"`
	Consistency    string          `json:"Consistency,omitempty"`
	BindOptions    *BindOptions    `json:"BindOptions,omitempty"`
	VolumeOptions  *VolumeOptions  `json:"VolumeOptions,omitempty"`
	ImageOptions   *ImageOptions   `json:"ImageOptions,omitempty"`
	TmpfsOptions   *TmpfsOptions   `json:"TmpfsOptions,omitempty"`
	ClusterOptions json.RawMessage `json:"ClusterOptions,omitempty"`
}

// HostConfig is the part of a container's configuration that depends on
// the machine it runs on: everything security-relevant is here.
type HostConfig struct {
	Binds           []string                 `json:"Binds"`
	ContainerIDFile string                   `json:"ContainerIDFile"`
	LogConfig       LogConfig                `json:"LogConfig"`
	NetworkMode     string                   `json:"NetworkMode"`
	PortBindings    map[string][]PortBinding `json:"PortBindings"`
	RestartPolicy   RestartPolicy            `json:"RestartPolicy"`
	AutoRemove      bool                     `json:"AutoRemove"`
	VolumeDriver    string                   `json:"VolumeDriver"`
	VolumesFrom     []string                 `json:"VolumesFrom"`
	ConsoleSize     [2]uint                  `json:"ConsoleSize"`
	Annotations     map[string]string        `json:"Annotations,omitempty"`

	CapAdd          StrSlice          `json:"CapAdd"`
	CapDrop         StrSlice          `json:"CapDrop"`
	Capabilities    []string          `json:"Capabilities,omitempty"`
	CgroupnsMode    string            `json:"CgroupnsMode"`
	DNS             []string          `json:"Dns"`
	DNSOptions      []string          `json:"DnsOptions"`
	DNSSearch       []string          `json:"DnsSearch"`
	ExtraHosts      []string          `json:"ExtraHosts"`
	GroupAdd        []string          `json:"GroupAdd"`
	IpcMode         string            `json:"IpcMode"`
	Cgroup          string            `json:"Cgroup"`
	Links           []string          `json:"Links"`
	OomScoreAdj     int               `json:"OomScoreAdj"`
	PidMode         string            `json:"PidMode"`
	Privileged      bool              `json:"Privileged"`
	PublishAllPorts bool              `json:"PublishAllPorts"`
	ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
	SecurityOpt     []string          `json:"SecurityOpt"`
	StorageOpt      map[string]string `json:"StorageOpt,omitempty"`
	Tmpfs           map[string]string `json:"Tmpfs,omitempty"`
	UTSMode         string            `json:"UTSMode"`
	UsernsMode      string            `json:"UsernsMode"`
	ShmSize         int64             `json:"ShmSize"`
	Sysctls         map[string]string `json:"Sysctls,omitempty"`
	Runtime         string            `json:"Runtime,omitempty"`

	Isolation string `json:"Isolation"`

	Resources

	Mounts []Mount `json:"Mounts,omitempty"`
	// A pointer, so that null (the daemon's default masks) and [] (no
	// masks at all) stay apart.
	MaskedPaths   *[]string `json:"MaskedPaths"`
	ReadonlyPaths *[]string `json:"ReadonlyPaths"`
	Init          *bool     `json:"Init,omitempty"`
}

// EndpointIPAMConfig fixes a container's addresses on one network.
type EndpointIPAMConfig struct {
	IPv4Address  string   `json:"IPv4Address,omitempty"`
	IPv6Address  string   `json:"IPv6Address,omitempty"`
	LinkLocalIPs []string `json:"LinkLocalIPs,omitempty"`
}

// EndpointSettings are a container's settings on one network.
type EndpointSettings struct {
	IPAMConfig          *EndpointIPAMConfig `json:"IPAMConfig"`
	Links               []string            `json:"Links"`
	Aliases             []string            `json:"Aliases"`
	DriverOpts          map[string]string   `json:"DriverOpts"`
	GwPriority          int                 `json:"GwPriority"`
	MacAddress          string              `json:"MacAddress"`
	NetworkID           string              `json:"NetworkID"`
	EndpointID          string              `json:"EndpointID"`
	Gateway             string              `json:"Gateway"`
	IPAddress           string              `json:"IPAddress"`
	IPPrefixLen         int                 `json:"IPPrefixLen"`
	IPv6Gateway         string              `json:"IPv6Gateway"`
	GlobalIPv6Address   string              `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int                 `json:"GlobalIPv6PrefixLen"`
	DNSNames            []string            `json:"DNSNames"`
}

// NetworkingConfig is a container's networks at creation.
type NetworkingConfig struct {
	EndpointsConfig map[string]*EndpointSettings `json:"EndpointsConfig"`
}

// CreateRequest is the body of POST /containers/create.
type CreateRequest struct {
	ContainerConfig
	HostConfig       *HostConfig       `json:"HostConfig,omitempty"`
	NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

// ExecConfig is the body of POST /containers/{id}/exec.
type ExecConfig struct {
	User         string   `json:"User"`
	Privileged   bool     `json:"Privileged"`
	Tty          bool     `json:"Tty"`
	ConsoleSize  *[2]uint `json:"ConsoleSize,omitempty"`
	AttachStdin  bool     `json:"AttachStdin"`
	AttachStderr bool     `json:"AttachStderr"`
	AttachStdout bool     `json:"AttachStdout"`
	Detach       bool     `json:"Detach"`
	DetachKeys   string   `json:"DetachKeys"`
	Env          []string `json:"Env"`
	WorkingDir   string   `json:"WorkingDir"`
	Cmd          StrSlice `json:"Cmd"`
}

// ExecStart is the body of POST /exec/{id}/start.
type ExecStart struct {
	Detach      bool     `json:"Detach"`
	Tty         bool     `json:"Tty"`
	ConsoleSize *[2]uint `json:"ConsoleSize,omitempty"`
}

// IPAMPool is one address pool of a network.
type IPAMPool struct {
	Subnet     string            `json:"Subnet,omitempty"`
	IPRange    string            `json:"IPRange,omitempty"`
	Gateway    string            `json:"Gateway,omitempty"`
	AuxAddress map[string]string `json:"AuxiliaryAddresses,omitempty"`
}

// IPAM is a network's address management.
type IPAM struct {
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
	Config  []IPAMPool        `json:"Config"`
}

// ConfigReference names a configuration-only network to copy.
type ConfigReference struct {
	Network string `json:"Network"`
}

// NetworkCreate is the body of POST /networks/create.
type NetworkCreate struct {
	Name           string            `json:"Name"`
	CheckDuplicate bool              `json:"CheckDuplicate,omitempty"`
	Driver         string            `json:"Driver"`
	Scope          string            `json:"Scope"`
	EnableIPv4     *bool             `json:"EnableIPv4,omitempty"`
	EnableIPv6     *bool             `json:"EnableIPv6,omitempty"`
	IPAM           *IPAM             `json:"IPAM"`
	Internal       bool              `json:"Internal"`
	Attachable     bool              `json:"Attachable"`
	Ingress        bool              `json:"Ingress"`
	ConfigOnly     bool              `json:"ConfigOnly"`
	ConfigFrom     *ConfigReference  `json:"ConfigFrom"`
	Options        map[string]string `json:"Options"`
	Labels         map[string]string `json:"Labels"`
}

// NetworkConnect is the body of POST /networks/{id}/connect.
type NetworkConnect struct {
	Container      string            `json:"Container"`
	EndpointConfig *EndpointSettings `json:"EndpointConfig,omitempty"`
}

// NetworkDisconnect is the body of POST /networks/{id}/disconnect.
type NetworkDisconnect struct {
	Container string `json:"Container"`
	Force     bool   `json:"Force"`
}

// VolumeCreate is the body of POST /volumes/create. ClusterVolumeSpec is
// a swarm feature; it is kept raw because the only value it may have is
// none.
type VolumeCreate struct {
	ClusterVolumeSpec json.RawMessage   `json:"ClusterVolumeSpec,omitempty"`
	Driver            string            `json:"Driver"`
	DriverOpts        map[string]string `json:"DriverOpts"`
	Labels            map[string]string `json:"Labels"`
	Name              string            `json:"Name"`
}
