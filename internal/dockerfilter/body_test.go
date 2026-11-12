package dockerfilter

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cliCreate is a create body as the Docker client sends it for a plain
// docker run: every HostConfig field present, at its zero value.
func cliCreate() *CreateRequest {
	f := false
	return &CreateRequest{
		ContainerConfig: ContainerConfig{Image: "busybox:1.36", Cmd: StrSlice{"true"}, AttachStdout: true, AttachStderr: true},
		HostConfig: &HostConfig{
			NetworkMode:   "default",
			RestartPolicy: RestartPolicy{Name: "no"},
			LogConfig:     LogConfig{Config: map[string]string{}},
			PortBindings:  map[string][]PortBinding{},
			DNS:           []string{},
			DNSOptions:    []string{},
			DNSSearch:     []string{},
			Resources: Resources{
				OomKillDisable:    &f,
				BlkioWeightDevice: []*WeightDevice{}, BlkioDeviceReadBps: []*ThrottleDevice{},
				BlkioDeviceWriteBps: []*ThrottleDevice{}, BlkioDeviceReadIOps: []*ThrottleDevice{},
				BlkioDeviceWriteIOps: []*ThrottleDevice{}, Devices: []DeviceMapping{}, Ulimits: []*Ulimit{},
			},
		},
		NetworkingConfig: &NetworkingConfig{EndpointsConfig: map[string]*EndpointSettings{}},
	}
}

// fillEmpty sets every nil slice and map reachable in v to an empty one,
// and every nil pointer to a zero value, except the masks, whose empty
// list means something: the zero config written with [] and {} wherever
// the type allows.
func fillEmpty(v reflect.Value, name string) {
	switch v.Kind() {
	case reflect.Pointer:
		if name == "MaskedPaths" || name == "ReadonlyPaths" {
			return
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillEmpty(v.Elem(), name)
	case reflect.Slice:
		if v.IsNil() && v.Type() != reflect.TypeOf(json.RawMessage(nil)) {
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillEmpty(v.Field(i), v.Type().Field(i).Name)
			}
		}
	}
}

func testFilter(t *testing.T) *Filter {
	t.Helper()
	dir := realDir(t, t.TempDir())
	cfg := testConfig(dir)
	os.MkdirAll(cfg.Workspace, 0o755)
	return New(cfg, log.New(io.Discard, "", 0))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateAcceptsWhatTheClientSends(t *testing.T) {
	f := testFilter(t)
	nulls := &CreateRequest{ContainerConfig: ContainerConfig{Image: "x"}, HostConfig: &HostConfig{}, NetworkingConfig: &NetworkingConfig{}}
	empties := &CreateRequest{ContainerConfig: ContainerConfig{Image: "x"}}
	fillEmpty(reflect.ValueOf(empties).Elem(), "")
	empties.HostConfig.ConsoleSize = [2]uint{0, 0}
	empties.HostConfig.Init = nil
	empties.HostConfig.Mounts = []Mount{}
	empties.NetworkingConfig.EndpointsConfig = map[string]*EndpointSettings{}
	for name, body := range map[string]string{
		"the client's plain run": mustJSON(t, cliCreate()),
		"every field, null":      mustJSON(t, nulls),
		"every field, [] and {}": mustJSON(t, empties),
		"no HostConfig":          `{"Image":"busybox:1.36","Cmd":["true"]}`,
		"HostConfig null":        `{"Image":"busybox:1.36","HostConfig":null}`,
		"Cmd as a string":        `{"Image":"busybox:1.36","Cmd":"true"}`,
		"OomKillDisable false":   `{"Image":"x","HostConfig":{"OomKillDisable":false}}`,
		"Isolation empty":        `{"Image":"x","HostConfig":{"Isolation":""}}`,
		"Capabilities null":      `{"Image":"x","HostConfig":{"Capabilities":null}}`,
		"ClusterOptions null":    `{"Image":"x","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t","ClusterOptions":null}]}}`,
		"options a run may set": mustJSON(t, func() *CreateRequest {
			r := cliCreate()
			h := r.HostConfig
			pl, mem := int64(100), int64(128<<20)
			tr := true
			h.CapAdd, h.CapDrop = StrSlice{"IPC_LOCK", "cap_net_bind_service", "Chown"}, StrSlice{"ALL"}
			h.SecurityOpt = []string{"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
			h.Runtime, h.NetworkMode = "devkit-runc", "f-net"
			h.PortBindings = map[string][]PortBinding{"80/tcp": {{HostIP: "", HostPort: "8080"}, {HostIP: "127.0.0.1"}, {HostIP: "::1"}}}
			h.LogConfig = LogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "3"}}
			h.Binds = []string{f.cfg.Workspace + ":/w", f.cfg.Workspace + "/sub/new:/s:ro,z", "vol:/v:nocopy", "/anon", "/anon2:ro"}
			h.Mounts = []Mount{
				{Type: "bind", Source: f.cfg.Workspace, Target: "/m", ReadOnly: true, BindOptions: &BindOptions{CreateMountpoint: true, Propagation: "rprivate", NonRecursive: true, ReadOnlyNonRecursive: true}},
				{Type: "volume", Source: "data", Target: "/d", VolumeOptions: &VolumeOptions{NoCopy: true, Labels: map[string]string{"a": "b"}, Subpath: "x"}},
				{Type: "volume", Target: "/anon"},
				{Type: "tmpfs", Target: "/t", TmpfsOptions: &TmpfsOptions{SizeBytes: 1 << 20, Mode: 0o1777}},
			}
			h.VolumesFrom, h.Links, h.ExtraHosts = []string{"other:ro"}, []string{"db:db"}, []string{"host.docker.internal:host-gateway"}
			h.DNS, h.DNSOptions, h.DNSSearch, h.GroupAdd = []string{"1.1.1.1"}, []string{"ndots:1"}, []string{"x"}, []string{"1000"}
			h.Tmpfs = map[string]string{"/run": "rw,exec"}
			h.Memory, h.MemorySwap, h.MemoryReservation, h.NanoCPUs, h.CPUShares = mem, mem, mem, 1e9, 512
			h.CPUPeriod, h.CPUQuota, h.CpusetCpus, h.CpusetMems, h.PidsLimit, h.ShmSize = 100000, 50000, "0", "0", &pl, 1<<26
			h.Ulimits, h.BlkioWeight = []*Ulimit{{Name: "nofile", Soft: 1024, Hard: 2048}}, 500
			h.RestartPolicy, h.AutoRemove, h.Init, h.ReadonlyRootfs, h.PublishAllPorts = RestartPolicy{Name: "on-failure", MaximumRetryCount: 3}, true, &tr, true, true
			h.ConsoleSize, h.ContainerIDFile = [2]uint{24, 80}, "/tmp/cid"
			h.IpcMode, h.PidMode, h.CgroupnsMode = "shareable", "private", "private"
			r.NetworkingConfig.EndpointsConfig["f-net"] = &EndpointSettings{Aliases: []string{"a"}, DNSNames: []string{"a"}, IPAMConfig: &EndpointIPAMConfig{IPv4Address: "10.0.0.5"}, GwPriority: 1}
			r.Healthcheck = &HealthConfig{Test: []string{"CMD", "true"}, Interval: 2e9, Retries: 3}
			r.Volumes, r.ExposedPorts = map[string]struct{}{"/anon": {}}, map[string]struct{}{"80/tcp": {}}
			r.Entrypoint, r.Shell, r.Labels, r.Env = StrSlice{}, StrSlice{"/bin/sh", "-c"}, map[string]string{"l": "v"}, []string{"A=b"}
			return r
		}()),
	} {
		out, err := decodeCreate(f, []byte(body))
		if err != nil {
			t.Errorf("%s: refused: %v\n%s", name, err, body)
			continue
		}
		var got CreateRequest
		json.Unmarshal(out, &got)
		if got.HostConfig == nil || !hasCap(got.HostConfig.CapDrop, "NET_RAW") && !hasCap(got.HostConfig.CapDrop, "ALL") {
			t.Errorf("%s: NET_RAW should be dropped: %s", name, out)
		}
	}
}

func hasCap(list StrSlice, c string) bool {
	for _, x := range list {
		if normCap(x) == normCap(c) {
			return true
		}
	}
	return false
}

// One case per refused field: each starts from the client's plain run.
func TestCreateRefusals(t *testing.T) {
	f := testFilter(t)
	ws := f.cfg.Workspace
	tr := true
	adj := int64(1)
	cases := map[string]func(r *CreateRequest){
		"Privileged":            func(r *CreateRequest) { r.HostConfig.Privileged = true },
		"Devices":               func(r *CreateRequest) { r.HostConfig.Devices = []DeviceMapping{{PathOnHost: "/dev/null"}} },
		"DeviceCgroupRules":     func(r *CreateRequest) { r.HostConfig.DeviceCgroupRules = []string{"c 1:3 rwm"} },
		"DeviceRequests":        func(r *CreateRequest) { r.HostConfig.DeviceRequests = []DeviceRequest{{Count: -1}} },
		"Sysctls":               func(r *CreateRequest) { r.HostConfig.Sysctls = map[string]string{"net.ipv4.ip_forward": "1"} },
		"CgroupParent":          func(r *CreateRequest) { r.HostConfig.CgroupParent = "/x" },
		"Cgroup":                func(r *CreateRequest) { r.HostConfig.Cgroup = "container:x" },
		"VolumeDriver":          func(r *CreateRequest) { r.HostConfig.VolumeDriver = "other" },
		"StorageOpt":            func(r *CreateRequest) { r.HostConfig.StorageOpt = map[string]string{"size": "1G"} },
		"Isolation":             func(r *CreateRequest) { r.HostConfig.Isolation = "hyperv" },
		"MaskedPaths emptied":   func(r *CreateRequest) { r.HostConfig.MaskedPaths = &[]string{} },
		"ReadonlyPaths emptied": func(r *CreateRequest) { r.HostConfig.ReadonlyPaths = &[]string{} },
		"MaskedPaths set":       func(r *CreateRequest) { r.HostConfig.MaskedPaths = &[]string{"/proc/kcore"} },
		"Annotations":           func(r *CreateRequest) { r.HostConfig.Annotations = map[string]string{"a": "b"} },
		"OomScoreAdj":           func(r *CreateRequest) { r.HostConfig.OomScoreAdj = -500 },
		"OomKillDisable":        func(r *CreateRequest) { r.HostConfig.OomKillDisable = &tr },
		"UsernsMode":            func(r *CreateRequest) { r.HostConfig.UsernsMode = "host" },
		"UTSMode":               func(r *CreateRequest) { r.HostConfig.UTSMode = "host" },
		"CgroupnsMode host":     func(r *CreateRequest) { r.HostConfig.CgroupnsMode = "host" },
		"PidMode host":          func(r *CreateRequest) { r.HostConfig.PidMode = "host" },
		"PidMode container":     func(r *CreateRequest) { r.HostConfig.PidMode = "container:x" },
		"IpcMode host":          func(r *CreateRequest) { r.HostConfig.IpcMode = "host" },
		"IpcMode container":     func(r *CreateRequest) { r.HostConfig.IpcMode = "container:x" },
		"KernelMemory":          func(r *CreateRequest) { r.HostConfig.KernelMemory = 1 },
		"KernelMemoryTCP":       func(r *CreateRequest) { r.HostConfig.KernelMemoryTCP = 1 },
		"CpuRealtimePeriod":     func(r *CreateRequest) { r.HostConfig.CPURealtimePeriod = 1 },
		"CpuRealtimeRuntime":    func(r *CreateRequest) { r.HostConfig.CPURealtimeRuntime = 1 },
		"BlkioWeightDevice": func(r *CreateRequest) {
			r.HostConfig.BlkioWeightDevice = []*WeightDevice{{Path: "/dev/vda", Weight: 10}}
		},
		"BlkioDeviceReadBps":   func(r *CreateRequest) { r.HostConfig.BlkioDeviceReadBps = []*ThrottleDevice{{Path: "/dev/vda"}} },
		"BlkioDeviceWriteBps":  func(r *CreateRequest) { r.HostConfig.BlkioDeviceWriteBps = []*ThrottleDevice{{Path: "/dev/vda"}} },
		"BlkioDeviceReadIOps":  func(r *CreateRequest) { r.HostConfig.BlkioDeviceReadIOps = []*ThrottleDevice{{Path: "/dev/vda"}} },
		"BlkioDeviceWriteIOps": func(r *CreateRequest) { r.HostConfig.BlkioDeviceWriteIOps = []*ThrottleDevice{{Path: "/dev/vda"}} },
		"IOMaximumIOps":        func(r *CreateRequest) { r.HostConfig.IOMaximumIOps = 1 },
		"IOMaximumBandwidth":   func(r *CreateRequest) { r.HostConfig.IOMaximumBandwidth = 1 },
		"CpuCount":             func(r *CreateRequest) { r.HostConfig.CPUCount = 1 },
		"CpuPercent":           func(r *CreateRequest) { r.HostConfig.CPUPercent = 1 },
		"Capabilities":         func(r *CreateRequest) { r.HostConfig.Capabilities = []string{"CAP_SYS_ADMIN"} },
		"SecurityOpt seccomp":  func(r *CreateRequest) { r.HostConfig.SecurityOpt = []string{"seccomp=unconfined"} },
		"SecurityOpt apparmor": func(r *CreateRequest) { r.HostConfig.SecurityOpt = []string{"apparmor=unconfined"} },
		"SecurityOpt label":    func(r *CreateRequest) { r.HostConfig.SecurityOpt = []string{"label=disable"} },
		"SecurityOpt systempaths": func(r *CreateRequest) {
			r.HostConfig.SecurityOpt = []string{"systempaths=unconfined"}
		},
		"SecurityOpt nnp false": func(r *CreateRequest) { r.HostConfig.SecurityOpt = []string{"no-new-privileges=false"} },
		"SecurityOpt nnp:false": func(r *CreateRequest) { r.HostConfig.SecurityOpt = []string{"no-new-privileges:false"} },
		"CapAdd SYS_ADMIN":      func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"SYS_ADMIN"} },
		"CapAdd NET_ADMIN":      func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"cap_net_admin"} },
		"CapAdd NET_RAW":        func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"NET_RAW"} },
		"CapAdd ALL":            func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"all"} },
		"CapAdd CAP_ALL":        func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"CAP_ALL"} },
		"CapAdd SYS_PTRACE":     func(r *CreateRequest) { r.HostConfig.CapAdd = StrSlice{"SYS_PTRACE"} },
		"Runtime runc":          func(r *CreateRequest) { r.HostConfig.Runtime = "runc" },
		"Runtime containerd":    func(r *CreateRequest) { r.HostConfig.Runtime = "io.containerd.runc.v2" },
		"Runtime runsc":         func(r *CreateRequest) { r.HostConfig.Runtime = "runsc" },
		"NetworkMode host":      func(r *CreateRequest) { r.HostConfig.NetworkMode = "host" },
		"NetworkMode odd name":  func(r *CreateRequest) { r.HostConfig.NetworkMode = "../x" },
		"NetworkMode container bad": func(r *CreateRequest) {
			r.HostConfig.NetworkMode = "container:"
		},
		"EndpointsConfig host": func(r *CreateRequest) { r.NetworkingConfig.EndpointsConfig["host"] = &EndpointSettings{} },
		"EndpointsConfig DriverOpts": func(r *CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["n"] = &EndpointSettings{DriverOpts: map[string]string{"a": "b"}}
		},
		"PortBindings all interfaces": func(r *CreateRequest) {
			r.HostConfig.PortBindings = map[string][]PortBinding{"80/tcp": {{HostIP: "0.0.0.0", HostPort: "80"}}}
		},
		"PortBindings ::": func(r *CreateRequest) {
			r.HostConfig.PortBindings = map[string][]PortBinding{"80/tcp": {{HostIP: "::"}}}
		},
		"LogConfig syslog": func(r *CreateRequest) { r.HostConfig.LogConfig = LogConfig{Type: "syslog"} },
		"LogConfig option": func(r *CreateRequest) {
			r.HostConfig.LogConfig = LogConfig{Type: "json-file", Config: map[string]string{"syslog-address": "udp://1.1.1.1:514"}}
		},
		"Binds /etc":            func(r *CreateRequest) { r.HostConfig.Binds = []string{"/etc:/e"} },
		"Binds /":               func(r *CreateRequest) { r.HostConfig.Binds = []string{"/:/host"} },
		"Binds climbs out":      func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + "/../.ssh:/s"} },
		"Binds sibling":         func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + "-evil:/s"} },
		"Binds rshared":         func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + ":/w:rshared"} },
		"Binds slave":           func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + ":/w:ro,slave"} },
		"Binds relative":        func(r *CreateRequest) { r.HostConfig.Binds = []string{"a/b:/w"} },
		"Binds dst propagation": func(r *CreateRequest) { r.HostConfig.Binds = []string{"/w:rshared"} },
		"Binds unknown option":  func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + ":/w:exec"} },
		"Binds four parts":      func(r *CreateRequest) { r.HostConfig.Binds = []string{ws + ":/w:ro:x"} },
		"Binds empty source":    func(r *CreateRequest) { r.HostConfig.Binds = []string{":/w"} },
		"Mounts bind /etc":      func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Type: "bind", Source: "/etc", Target: "/e"}} },
		"Mounts bind propagation": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "bind", Source: ws, Target: "/w", BindOptions: &BindOptions{Propagation: "shared"}}}
		},
		"Mounts bind relative": func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Type: "bind", Source: "ws", Target: "/w"}} },
		"Mounts volume driver opts": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "volume", Target: "/v", VolumeOptions: &VolumeOptions{DriverConfig: &MountDriver{Options: map[string]string{"device": "/etc"}}}}}
		},
		"Mounts volume driver": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "volume", Target: "/v", VolumeOptions: &VolumeOptions{DriverConfig: &MountDriver{Name: "other"}}}}
		},
		"Mounts volume path": func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Type: "volume", Source: "/etc", Target: "/v"}} },
		"Mounts tmpfs options": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "tmpfs", Target: "/t", TmpfsOptions: &TmpfsOptions{Options: [][]string{{"exec"}}}}}
		},
		"Mounts image": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "image", Source: "busybox", Target: "/i"}}
		},
		"Mounts npipe":   func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Type: "npipe", Source: "x", Target: "/i"}} },
		"Mounts cluster": func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Type: "cluster", Source: "x", Target: "/i"}} },
		"Mounts no type": func(r *CreateRequest) { r.HostConfig.Mounts = []Mount{{Source: ws, Target: "/i"}} },
		"Mounts ClusterOptions": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "volume", Target: "/i", ClusterOptions: json.RawMessage(`{}`)}}
		},
		"Mounts bind with volume options": func(r *CreateRequest) {
			r.HostConfig.Mounts = []Mount{{Type: "bind", Source: ws, Target: "/w", VolumeOptions: &VolumeOptions{}}}
		},
		"MemorySwappiness is fine but PidsLimit adj": func(r *CreateRequest) { r.HostConfig.MemorySwappiness = &adj; r.HostConfig.Privileged = true },
	}
	for name, mod := range cases {
		r := cliCreate()
		mod(r)
		if out, err := decodeCreate(f, []byte(mustJSON(t, r))); err == nil {
			t.Errorf("%s should be refused; forwarded %s", name, out)
		}
	}
}

// A bind source whose symlinks lead outside the workspace is refused; one
// that stays inside passes. A source the filter cannot follow to its end
// passes only with the runtime guard behind the filter.
func TestBindSymlinks(t *testing.T) {
	t.Run("guarded", func(t *testing.T) { testBindSymlinks(t, true) })
	t.Run("unguarded", func(t *testing.T) { testBindSymlinks(t, false) })
}

func testBindSymlinks(t *testing.T, guarded bool) {
	f := testFilter(t)
	f.cfg.RuntimeGuard = guarded
	ws := f.cfg.Workspace
	outside := filepath.Dir(ws)
	os.Symlink("/etc", filepath.Join(ws, "etc"))
	os.Symlink(outside, filepath.Join(ws, "up"))
	os.Symlink("/nonexistent-devkit/x", filepath.Join(ws, "dangling"))
	os.MkdirAll(filepath.Join(ws, "sub"), 0o755)
	os.Symlink(filepath.Join(ws, "sub"), filepath.Join(ws, "in"))
	os.Symlink("sub", filepath.Join(ws, "rel"))
	os.Symlink("../../ws/sub/../sub", filepath.Join(ws, "sub", "back"))
	os.Symlink("loop2", filepath.Join(ws, "loop1"))
	os.Symlink("loop1", filepath.Join(ws, "loop2"))
	// A directory the filter may not read, outside the workspace and in it:
	// a walk that has left the workspace is refused even when it cannot go
	// on; one stopped inside it falls back to the path as written when the
	// guard checks the mount, and is refused when nothing does (gVisor).
	locked := filepath.Join(outside, "locked")
	os.MkdirAll(filepath.Join(locked, "x"), 0o755)
	os.Chmod(locked, 0o000)
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	os.Symlink(filepath.Join(locked, "x"), filepath.Join(ws, "tolocked"))
	// The kernel follows inetc before its "..": to /etc's parent, /.
	os.Symlink("/etc/ssl", filepath.Join(ws, "inetc"))
	os.MkdirAll(filepath.Join(ws, "private", "y"), 0o755)
	os.Symlink("/etc", filepath.Join(ws, "private", "l"))
	os.Chmod(filepath.Join(ws, "private"), 0o000)
	t.Cleanup(func() { os.Chmod(filepath.Join(ws, "private"), 0o755) })
	for src, ok := range map[string]bool{
		ws + "/etc": false, ws + "/etc/x/y": false, ws + "/up": false, ws + "/up/ws/sub": true, ws + "/up/other": false, ws + "/dangling": false,
		ws + "/in": true, ws + "/in/new/dir": true, ws + "/rel": true, ws + "/sub": true, ws + "/missing/a": true, ws: true,
		ws + "/sub/back": true, ws + "/loop1": false, ws + "/tolocked": false, ws + "/tolocked/z": false, ws + "/private/y": guarded,
		ws + "/private/l": guarded, ws + "/sub/../in": true, ws + "/inetc/..": false, ws + "/inetc/../sub": false,
	} {
		r := cliCreate()
		r.HostConfig.Binds = []string{src + ":/x"}
		_, err := decodeCreate(f, []byte(mustJSON(t, r)))
		if (err == nil) != ok {
			t.Errorf("bind %s: err=%v, want ok=%v", src, err, ok)
		}
		if err != nil && strings.HasSuffix(src, "/private/l") && !strings.Contains(err.Error(), "may not look inside") {
			t.Errorf("the refusal should say why: %v", err)
		}
		r = cliCreate()
		r.HostConfig.Mounts = []Mount{{Type: "bind", Source: src, Target: "/x"}}
		if _, err := decodeCreate(f, []byte(mustJSON(t, r))); (err == nil) != ok {
			t.Errorf("mount %s: err=%v, want ok=%v", src, err, ok)
		}
	}
}

// Bodies the filter and the daemon could read differently: duplicate keys
// at every level, keys in another case, escaped keys, more than one value.
func TestBodyTricks(t *testing.T) {
	f := testFilter(t)
	refused := map[string]string{
		"duplicate, true last":            `{"Image":"x","HostConfig":{"Privileged":false,"Privileged":true}}`,
		"duplicate, true first":           `{"Image":"x","HostConfig":{"Privileged":true,"Privileged":false}}`,
		"duplicate top level":             `{"Image":"x","Image":"y"}`,
		"duplicate HostConfig":            `{"Image":"x","HostConfig":{},"HostConfig":{"Privileged":true}}`,
		"duplicate in LogConfig":          `{"Image":"x","HostConfig":{"LogConfig":{"Type":"","Type":"syslog"}}}`,
		"duplicate in a map":              `{"Image":"x","Labels":{"a":"1","a":"2"}}`,
		"duplicate in a list item":        `{"Image":"x","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t","Type":"bind"}]}}`,
		"duplicate in an endpoint":        `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"n":{"Aliases":[],"Aliases":["a"]}}}}`,
		"duplicate in Healthcheck":        `{"Image":"x","Healthcheck":{"Retries":1,"Retries":2}}`,
		"duplicate in BindOptions":        `{"Image":"x","HostConfig":{"Mounts":[{"Type":"bind","Source":"/w","Target":"/t","BindOptions":{"Propagation":"","Propagation":"shared"}}]}}`,
		"duplicate in a raw field":        `{"Image":"x","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t","ClusterOptions":{"a":1,"a":2}}]}}`,
		"duplicate, escaped second":       `{"Image":"x","HostConfig":{"Privileged":false,"Privile\u0067ed":true}}`,
		"lower-case key":                  `{"Image":"x","HostConfig":{"privileged":true}}`,
		"upper-case key":                  `{"Image":"x","HostConfig":{"PRIVILEGED":true}}`,
		"lower-case HostConfig":           `{"Image":"x","hostconfig":{"Privileged":true}}`,
		"lower-case CapAdd":               `{"Image":"x","HostConfig":{"capadd":["SYS_ADMIN"]}}`,
		"lower-case Binds":                `{"Image":"x","HostConfig":{"binds":["/etc:/e"]}}`,
		"lower-case nested":               `{"Image":"x","HostConfig":{"LogConfig":{"type":"syslog"}}}`,
		"Kelvin sign":                     `{"Image":"x","HostConfig":{"Lin\u212as":["a"]}}`,
		"long s":                          `{"Image":"x","HostConfig":{"Sy\u017fctls":{"a":"b"}}}`,
		"escaped Privileged":              `{"Image":"x","HostConfig":{"Privile\u0067ed":true}}`,
		"escaped Binds":                   `{"Image":"x","HostConfig":{"\u0042inds":["/etc:/e"]}}`,
		"trailing document":               `{"Image":"x"}{"HostConfig":{"Privileged":true}}`,
		"trailing garbage":                `{"Image":"x"} x`,
		"two values in a list":            `[{"Image":"x"}]`,
		"unknown field":                   `{"Image":"x","HostConfig":{"Frobnicate":true}}`,
		"unknown top-level field":         `{"Image":"x","Frobnicate":true}`,
		"unknown field in a struct{} map": `{"Image":"x","Volumes":{"/v":{"x":1}}}`,
		"wrong type":                      `{"Image":"x","HostConfig":{"Privileged":"true"}}`,
		"number for a bool":               `{"Image":"x","HostConfig":{"Privileged":1}}`,
		"object for a list":               `{"Image":"x","HostConfig":{"Binds":{"a":"/etc:/e"}}}`,
		"not JSON":                        `{"Image":`,
		"empty":                           ``,
		"null":                            `null`,
		"masked paths emptied":            `{"Image":"x","HostConfig":{"MaskedPaths":[],"ReadonlyPaths":[]}}`,
	}
	for name, body := range refused {
		if out, err := decodeCreate(f, []byte(body)); err == nil {
			t.Errorf("%s should be refused; forwarded %s", name, out)
		}
	}
	// The escaped key is the canonical key: it is read and forwarded as it.
	out, err := decodeCreate(f, []byte(`{"Image":"x","HostConfig":{"Ca\u0070Drop":["ALL"],"Privile\u0067ed":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"CapDrop":["ALL"]`)) || bytes.Contains(out, []byte(`\u`)) {
		t.Errorf("forwarded %s", out)
	}
	if _, err := decodeCreate(f, []byte(`{"Image":"x"}`+strings.Repeat(" ", MaxBody))); err != nil {
		t.Errorf("trailing whitespace is not a second value: %v", err)
	}
}

// What the daemon receives is the body as validated and encoded again,
// with NET_RAW dropped, never the client's bytes.
func TestForwardedBodyIsReencoded(t *testing.T) {
	h := newHarness(t)
	body := `{"Image":"busybox:1.36",   "Cmd":"true", "Labels":{"z":"<&>"},"HostConfig":{"Ca\u0070Add":["IPC_LOCK"],"Binds":null}}`
	st, resp := h.raw(t, "POST", "/v1.52/containers/create?name=x", body)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, resp)
	}
	got := h.daemon.last(t)
	if got.URI != "/v1.52/containers/create?name=x" || got.Header.Get("Content-Type") != "application/json" {
		t.Errorf("forwarded %s %v", got.URI, got.Header)
	}
	var want CreateRequest
	json.Unmarshal([]byte(body), &want)
	want.HostConfig.CapDrop = StrSlice{"NET_RAW"}
	wantBytes, _ := json.Marshal(&want)
	if !bytes.Equal(got.Body, wantBytes) {
		t.Errorf("forwarded body:\n%s\nwant\n%s", got.Body, wantBytes)
	}
	if bytes.Contains(got.Body, []byte(`\u0070`)) || !bytes.Contains(got.Body, []byte(`"Cmd":["true"]`)) {
		t.Errorf("the client's bytes were forwarded: %s", got.Body)
	}
	// Smuggling attempts never arrive: each is refused before the daemon.
	before := len(h.daemon.requests())
	for _, b := range []string{
		`{"Image":"x","HostConfig":{"Privileged":false,"privileged":true}}`,
		`{"Image":"x","HostConfig":{"CapDrop":["NET_RAW"],"CapDrop":[]}}`,
		`{"Image":"x","HostConfig":{"Binds":[],"BINDS":["/etc:/e"]}}`,
	} {
		if st, resp := h.raw(t, "POST", "/containers/create", b); st != http.StatusForbidden {
			t.Errorf("%s: %d %s", b, st, resp)
		}
	}
	if len(h.daemon.requests()) != before {
		t.Error("a smuggling attempt reached the daemon")
	}
	// Oversized.
	big := `{"Image":"x","Labels":{"a":"` + strings.Repeat("a", MaxBody) + `"}}`
	if st, resp := h.raw(t, "POST", "/containers/create", big); st != http.StatusForbidden || !strings.Contains(resp, "larger") {
		t.Errorf("oversized: %d %s", st, resp)
	}
}

func TestOtherBodies(t *testing.T) {
	f := testFilter(t)
	for _, c := range []struct {
		name string
		dec  func(*Filter, []byte) ([]byte, error)
		body string
		ok   bool
	}{
		{"exec", decodeExec, `{"User":"","Privileged":false,"Tty":false,"AttachStdin":false,"AttachStderr":true,"AttachStdout":true,"Detach":false,"DetachKeys":"","Env":null,"WorkingDir":"","Cmd":["cat","/i"]}`, true},
		{"exec with console size", decodeExec, `{"Cmd":"true","ConsoleSize":[24,80],"User":"1000","Env":["X=y"],"WorkingDir":"/tmp"}`, true},
		{"exec privileged", decodeExec, `{"Cmd":["true"],"Privileged":true}`, false},
		{"exec unknown", decodeExec, `{"Cmd":["true"],"Frobnicate":true}`, false},
		{"exec start", decodeExecStart, `{"Detach":false,"Tty":true,"ConsoleSize":[24,80]}`, true},
		{"exec start privileged", decodeExecStart, `{"Privileged":true}`, false},
		{"exec start Detach dup", decodeExecStart, `{"Detach":true,"Detach":false}`, false},
		{"network", decodeNetworkCreate, `{"Name":"f-net","Driver":"bridge","Scope":"","EnableIPv4":null,"EnableIPv6":null,"IPAM":{"Driver":"default","Options":{},"Config":[]},"Internal":false,"Attachable":false,"Ingress":false,"ConfigOnly":false,"ConfigFrom":null,"Options":{},"Labels":{}}`, true},
		{"network options", decodeNetworkCreate, `{"Name":"n","Options":{"com.docker.network.bridge.name":"br1","com.docker.network.bridge.enable_icc":"false","com.docker.network.bridge.enable_ip_masquerade":"true","com.docker.network.driver.mtu":"1400","com.docker.network.bridge.host_binding_ipv4":"127.0.0.1"},"IPAM":{"Config":[{"Subnet":"10.9.0.0/24","Gateway":"10.9.0.1","AuxiliaryAddresses":{"a":"10.9.0.2"}}]},"Labels":{"com.docker.compose.network":"default"}}`, true},
		{"network macvlan", decodeNetworkCreate, `{"Name":"n","Driver":"macvlan"}`, false},
		{"network host", decodeNetworkCreate, `{"Name":"n","Driver":"host"}`, false},
		{"network every interface", decodeNetworkCreate, `{"Name":"n","Options":{"com.docker.network.bridge.host_binding_ipv4":"0.0.0.0"}}`, false},
		{"network gateway mode", decodeNetworkCreate, `{"Name":"n","Options":{"com.docker.network.bridge.gateway_mode_ipv4":"routed"}}`, false},
		{"network ingress", decodeNetworkCreate, `{"Name":"n","Ingress":true}`, false},
		{"network config-only", decodeNetworkCreate, `{"Name":"n","ConfigOnly":true}`, false},
		{"network config-from", decodeNetworkCreate, `{"Name":"n","ConfigFrom":{"Network":"x"}}`, false},
		{"network swarm scope", decodeNetworkCreate, `{"Name":"n","Scope":"swarm"}`, false},
		{"network ipam driver", decodeNetworkCreate, `{"Name":"n","IPAM":{"Driver":"other"}}`, false},
		{"connect", decodeNetworkConnect, `{"Container":"c","EndpointConfig":{"Aliases":["a"],"IPAMConfig":{"IPv4Address":"10.0.0.2"}}}`, true},
		{"connect driver opts", decodeNetworkConnect, `{"Container":"c","EndpointConfig":{"DriverOpts":{"a":"b"}}}`, false},
		{"disconnect", decodeNetworkDisconnect, `{"Container":"c","Force":true}`, true},
		{"disconnect unknown", decodeNetworkDisconnect, `{"Container":"c","EndpointConfig":{}}`, false},
		{"volume", decodeVolumeCreate, `{"Name":"v","Driver":"","DriverOpts":{},"Labels":{"a":"b"}}`, true},
		{"volume local", decodeVolumeCreate, `{"Name":"v","Driver":"local","DriverOpts":null,"ClusterVolumeSpec":null}`, true},
		{"volume bind", decodeVolumeCreate, `{"Name":"v","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/etc"}}`, false},
		{"volume other driver", decodeVolumeCreate, `{"Name":"v","Driver":"other"}`, false},
		{"volume cluster", decodeVolumeCreate, `{"Name":"v","ClusterVolumeSpec":{"Group":"g"}}`, false},
		{"commit", decodeCommit, `{"Image":"x","Cmd":["sh"],"Env":["A=b"]}`, true},
		{"commit null", decodeCommit, `null`, true},
		{"commit unknown", decodeCommit, `{"Image":"x","HostConfig":{"Privileged":true}}`, false},
	} {
		out, err := c.dec(f, []byte(c.body))
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v out=%s", c.name, err, out)
		}
	}
}

// FuzzCreate checks the filter's invariant: whatever body it forwards,
// the daemon's way of reading it (encoding/json into the same structure,
// keys matched in any case, the last of two duplicates winning) yields a
// configuration that passes validation, and the same configuration again.
func FuzzCreate(f *testing.F) {
	for _, s := range []string{
		`{"Image":"busybox:1.36","Cmd":["true"]}`,
		`{"Image":"x","HostConfig":{"Privileged":true}}`,
		`{"Image":"x","HostConfig":{"Privileged":false,"privileged":true}}`,
		`{"Image":"x","HostConfig":{"Binds":["/ws:/w","/etc:/e"],"CapAdd":["IPC_LOCK"],"CapDrop":["ALL"]}}`,
		`{"Image":"x","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ws","Target":"/w","BindOptions":{"Propagation":"rprivate"}}]}}`,
		`{"Image":"x","HostConfig":{"MaskedPaths":null,"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"80"}]}}}`,
		`{"Image":"x","HostConfig":{"Privile\u0067ed":true}}`,
		`{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"n":{"Aliases":["a"]}}},"HostConfig":{"NetworkMode":"n"}}`,
		`{"Cmd":"x","Entrypoint":[],"Shell":null,"Healthcheck":{"Test":["NONE"]}}`,
	} {
		f.Add([]byte(s))
	}
	fl := &Filter{cfg: &Config{DaemonSocket: "/nonexistent/d.sock", Workspace: "/ws", Runtimes: []string{"devkit-runc"}, Capabilities: []string{"IPC_LOCK"}}}
	f.Fuzz(func(t *testing.T, body []byte) {
		out, err := decodeCreate(fl, body)
		if err != nil {
			return
		}
		var daemon CreateRequest
		if err := json.Unmarshal(out, &daemon); err != nil {
			t.Fatalf("the forwarded body does not decode: %v\n%s", err, out)
		}
		if err := fl.validateCreate(&daemon); err != nil {
			t.Fatalf("the daemon would read a configuration the filter refuses: %v\nin:  %q\nout: %s", err, body, out)
		}
		again, _ := json.Marshal(&daemon)
		if !bytes.Equal(again, out) {
			t.Fatalf("the daemon would read something other than what was validated:\nout:   %s\nagain: %s", out, again)
		}
	})
}
