package dockerfilter

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// nameRe is a plain Docker object name: a volume, a network or a container.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// empty reports whether v holds nothing: null, false, 0, "", [] or {}.
// What the real Docker client sends for a setting it does not use is one
// of these, depending on the type.
func empty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Invalid:
		return true
	case reflect.Pointer, reflect.Interface:
		return v.IsNil() || empty(v.Elem())
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !empty(v.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !empty(v.Field(i)) {
				return false
			}
		}
		return true
	}
	return v.IsZero()
}

func mustBeEmpty(field string, v any) error {
	if !empty(reflect.ValueOf(v)) {
		return fmt.Errorf("%s is not allowed", field)
	}
	return nil
}

func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q is not allowed", field, v)
}

// validateCreate checks a container create request and adds what the
// filter enforces on every container. Anything it does not list as
// allowed must be at its zero value.
func (f *Filter) validateCreate(r *CreateRequest) error {
	if r.HostConfig == nil {
		r.HostConfig = &HostConfig{}
	}
	h := r.HostConfig
	for _, z := range []struct {
		field string
		v     any
	}{
		{"HostConfig.Privileged", h.Privileged},
		{"HostConfig.Devices", h.Devices},
		{"HostConfig.DeviceCgroupRules", h.DeviceCgroupRules},
		{"HostConfig.DeviceRequests", h.DeviceRequests},
		{"HostConfig.Sysctls", h.Sysctls},
		{"HostConfig.CgroupParent", h.CgroupParent},
		{"HostConfig.Cgroup", h.Cgroup},
		{"HostConfig.VolumeDriver", h.VolumeDriver},
		{"HostConfig.StorageOpt", h.StorageOpt},
		{"HostConfig.Isolation", h.Isolation},
		{"HostConfig.Annotations", h.Annotations},
		{"HostConfig.OomScoreAdj", h.OomScoreAdj},
		{"HostConfig.OomKillDisable", h.OomKillDisable},
		{"HostConfig.UsernsMode", h.UsernsMode},
		{"HostConfig.UTSMode", h.UTSMode},
		{"HostConfig.KernelMemory", h.KernelMemory},
		{"HostConfig.KernelMemoryTCP", h.KernelMemoryTCP},
		{"HostConfig.CpuRealtimePeriod", h.CPURealtimePeriod},
		{"HostConfig.CpuRealtimeRuntime", h.CPURealtimeRuntime},
		{"HostConfig.BlkioWeightDevice", h.BlkioWeightDevice},
		{"HostConfig.BlkioDeviceReadBps", h.BlkioDeviceReadBps},
		{"HostConfig.BlkioDeviceWriteBps", h.BlkioDeviceWriteBps},
		{"HostConfig.BlkioDeviceReadIOps", h.BlkioDeviceReadIOps},
		{"HostConfig.BlkioDeviceWriteIOps", h.BlkioDeviceWriteIOps},
		{"HostConfig.IOMaximumIOps", h.IOMaximumIOps},
		{"HostConfig.IOMaximumBandwidth", h.IOMaximumBandwidth},
		{"HostConfig.CpuCount", h.CPUCount},
		{"HostConfig.CpuPercent", h.CPUPercent},
		{"HostConfig.Capabilities", h.Capabilities},
	} {
		if err := mustBeEmpty(z.field, z.v); err != nil {
			return err
		}
	}
	// null keeps the daemon's masks; an empty list, which is what
	// --security-opt systempaths=unconfined sends, removes them.
	if h.MaskedPaths != nil {
		return errors.New("HostConfig.MaskedPaths is not allowed")
	}
	if h.ReadonlyPaths != nil {
		return errors.New("HostConfig.ReadonlyPaths is not allowed")
	}
	if err := oneOf("HostConfig.CgroupnsMode", h.CgroupnsMode, "", "private"); err != nil {
		return err
	}
	if err := oneOf("HostConfig.PidMode", h.PidMode, "", "private"); err != nil {
		return err
	}
	if err := oneOf("HostConfig.IpcMode", h.IpcMode, "", "private", "none", "shareable"); err != nil {
		return err
	}
	for _, o := range h.SecurityOpt {
		if err := oneOf("HostConfig.SecurityOpt", o, "no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"); err != nil {
			return err
		}
	}
	allowed := f.cfg.allowedCaps()
	for _, c := range h.CapAdd {
		n := normCap(c)
		if n == "CAP_ALL" || !allowed[n] {
			return fmt.Errorf("HostConfig.CapAdd %q is not allowed", c)
		}
	}
	dropped := false
	for _, c := range h.CapDrop {
		if n := normCap(c); n == "CAP_ALL" || n == "CAP_NET_RAW" {
			dropped = true
		}
	}
	if !dropped {
		h.CapDrop = append(h.CapDrop, "NET_RAW")
	}
	if h.Runtime != "" && !f.cfg.allowedRuntime(h.Runtime) {
		return fmt.Errorf("HostConfig.Runtime %q is not allowed", h.Runtime)
	}
	if err := checkNetworkMode(h.NetworkMode); err != nil {
		return err
	}
	// A binding with no address takes the network's default, which is
	// loopback for the default bridge and for networks made through the
	// filter, but not for one made before it. Naming loopback here makes
	// the binding the same on every network.
	for port, bindings := range h.PortBindings {
		for i, b := range bindings {
			if err := oneOf("HostConfig.PortBindings["+port+"].HostIp", b.HostIP, "", "127.0.0.1", "::1"); err != nil {
				return err
			}
			if b.HostIP == "" {
				bindings[i].HostIP = "127.0.0.1"
			}
		}
	}
	if err := oneOf("HostConfig.LogConfig.Type", h.LogConfig.Type, "", "json-file", "local", "none"); err != nil {
		return err
	}
	for k := range h.LogConfig.Config {
		if err := oneOf("HostConfig.LogConfig.Config key", k, "max-size", "max-file", "compress", "labels", "env", "tag", "mode", "max-buffer-size"); err != nil {
			return err
		}
	}
	for _, b := range h.Binds {
		if err := f.checkBind(b); err != nil {
			return err
		}
	}
	for i := range h.Mounts {
		if string(h.Mounts[i].ClusterOptions) == "null" {
			h.Mounts[i].ClusterOptions = nil
		}
		if err := f.checkMount(h.Mounts[i]); err != nil {
			return fmt.Errorf("HostConfig.Mounts[%d]: %v", i, err)
		}
	}
	if r.NetworkingConfig != nil {
		for n, ep := range r.NetworkingConfig.EndpointsConfig {
			if !nameRe.MatchString(n) || n == "host" {
				return fmt.Errorf("NetworkingConfig.EndpointsConfig %q is not allowed", n)
			}
			if err := checkEndpoint(ep); err != nil {
				return fmt.Errorf("NetworkingConfig.EndpointsConfig[%s]: %v", n, err)
			}
		}
	}
	return nil
}

func checkNetworkMode(m string) error {
	switch {
	case m == "" || m == "default" || m == "bridge" || m == "none":
		return nil
	case strings.HasPrefix(m, "container:"):
		if nameRe.MatchString(strings.TrimPrefix(m, "container:")) {
			return nil
		}
	case m != "host" && nameRe.MatchString(m):
		return nil
	}
	return fmt.Errorf("HostConfig.NetworkMode %q is not allowed", m)
}

func checkEndpoint(ep *EndpointSettings) error {
	if ep == nil {
		return nil
	}
	return mustBeEmpty("DriverOpts", ep.DriverOpts)
}

// The bind options the daemon knows, and the ones a bind may have here.
var (
	propagationModes = map[string]bool{"shared": true, "rshared": true, "slave": true, "rslave": true, "private": true, "rprivate": true}
	bindModes        = map[string]bool{"ro": true, "rw": true, "z": true, "Z": true, "nocopy": true, "cached": true, "delegated": true, "consistent": true}
)

// daemonMode reports whether the daemon would read s as the mode part of a
// bind, which is how it tells "dst:mode" from "src:dst".
func daemonMode(s string) bool {
	if s == "" {
		return false
	}
	for _, o := range strings.Split(s, ",") {
		if !bindModes[o] && !propagationModes[o] {
			return false
		}
	}
	return true
}

// splitBind splits one HostConfig.Binds entry the way the daemon's Linux
// parser splits it, and returns its source ("" for an anonymous volume)
// and its mode.
func splitBind(b string) (src, mode string, err error) {
	arr := strings.SplitN(b, ":", 4)
	switch len(arr) {
	case 1:
	case 2:
		if daemonMode(arr[1]) {
			mode = arr[1]
		} else {
			src = arr[0]
		}
	case 3:
		src, mode = arr[0], arr[2]
	default:
		return "", "", fmt.Errorf("HostConfig.Binds %q is not a bind the filter can read", b)
	}
	if arr[0] == "" {
		return "", "", fmt.Errorf("HostConfig.Binds %q is not a bind the filter can read", b)
	}
	return src, mode, nil
}

// checkBind checks one HostConfig.Binds entry.
func (f *Filter) checkBind(b string) error {
	src, mode, err := splitBind(b)
	if err != nil {
		return err
	}
	if mode != "" {
		for _, o := range strings.Split(mode, ",") {
			if !bindModes[o] {
				return fmt.Errorf("HostConfig.Binds %q: option %q is not allowed", b, o)
			}
		}
	}
	if src == "" || nameRe.MatchString(src) {
		return nil // an anonymous or named volume
	}
	if err := f.checkSource(src); err != nil {
		return fmt.Errorf("HostConfig.Binds %q: %v", b, err)
	}
	return nil
}

func (f *Filter) checkMount(m Mount) error {
	if m.ClusterOptions != nil {
		return errors.New("ClusterOptions is not allowed")
	}
	if m.ImageOptions != nil {
		return errors.New("ImageOptions is not allowed")
	}
	switch m.Type {
	case "bind":
		if m.VolumeOptions != nil || m.TmpfsOptions != nil {
			return errors.New("a bind mount takes bind options only")
		}
		if o := m.BindOptions; o != nil {
			if err := oneOf("BindOptions.Propagation", o.Propagation, "", "rprivate"); err != nil {
				return err
			}
		}
		return f.checkSource(m.Source)
	case "volume":
		if m.BindOptions != nil || m.TmpfsOptions != nil {
			return errors.New("a volume mount takes volume options only")
		}
		if m.Source != "" && !nameRe.MatchString(m.Source) {
			return fmt.Errorf("volume name %q is not allowed", m.Source)
		}
		if o := m.VolumeOptions; o != nil {
			if err := mustBeEmpty("VolumeOptions.DriverConfig", o.DriverConfig); err != nil {
				return err
			}
		}
		return nil
	case "tmpfs":
		if m.BindOptions != nil || m.VolumeOptions != nil || m.Source != "" {
			return errors.New("a tmpfs mount takes a size and a mode only")
		}
		if o := m.TmpfsOptions; o != nil {
			if err := mustBeEmpty("TmpfsOptions.Options", o.Options); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("mount type %q is not allowed", m.Type)
}

// checkSource allows a bind source in the workspace: by its path as asked,
// and by where its symlinks lead now. The second is checked again by the
// runtime guard on the mount as made, when the guard is there, since the
// workspace is the sandbox user's to rearrange between this check and the
// mount. A walk that has left the workspace is refused even when it cannot
// go on. Where the filter may not read a directory inside the workspace,
// the walk stops there: with the guard behind it, the lexical check stands
// for the rest; without it, nothing would check the rest, so the source is
// refused.
func (f *Filter) checkSource(src string) error {
	if !path.IsAbs(src) {
		return fmt.Errorf("source %q is not an absolute path", src)
	}
	clean := filepath.Clean(src)
	if !under(clean, f.cfg.Workspace) {
		return fmt.Errorf("source %s is outside the workspace", src)
	}
	walks := []string{clean}
	if clean != src {
		// The kernel follows a symlink before it applies a "..", which the
		// cleaned path has already removed: the path as written is walked
		// too, in case the daemon passes it on unclean.
		walks = append(walks, src)
	}
	for _, p := range walks {
		real, err := resolve(p)
		switch {
		case !under(real, f.cfg.Workspace):
			return fmt.Errorf("source %s leads outside the workspace, to %s", src, real)
		case errors.Is(err, fs.ErrPermission) && f.cfg.RuntimeGuard:
		case errors.Is(err, fs.ErrPermission):
			return fmt.Errorf("source %s cannot be checked: the filter may not look inside %s, and under this runtime nothing else checks the mount. "+
				"Make the directories on the way readable by others (chmod o+rx), or mount a path the filter can read", src, filepath.Dir(real))
		case err != nil:
			return fmt.Errorf("source %s: %v", src, err)
		}
	}
	return nil
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// resolve follows p's symlinks one component at a time, as the kernel
// would, and returns where p leads. Components that do not exist yet are
// appended as they are: the daemon creates a missing bind source as
// directories. If a component cannot be read, it returns the path resolved
// up to that component, and the error.
func resolve(p string) (string, error) {
	rest := strings.Split(p, "/")
	cur := "/"
	for links := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			return filepath.Join(append([]string{next}, rest...)...), nil
		}
		if err != nil {
			return next, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if links++; links > 40 {
			return next, errors.New("too many levels of symlinks")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return next, err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return cur, nil
}

func (f *Filter) validateExec(e *ExecConfig) error {
	if e.Privileged {
		return errors.New("Privileged is not allowed")
	}
	return nil
}

// The bridge options a network may set.
var networkOptions = map[string]bool{
	"com.docker.network.bridge.name":                 true,
	"com.docker.network.bridge.enable_icc":           true,
	"com.docker.network.bridge.enable_ip_masquerade": true,
	"com.docker.network.driver.mtu":                  true,
	"com.docker.network.bridge.host_binding_ipv4":    true,
}

func (f *Filter) validateNetworkCreate(n *NetworkCreate) error {
	if err := oneOf("Driver", n.Driver, "", "bridge"); err != nil {
		return err
	}
	if err := oneOf("Scope", n.Scope, "", "local"); err != nil {
		return err
	}
	if n.Ingress {
		return errors.New("Ingress is not allowed")
	}
	if n.ConfigOnly {
		return errors.New("ConfigOnly is not allowed")
	}
	if err := mustBeEmpty("ConfigFrom", n.ConfigFrom); err != nil {
		return err
	}
	// A network's ports are published on its own default address, not the
	// daemon's: the daemon's "ip" setting is the default bridge's only. The
	// filter sets loopback on every network it lets the user make.
	if n.Options == nil {
		n.Options = map[string]string{}
	}
	if _, ok := n.Options[loopbackOption]; !ok {
		n.Options[loopbackOption] = "127.0.0.1"
	}
	keys := make([]string, 0, len(n.Options))
	for k := range n.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !networkOptions[k] {
			return fmt.Errorf("network option %q is not allowed", k)
		}
		if k == loopbackOption && n.Options[k] != "127.0.0.1" {
			return fmt.Errorf("network option %s=%q is not allowed", k, n.Options[k])
		}
	}
	if n.IPAM != nil {
		if err := oneOf("IPAM.Driver", n.IPAM.Driver, "", "default"); err != nil {
			return err
		}
	}
	return nil
}

func (f *Filter) validateNetworkConnect(n *NetworkConnect) error {
	return checkEndpoint(n.EndpointConfig)
}

func (f *Filter) validateVolumeCreate(v *VolumeCreate) error {
	if err := oneOf("Driver", v.Driver, "", "local"); err != nil {
		return err
	}
	if err := mustBeEmpty("DriverOpts", v.DriverOpts); err != nil {
		return err
	}
	if v.ClusterVolumeSpec != nil && string(v.ClusterVolumeSpec) != "null" {
		return errors.New("ClusterVolumeSpec is not allowed")
	}
	v.ClusterVolumeSpec = nil
	return nil
}
