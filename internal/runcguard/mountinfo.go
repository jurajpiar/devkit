package runcguard

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strings"
)

// MountEntry is one line of /proc/<pid>/mountinfo.
type MountEntry struct {
	Dev    string // major:minor
	Root   string // the path within the filesystem that is mounted
	Point  string // where it is mounted
	FSType string
	Source string
}

// ParseMountinfo reads a mountinfo table: "id parent major:minor root
// mountpoint options [optional fields...] - fstype source superoptions",
// with spaces, tabs, newlines and backslashes in paths written as octal
// escapes.
func ParseMountinfo(r io.Reader) ([]MountEntry, error) {
	var out []MountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		f := strings.Split(line, " ")
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 10 || sep < 0 || sep+2 >= len(f) {
			return nil, fmt.Errorf("mountinfo line %d: cannot read %q", n, line)
		}
		root, err := unescape(f[3])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %v", n, err)
		}
		point, err := unescape(f[4])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %v", n, err)
		}
		src, err := unescape(f[sep+2])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %v", n, err)
		}
		if !strings.Contains(f[2], ":") {
			return nil, fmt.Errorf("mountinfo line %d: bad device %q", n, f[2])
		}
		out = append(out, MountEntry{Dev: f[2], Root: root, Point: point, FSType: f[sep+1], Source: src})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the mount table is empty")
	}
	return out, nil
}

// unescape decodes the kernel's \ooo escapes.
func unescape(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		v := 0
		for _, c := range []byte(s[i+1 : i+4]) {
			if c < '0' || c > '7' {
				return "", fmt.Errorf("bad escape in %q", s)
			}
			v = v*8 + int(c-'0')
		}
		if v > 255 {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

// Policy is where a container's mounts of existing filesystems may come
// from.
type Policy struct {
	Workspace  string
	DataRoot   string
	DockerInit string
	// ContainerID is the container being created: runc's container ID,
	// which is Docker's, and the name of its directory under the data
	// root. Only that directory's files may be mounted into it.
	ContainerID string
	// Cgroup is the container's own cgroup, as /proc/<pid>/cgroup gives it
	// to the guard. A cgroup2 mount passes only at or below it.
	Cgroup string
	// Gofer says the table is a gVisor gofer's rather than a runc
	// container's. A gofer holds only the container's root and the host
	// files it serves to the sandbox: its proc, sysfs, cgroups, devices and
	// tmpfs mounts are the sandbox's own and never appear in its table. So
	// none of runc's exceptions for kernel filesystems applies, and neither
	// does the pass for a filesystem made for the container: anything in a
	// gofer's table other than its root overlay and the allowed paths of
	// the VM's root filesystem is refused.
	Gofer bool
}

// containerFiles are the files Docker mounts into a container from the
// container's own directory under the data root. The directory also holds
// what Docker reads the container's settings and privileges from
// (config.v2.json, hostconfig.json), its log and its checkpoints, none of
// which a container is given.
var containerFiles = map[string]bool{"hosts": true, "hostname": true, "resolv.conf": true}

// devNodes are the device nodes runc binds into every rootless container.
var devNodes = map[string]bool{"/null": true, "/zero": true, "/full": true, "/tty": true, "/random": true, "/urandom": true}

// canonicalPoint is where the VM's own instance of a kernel filesystem may
// appear in a container: runc binds the VM's sysfs and mqueue in their
// place when a rootless container may not mount new ones. A container's
// devpts is always a new instance.
var canonicalPoint = map[string]string{"sysfs": "/sys", "mqueue": "/dev/mqueue"}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// Check returns the first of the container's mounts that comes from
// outside where mounts may come from, or nil. host is the guard's own
// mount table, which is the daemon's: a device that does not appear in it
// is a filesystem made for the container (its proc, its tmpfs, its devpts)
// and passes, except a namespace file, whose filesystem never appears
// there. Of the filesystems that exist outside the container, only these
// pass: the overlay at its root; cgroup2 at or below the container's own
// cgroup; sysfs and mqueue whole and where they belong; the device nodes
// rootless containers bind; the container's own shared-memory tmpfs; and
// from the VM's root filesystem, the workspace, a volume's data, the
// container's own hosts, hostname and resolv.conf, and docker-init. The
// VM's /proc never passes: a container's own proc is always a new
// filesystem.
func Check(host, ctr []MountEntry, p Policy) *MountEntry {
	devs := map[string]bool{}
	var rootMount *MountEntry
	for i := range host {
		devs[host[i].Dev] = true
		if host[i].Point == "/" {
			rootMount = &host[i]
		}
	}
	// Paths on the root filesystem as mountinfo writes them: relative to
	// the filesystem's root, which is "/" unless "/" is a subvolume.
	fsPath := func(p string) string {
		if rootMount == nil || rootMount.Root == "/" {
			return p
		}
		return path.Join(rootMount.Root, p)
	}
	for i := range ctr {
		m := &ctr[i]
		if m.FSType == "nsfs" {
			return m // a handle on another namespace: Docker never mounts one
		}
		if p.Gofer {
			if m.FSType == "overlay" && m.Point == "/" && m.Root == "/" {
				continue
			}
			if rootMount != nil && m.Dev == rootMount.Dev && allowedOnRoot(m.Root, p, fsPath) {
				continue
			}
			return m
		}
		if !devs[m.Dev] {
			continue
		}
		switch {
		case m.FSType == "overlay" && m.Point == "/":
			continue
		case m.FSType == "cgroup2" && p.Cgroup != "" && under(m.Root, p.Cgroup):
			continue
		case m.FSType == "tmpfs" && m.Root == "/" && ownShm(host, m.Dev, p):
			continue
		case m.FSType == "proc":
			return m
		case canonicalPoint[m.FSType] != "" && m.Root == "/" && m.Point == canonicalPoint[m.FSType]:
			continue
		case m.FSType == "devtmpfs" && devNodes[m.Root]:
			continue
		}
		if rootMount != nil && m.Dev == rootMount.Dev && allowedOnRoot(m.Root, p, fsPath) {
			continue
		}
		return m
	}
	return nil
}

// GoferFinal reports whether a gofer's mount table is in its final form:
// exactly one mount at "/", and that the container's root overlay, whole.
// runsc's gofer first builds the container's tree under a tmpfs of its own
// (its "/" a tmpfs, the overlay at /root and every bind below it) and then
// moves into it; before that, its table is the daemon's, with the VM's root
// at "/". Neither is a table to judge, only to wait out: the overlay at
// /root says nothing about where the binds will appear. Two mounts at "/"
// are a root being replaced, not a root.
func GoferFinal(t []MountEntry) bool {
	n, ok := 0, true
	for _, m := range t {
		if m.Point == "/" {
			n++
			ok = ok && m.FSType == "overlay" && m.Root == "/"
		}
	}
	return n == 1 && ok
}

// SandboxFinal reports whether a gVisor sandbox's mount table is in its
// final form: exactly one mount at "/", and that a new tmpfs (a device the
// guard's own table does not have), whole. Until the sandbox has moved into
// it, its table is a copy of the daemon's, with the VM's root at "/".
func SandboxFinal(host, t []MountEntry) bool {
	n, ok := 0, true
	for i := range t {
		if m := &t[i]; m.Point == "/" {
			n++
			ok = ok && m.FSType == "tmpfs" && m.Root == "/" && !hasDev(host, m.Dev)
		}
	}
	return n == 1 && ok
}

func hasDev(host []MountEntry, dev string) bool {
	for _, h := range host {
		if h.Dev == dev {
			return true
		}
	}
	return false
}

// sandboxProc are the two mounts a sandbox holds besides its root from
// runsc create until its container starts, at exactly these points: a
// tmpfs at /proc and a proc at /proc/sandbox-proc, which the sandbox
// unmounts once running. Each must be a new filesystem: a proc of the
// guard's own table is the VM's process tree.
var sandboxProc = map[string]string{"/proc": "tmpfs", "/proc/sandbox-proc": "proc"}

// CheckSandbox returns what is wrong with a gVisor sandbox's mount table,
// or nil. The sentry runs in a mount namespace whose root is a new tmpfs:
// every host file it reaches comes through the gofer, whose table Check
// judges. The table must start with that root, and may hold besides it
// only the new tmpfs at /proc and new proc at /proc/sandbox-proc, each at
// most once. Anything else, a filesystem of the VM's among them, is
// returned.
func CheckSandbox(host, sb []MountEntry) *MountEntry {
	seen := map[string]bool{}
	for i := range sb {
		m := &sb[i]
		if hasDev(host, m.Dev) || m.Root != "/" {
			return m
		}
		if i == 0 {
			if m.FSType != "tmpfs" || m.Point != "/" {
				return m
			}
			continue
		}
		if fs, ok := sandboxProc[m.Point]; !ok || fs != m.FSType || seen[m.Point] {
			return m
		}
		seen[m.Point] = true
	}
	return nil
}

// validID is a container ID the guard can match to a directory: one path
// component.
func validID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.Contains(id, "/")
}

// ownShm reports whether dev is the tmpfs Docker mounts at the container's
// own shm directory, which it does for --ipc shareable.
func ownShm(host []MountEntry, dev string, p Policy) bool {
	if !validID(p.ContainerID) {
		return false
	}
	want := path.Join(p.DataRoot, "containers", p.ContainerID, "mounts", "shm")
	for _, h := range host {
		if h.Dev == dev && h.FSType == "tmpfs" && h.Root == "/" && h.Point == want {
			return true
		}
	}
	return false
}

// allowedOnRoot is the rule for mounts of the VM's root filesystem.
// Volumes and container files are matched to Docker's own layout:
// <data>/volumes/<name>/_data and below, and of <data>/containers/, only
// the three files Docker gives a container from its own directory.
// mountinfo gives the path a mount was made from with its symlinks
// resolved, so a link elsewhere named like one of these does not pass.
func allowedOnRoot(root string, p Policy, fsPath func(string) string) bool {
	if under(root, fsPath(p.Workspace)) || root == fsPath(p.DockerInit) {
		return true
	}
	if rel, ok := strings.CutPrefix(root, fsPath(p.DataRoot)+"/volumes/"); ok {
		parts := strings.Split(rel, "/")
		return len(parts) >= 2 && parts[0] != "" && parts[1] == "_data"
	}
	if rel, ok := strings.CutPrefix(root, fsPath(p.DataRoot)+"/containers/"); ok {
		id, file, _ := strings.Cut(rel, "/")
		return validID(p.ContainerID) && id == p.ContainerID && containerFiles[file]
	}
	return false
}
