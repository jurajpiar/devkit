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
}

// devNodes are the device nodes runc binds into every rootless container.
var devNodes = map[string]bool{"/null": true, "/zero": true, "/full": true, "/tty": true, "/random": true, "/urandom": true}

// canonicalPoint is where each kernel filesystem of a container's own
// belongs.
var canonicalPoint = map[string]string{"sysfs": "/sys", "mqueue": "/dev/mqueue", "devpts": "/dev/pts"}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// Check returns the first of the container's mounts that comes from
// outside where mounts may come from, or nil. host is the guard's own
// mount table, which is the daemon's: a device that does not appear in it
// is a filesystem made for the container (its proc, its tmpfs, its devpts)
// and passes. Of the filesystems that exist outside the container, only
// these pass: the overlay at its root; cgroup2; sysfs, mqueue and devpts
// whole and where they belong; the device nodes rootless containers bind;
// and from the VM's root filesystem, the workspace, a volume's data, a
// container's own files under the data root, and docker-init. The VM's
// /proc never passes: a container's own proc is always a new filesystem.
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
		if !devs[m.Dev] {
			continue
		}
		switch {
		case m.FSType == "overlay" && m.Point == "/":
			continue
		case m.FSType == "cgroup2":
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

// allowedOnRoot is the rule for mounts of the VM's root filesystem.
// Volumes and container files are matched to Docker's own layout:
// <data>/volumes/<name>/_data and below, <data>/containers/<id>/<file>
// and below, never the directories that hold every volume or container.
func allowedOnRoot(root string, p Policy, fsPath func(string) string) bool {
	if under(root, fsPath(p.Workspace)) || root == fsPath(p.DockerInit) {
		return true
	}
	if rel, ok := strings.CutPrefix(root, fsPath(p.DataRoot)+"/volumes/"); ok {
		parts := strings.Split(rel, "/")
		return len(parts) >= 2 && parts[0] != "" && parts[1] == "_data"
	}
	if rel, ok := strings.CutPrefix(root, fsPath(p.DataRoot)+"/containers/"); ok {
		parts := strings.Split(rel, "/")
		return len(parts) >= 2 && parts[0] != "" && parts[1] != ""
	}
	return false
}
