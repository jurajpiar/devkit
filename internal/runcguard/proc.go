package runcguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// fileID is a file's identity: its device and inode.
type fileID struct{ Dev, Ino uint64 }

func statID(fi os.FileInfo) (fileID, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, errors.New("no device and inode")
	}
	return fileID{uint64(st.Dev), st.Ino}, nil
}

// procEntry is one process's directory under /proc, held open: every read
// through it is of that process, or fails once it has exited, even if its
// pid has been given to another process since.
type procEntry interface {
	ReadFile(name string) ([]byte, error)
	// ExeID is the identity of the file the process runs, taken through
	// its exe link rather than from the link's text, which is a path in
	// the process's own mount namespace.
	ExeID() (fileID, error)
	Close() error
}

// procInfo is what the guard reads to recognise a process.
type procInfo struct {
	PPid int
	// UID is the real and effective uid, when both are the same, as the
	// guard's user namespace sees them; -1 otherwise.
	UID  int
	Argv []string
}

func readProcInfo(e procEntry) (procInfo, error) {
	var in procInfo
	stat, err := e.ReadFile("stat")
	if err != nil {
		return in, err
	}
	// "pid (comm) state ppid ...": comm is the process's to choose and may
	// hold spaces and parentheses, so fields are counted from the last ')'.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return in, errors.New("cannot read stat")
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 2 {
		return in, errors.New("cannot read stat")
	}
	if in.PPid, err = strconv.Atoi(f[1]); err != nil {
		return in, errors.New("cannot read stat")
	}
	status, err := e.ReadFile("status")
	if err != nil {
		return in, err
	}
	in.UID = -1
	for _, l := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(l, "Uid:"); ok {
			u := strings.Fields(rest)
			if len(u) >= 2 && u[0] == u[1] {
				if n, err := strconv.Atoi(u[0]); err == nil {
					in.UID = n
				}
			}
		}
	}
	cmd, err := e.ReadFile("cmdline")
	if err != nil {
		return in, err
	}
	in.Argv = strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	return in, nil
}

// goferFor reports whether argv is a gofer's command line for the
// container whose bundle is bundle: runsc starts its gofer as
// "runsc-gofer <global flags> gofer --bundle <bundle> ...". The bundle is
// matched as a whole argument, so another container's bundle that merely
// begins with this one's does not match. A process can write any command
// line for itself; this only tells gofers apart, and the exe, the uid and
// the parent are what a container cannot forge.
func goferFor(argv []string, bundle string) bool {
	if len(argv) == 0 || argv[0] != "runsc-gofer" {
		return false
	}
	sub := -1
	for i, a := range argv[1:] {
		if a == "gofer" {
			sub = i + 1
			break
		}
	}
	if sub < 0 {
		return false
	}
	rest := argv[sub+1:]
	for i, a := range rest {
		if a == "--bundle="+bundle || (a == "--bundle" && i+1 < len(rest) && rest[i+1] == bundle) {
			return true
		}
	}
	return false
}

// isGofer reports whether the process is the gofer the guard is looking
// for. What a process says of itself is read first, and its executable
// last: a process that is not a gofer of this container is not opened.
func isGofer(e procEntry, ppid, uid int, runsc fileID, bundle string) bool {
	in, err := readProcInfo(e)
	if err != nil || in.PPid != ppid || in.UID != uid || !goferFor(in.Argv, bundle) {
		return false
	}
	exe, err := e.ExeID()
	return err == nil && exe == runsc
}

// findGofer finds the gofer of the sandbox whose pid is sandbox and whose
// parent is ppid, and returns it held open. A gofer is a process that runs
// the real runsc (by device and inode, which no process in a container can
// give itself without the file being mounted into it), as the guard's own
// uid, with the sandbox's parent (runsc create starts both, and when it
// exits both pass to the same reaper), and with this container's bundle on
// its command line. Exactly one process must be all of these; none, or more
// than one, is an error, so a look-alike can at worst stop a container from
// starting, never stand in for its gofer.
func findGofer(proc string, sandbox, ppid, uid int, runsc fileID, bundle string) (procEntry, error) {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var found []procEntry
	for _, d := range ents {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 0 || pid == sandbox || strconv.Itoa(pid) != d.Name() {
			continue
		}
		e, err := openProc(proc, pid)
		if err != nil {
			continue // exited, or not the guard's to read: not a gofer of its
		}
		if !isGofer(e, ppid, uid, runsc, bundle) {
			e.Close()
			continue
		}
		found = append(found, e)
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, errors.New("found no gofer for the container")
	}
	for _, e := range found {
		e.Close()
	}
	return nil, fmt.Errorf("found %d processes that each look like the container's gofer", len(found))
}
