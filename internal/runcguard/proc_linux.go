package runcguard

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// maxProcFile bounds a read from /proc: a mount table is far smaller.
const maxProcFile = 4 << 20

// dirEntry is a /proc/<pid> directory held by a file descriptor. The
// descriptor stays bound to the process it was opened for: once that
// process exits, reads through it fail, even if the pid is reused.
type dirEntry struct{ fd int }

func openProc(proc string, pid int) (procEntry, error) {
	fd, err := syscall.Open(filepath.Join(proc, strconv.Itoa(pid)), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &dirEntry{fd}, nil
}

func (d *dirEntry) ReadFile(name string) ([]byte, error) {
	fd, err := syscall.Openat(d.fd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxProcFile))
}

// ExeID opens the exe link, which the kernel resolves to the file the
// process runs whatever mount namespace it is in, and takes the identity
// of what it opened.
func (d *dirEntry) ExeID() (fileID, error) {
	fd, err := syscall.Openat(d.fd, "exe", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fileID{}, err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fileID{}, err
	}
	return fileID{uint64(st.Dev), st.Ino}, nil
}

func (d *dirEntry) Close() error { return syscall.Close(d.fd) }
