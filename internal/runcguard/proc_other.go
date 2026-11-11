//go:build !linux

package runcguard

import (
	"os"
	"path/filepath"
	"strconv"
)

// pathEntry reads a process directory by path. The guard only runs on
// Linux, where a held descriptor is used instead; this lets the rest of
// the guard be built and tested elsewhere against a tree of files.
type pathEntry struct{ dir string }

func openProc(proc string, pid int) (procEntry, error) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	return &pathEntry{dir}, nil
}

func (p *pathEntry) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(p.dir, name))
}

func (p *pathEntry) ExeID() (fileID, error) {
	fi, err := os.Stat(filepath.Join(p.dir, "exe"))
	if err != nil {
		return fileID{}, err
	}
	return statID(fi)
}

func (p *pathEntry) Close() error { return nil }
