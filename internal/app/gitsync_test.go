package app

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// hostRepo is a project directory with history the VM must not get: a
// secret committed and deleted, a hook, and a token in the remote URL.
func hostRepo(t *testing.T) (dir, secretBlob string) {
	t.Helper()
	dir = t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "config", "user.name", "Test Person")
	gitIn(t, dir, "config", "user.email", "test@example.com")
	must(t, os.WriteFile(filepath.Join(dir, "secret.env"), []byte("API_KEY=hunter2\n"), 0o644))
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-qm", "one")
	secretBlob = gitIn(t, dir, "rev-parse", "HEAD:secret.env")
	gitIn(t, dir, "rm", "-q", "secret.env")
	must(t, os.WriteFile(filepath.Join(dir, "app.txt"), []byte("hello\n"), 0o644))
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-qm", "two")
	gitIn(t, dir, "remote", "add", "origin", "https://x:ghp_token@github.com/org/repo.git")
	must(t, os.WriteFile(filepath.Join(dir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\n"), 0o755))
	return dir, secretBlob
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func untar(t *testing.T, data []byte, dir string) []string {
	t.Helper()
	var names []string
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		must(t, err)
		names = append(names, strings.TrimPrefix(h.Name, "./"))
		p := filepath.Join(dir, h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			must(t, os.MkdirAll(p, 0o755))
		case tar.TypeReg:
			must(t, os.MkdirAll(filepath.Dir(p), 0o755))
			body, _ := io.ReadAll(tr)
			must(t, os.WriteFile(p, body, 0o644))
		}
	}
}

// tarStreams returns the commands that received a tar stream, with it.
func tarStreams(calls [][]string, inputs [][]byte) (cmds []string, streams [][]byte) {
	for i, in := range inputs {
		if in != nil {
			cmds = append(cmds, calls[i][len(calls[i])-1])
			streams = append(streams, in)
		}
	}
	return
}

func TestCopySyncAddsAFreshCloneGit(t *testing.T) {
	f, _ := fakeHome(t)
	src, secret := hostRepo(t)
	cfg := project.Default()
	cfg.Name = "gitsync"
	if err := syncSource(context.Background(), cfg, src); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	_, streams := tarStreams(calls, f.Inputs())
	if len(streams) != 2 {
		t.Fatalf("want the working tree and then .git, got %d tar streams", len(streams))
	}
	for _, n := range untar(t, streams[0], t.TempDir()) {
		if n == ".git" || strings.HasPrefix(n, ".git/") {
			t.Fatalf("the working-tree copy must not carry the host's .git: %s", n)
		}
	}
	vm := t.TempDir()
	for _, n := range untar(t, streams[1], vm) {
		if n != "" && n != "." && n != ".git" && !strings.HasPrefix(n, ".git/") {
			t.Errorf("the git stream should hold only .git, has %s", n)
		}
		if strings.HasPrefix(n, ".git/hooks/") {
			t.Errorf("hook copied: %s", n)
		}
	}
	if n := gitIn(t, vm, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("VM history: %s commits, want 1", n)
	}
	if strings.Contains(gitIn(t, vm, "cat-file", "--batch-all-objects", "--batch-check"), secret) {
		t.Error("the deleted secret reached the VM")
	}
	if u := gitIn(t, vm, "config", "remote.origin.url"); strings.Contains(u, "ghp_token") {
		t.Errorf("credential in the VM's remote: %s", u)
	}
	if !mentions(calls, "git reset -q") {
		t.Error("the VM should rebuild the index from HEAD without touching the files")
	}
	if !mentions(calls, "user.name 'Test Person'") || !mentions(calls, "user.email 'test@example.com'") {
		t.Error("commits in the VM should carry the host's git identity")
	}
}

func TestCopySyncKeepsTheVMsRepository(t *testing.T) {
	f, _ := fakeHome(t)
	src, _ := hostRepo(t)
	cfg := project.Default()
	cfg.Name = "gitsync"
	f.OnShell(`/.git" && echo yes`, "yes", 0)
	if err := syncSource(context.Background(), cfg, src); err != nil {
		t.Fatal(err)
	}
	_, streams := tarStreams(f.Calls(), f.Inputs())
	if len(streams) != 1 {
		t.Fatalf("an existing VM repository holds commits not on the host; only the working tree may be sent, got %d streams", len(streams))
	}
	if mentions(f.Calls(), "git reset") {
		t.Error("the VM's index must be left alone")
	}
}

func TestCopySyncOfAPlainDirectorySendsNoGit(t *testing.T) {
	f, _ := fakeHome(t)
	src := t.TempDir()
	must(t, os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644))
	cfg := project.Default()
	cfg.Name = "gitsync"
	if err := syncSource(context.Background(), cfg, src); err != nil {
		t.Fatal(err)
	}
	if _, streams := tarStreams(f.Calls(), f.Inputs()); len(streams) != 1 {
		t.Fatalf("got %d streams, want only the working tree", len(streams))
	}
}

// Tracked files that exclude kept out of the copy must not show as deleted,
// or a routine "git commit -a" in the VM would delete them upstream.
func TestExcludedTrackedFilesAreNotDeletions(t *testing.T) {
	dir, _ := hostRepo(t)
	for _, f := range []string{"vendor/lib/a.go", "web/dist/app.js", "debug.log", "keep.txt"} {
		must(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o755))
		must(t, os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644))
	}
	gitIn(t, dir, "add", "-f", ".")
	gitIn(t, dir, "commit", "-qm", "tracked build output")
	// What the VM sees: the excluded paths missing, and one real
	// uncommitted deletion.
	for _, p := range []string{"vendor", "web/dist", "debug.log", "keep.txt"} {
		must(t, os.RemoveAll(filepath.Join(dir, p)))
	}
	cmd := exec.Command("bash", "-c", skipExcludedScript(project.DefaultExclude))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if st := gitIn(t, dir, "status", "--porcelain"); st != "D keep.txt" {
		t.Errorf("status = %q, want only the real deletion", st)
	}
}
