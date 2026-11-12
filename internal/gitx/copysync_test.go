package gitx

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
)

// These tests run a copy sync end to end without a VM: the Mac's side as
// devkit runs it, and the VM's script as it is, run by bash (the Mac's
// /bin/bash, 3.2, when there is one) with a temporary HOME standing in for
// the sandbox user's.

// localGuest is a VM made of a directory: commands run in bash with HOME
// set to it.
type localGuest struct {
	t          *testing.T
	home, tmp  string
	bin        string
	extraEnv   []string
	failPut    bool
	failScript bool
	// failManifest fails the manifest's upload, after the pack's.
	failManifest bool
	// answer, when set, replaces what the VM says it has.
	answer *string
	// packObjects counts the objects of each pack the VM was sent.
	packObjects []int
}

func newLocalGuest(t *testing.T) *localGuest {
	t.Helper()
	g := &localGuest{t: t, home: t.TempDir(), tmp: t.TempDir(), bin: t.TempDir()}
	// The oldest bash the script must run under, when the Mac has it.
	if _, err := os.Stat("/bin/bash"); err == nil {
		if err := os.Symlink("/bin/bash", filepath.Join(g.bin, "bash")); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func (g *localGuest) Exec(ctx context.Context, command string) (string, error) {
	if g.failScript && strings.Contains(command, "devkit-sync ") {
		return "", io.ErrUnexpectedEOF
	}
	if g.answer != nil && strings.Contains(command, "rev-list --objects \"$c\"") {
		return *g.answer, nil
	}
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Env = append(os.Environ(), "HOME="+g.home, "TMPDIR="+g.tmp, "PATH="+g.bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, g.extraEnv...)
	cmd.Dir = g.home
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if stderr.Len() > 0 {
		g.t.Logf("guest stderr: %s", stderr.String())
	}
	return stdout.String(), err
}

func (g *localGuest) Put(ctx context.Context, local, name string) (string, error) {
	if g.failPut || g.failManifest && strings.HasSuffix(name, ".manifest") {
		return "", io.ErrClosedPipe
	}
	data, err := os.ReadFile(local)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(g.tmp, name)
	if strings.HasSuffix(name, ".pack") {
		g.packObjects = append(g.packObjects, packCount(g.t, local))
	}
	return dst, os.WriteFile(dst, data, 0o600)
}

func (g *localGuest) ws(rel string) string { return filepath.Join(g.home, "workspace", rel) }

// vmRepo is the VM's private repository.
func (g *localGuest) vmRepo() string {
	return filepath.Join(g.home, ".local", "state", "devkit", "sync.git")
}

// copyFixture is a Mac directory, its private repository and a VM.
type copyFixture struct {
	t        *testing.T
	mac      string
	repo     *CopyRepo
	vm       *localGuest
	excludes []string
}

func newCopyFixture(t *testing.T) *copyFixture {
	t.Helper()
	return newCopyFixtureAt(t, t.TempDir())
}

// newCopyFixtureAt is a fixture for the project mac, with the private
// repository outside it, as devkit keeps it.
func newCopyFixtureAt(t *testing.T, mac string) *copyFixture {
	t.Helper()
	repo, err := OpenCopyRepo(context.Background(), filepath.Join(t.TempDir(), "state", CopySyncRepoDir))
	if err != nil {
		t.Fatal(err)
	}
	return &copyFixture{t: t, mac: mac, repo: repo, vm: newLocalGuest(t), excludes: project.DefaultExclude}
}

func (f *copyFixture) snapshot() *CopySnapshot {
	f.t.Helper()
	ctx := context.Background()
	snap, err := f.repo.SnapshotOf(ctx, lima.TarCommand(ctx, f.mac, f.excludes))
	if err != nil {
		f.t.Fatal(err)
	}
	return snap
}

// sync takes a snapshot and delivers it.
func (f *copyFixture) sync(overwrite bool) *CopyResult {
	f.t.Helper()
	res, err := DeliverCopy(context.Background(), f.repo, f.snapshot(), f.vm, `$HOME/workspace`, overwrite)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func (f *copyFixture) mustSync() *CopyResult {
	f.t.Helper()
	res := f.sync(false)
	if !res.Synced {
		f.t.Fatalf("sync did not apply: %+v", res)
	}
	return res
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func (f *copyFixture) wantVM(rel, content string) {
	f.t.Helper()
	if got := read(f.t, f.vm.ws(rel)); got != content {
		f.t.Errorf("%s in the VM is %q, want %q", rel, got, content)
	}
}

func TestCopySyncSpike(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m("a.txt"), "one\n")
	put(t, m("b.txt"), "two\n")
	put(t, m("src/c.txt"), "three\n")
	put(t, m(".env"), "ignored-by-git\n")
	put(t, m(".gitignore"), ".env\n")
	put(t, m("node_modules/x/y"), "junk\n")

	t.Run("first sync into an empty workspace", func(t *testing.T) {
		res := f.mustSync()
		f.wantVM("a.txt", "one\n")
		f.wantVM("src/c.txt", "three\n")
		f.wantVM(".env", "ignored-by-git\n")
		if exists(f.vm.ws("node_modules")) {
			t.Error("node_modules is excluded and must not arrive")
		}
		if len(res.Kept) != 0 || len(res.Conflicts) != 0 {
			t.Errorf("nothing to keep or conflict on a first sync: %+v", res)
		}
	})

	t.Run("one-sided edits, an addition and a deletion", func(t *testing.T) {
		put(t, f.vm.ws("b.txt"), "two, edited in the VM\n")
		put(t, f.vm.ws("dist/out"), "built\n")
		put(t, m("a.txt"), "one, edited on the Mac\n")
		put(t, m("new.txt"), "new on the Mac\n")
		must(t, os.Remove(m("src/c.txt")))
		res := f.mustSync()
		f.wantVM("a.txt", "one, edited on the Mac\n")
		f.wantVM("b.txt", "two, edited in the VM\n")
		f.wantVM("new.txt", "new on the Mac\n")
		f.wantVM("dist/out", "built\n")
		if exists(f.vm.ws("src/c.txt")) {
			t.Error("a file deleted on the Mac should go")
		}
		if strings.Join(res.Kept, ",") != "b.txt" {
			t.Errorf("kept = %q, want b.txt", res.Kept)
		}
	})

	t.Run("both sides edit a file: nothing is applied", func(t *testing.T) {
		put(t, f.vm.ws("a.txt"), "one, edited in the VM too\n")
		put(t, m("a.txt"), "one, edited on the Mac again\n")
		put(t, m("new.txt"), "second Mac change\n")
		res := f.sync(false)
		if res.Synced || strings.Join(res.Conflicts, ",") != "a.txt" {
			t.Fatalf("want a refusal naming a.txt only, got %+v", res)
		}
		f.wantVM("a.txt", "one, edited in the VM too\n")
		f.wantVM("new.txt", "new on the Mac\n")
	})

	t.Run("--overwrite takes the Mac's version of the conflicts only", func(t *testing.T) {
		res := f.sync(true)
		if !res.Synced {
			t.Fatalf("overwrite should apply: %+v", res)
		}
		f.wantVM("a.txt", "one, edited on the Mac again\n")
		f.wantVM("new.txt", "second Mac change\n")
		f.wantVM("b.txt", "two, edited in the VM\n")
	})

	t.Run("an untracked file where the Mac adds one", func(t *testing.T) {
		put(t, f.vm.ws("clash.txt"), "made in the VM\n")
		put(t, m("clash.txt"), "made on the Mac\n")
		res := f.sync(false)
		if res.Synced || strings.Join(res.Conflicts, ",") != "clash.txt" {
			t.Fatalf("want a refusal naming clash.txt, got %+v", res)
		}
		f.wantVM("clash.txt", "made in the VM\n")
		if res := f.sync(true); !res.Synced {
			t.Fatalf("overwrite should apply: %+v", res)
		}
		f.wantVM("clash.txt", "made on the Mac\n")
	})

	t.Run("an untracked file identical to the Mac's is adopted", func(t *testing.T) {
		put(t, f.vm.ws("same.txt"), "same\n")
		put(t, m("same.txt"), "same\n")
		res := f.mustSync()
		if len(res.Kept) != 1 || res.Kept[0] != "b.txt" {
			t.Errorf("kept = %q, want only b.txt", res.Kept)
		}
	})

	t.Run("a VM edit the Mac deletes is a conflict", func(t *testing.T) {
		put(t, f.vm.ws("new.txt"), "VM\n")
		must(t, os.Remove(m("new.txt")))
		res := f.sync(false)
		if res.Synced || strings.Join(res.Conflicts, ",") != "new.txt" {
			t.Fatalf("want a refusal naming new.txt, got %+v", res)
		}
		f.wantVM("new.txt", "VM\n")
		if res := f.sync(true); !res.Synced {
			t.Fatalf("overwrite should apply: %+v", res)
		}
		if exists(f.vm.ws("new.txt")) {
			t.Error("--overwrite should take the Mac's deletion")
		}
	})

	t.Run("the workspace's own repository is not disturbed", func(t *testing.T) {
		ws := f.vm.ws("")
		gitT(t, ws, "init", "-q", "-b", "main")
		gitT(t, ws, "add", "-A")
		gitT(t, ws, "-c", "user.name=u", "-c", "user.email=u@u", "commit", "-qm", "in the VM")
		head := gitT(t, ws, "rev-parse", "HEAD")
		put(t, m("a.txt"), "after the VM commit\n")
		f.mustSync()
		if st := gitT(t, ws, "status", "--porcelain"); st != "M a.txt" {
			t.Errorf("the VM's repository should see the Mac's change as a modification, got %q", st)
		}
		if gitT(t, ws, "rev-parse", "HEAD") != head {
			t.Error("the VM's HEAD moved")
		}
	})
}

// gitT runs git in dir, for the test's own setup and checks.
func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// Some tests point the global config at a hostile one; the test's own
	// git must not read it.
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// packCount is the number of objects in a pack file.
func packCount(t *testing.T, pack string) int {
	t.Helper()
	scratch := t.TempDir()
	gitT(t, scratch, "init", "-q", "--bare")
	cmd := exec.Command("git", "--git-dir="+scratch, "index-pack", "--stdin")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull)
	in, err := os.Open(pack)
	must(t, err)
	defer in.Close()
	cmd.Stdin = in
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("index-pack: %v\n%s", err, out)
	}
	out := gitT(t, scratch, "count-objects", "-v")
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "in-pack: "); ok {
			n := 0
			for _, c := range v {
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	t.Fatalf("no in-pack count in %s", out)
	return 0
}
