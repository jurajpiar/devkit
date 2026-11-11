package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSyncKeepsVMEdits checks devkit sync for a copied project on a real VM.
// The Mac's directory is the source, but work done in the VM must survive a
// sync: a file only the VM changed is kept, a file only the Mac changed is
// updated, a file deleted on the Mac goes, and a file both changed stops
// the sync, with nothing applied, until the user says which side wins.
func TestSyncKeepsVMEdits(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2esync-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	mac := func(rel string) string { return filepath.Join(dir, rel) }
	write := func(rel, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(mac(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, mac(rel), content)
	}

	// A project with what a plain "git add" would get wrong: a file
	// .gitignore names, CRLF line endings under a .gitattributes that asks
	// for conversion and names a filter, a nested repository, a symlink, an
	// executable, a private file mode, an empty directory.
	write("a.txt", "one\n")
	write("b.txt", "two\n")
	write("src/c.txt", "three\n")
	write(".env", "SECRET=from-the-mac\n")
	write(".gitignore", ".env\n")
	write("win.txt", "crlf line\r\nsecond\r\n")
	write(".gitattributes", "* text=auto eol=lf\n*.txt filter=nosuch\n")
	write("lib/nested/f.txt", "nested\n")
	write("run.sh", "#!/bin/sh\necho hi\n")
	write("private.key", "not a real key\n")
	for _, c := range []struct {
		path string
		mode os.FileMode
	}{{"run.sh", 0o755}, {"private.key", 0o600}} {
		if err := os.Chmod(mac(c.path), c.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", mac("link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mac("empty-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", mac("lib/nested")).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	s.mustRun("up", "--no-install")

	vm := func(cmd string) string { out, _ := s.shell("cd ~/workspace && " + cmd); return out }
	cat := func(rel string) string { return vm("cat " + shq(rel) + " 2>&1") }
	is := func(t *testing.T, rel, want string) {
		t.Helper()
		if got := cat(rel); got != want {
			t.Errorf("%s in the VM is %q, want %q", rel, got, want)
		}
	}
	// sync runs devkit sync and returns its output and whether it succeeded.
	sync := func(args ...string) (string, bool) {
		out, err := s.run(append([]string{"sync"}, args...)...)
		return out, err == nil
	}

	t.Run("the first sync brings the directory as it is", func(t *testing.T) {
		is(t, "a.txt", "one\n")
		is(t, "src/c.txt", "three\n")
		is(t, ".env", "SECRET=from-the-mac\n")
		is(t, "lib/nested/f.txt", "nested\n")
		// Byte for byte: the project's .gitattributes asks for LF, and
		// names a filter. Neither may touch what is copied.
		if got := vm("od -An -c win.txt | tr -s ' ' | tr -d '\\n'"); !strings.Contains(got, `\r \n s e c o n d \r \n`) {
			t.Errorf("win.txt lost its CRLF line endings in the VM: %s", got)
		}
		out := vm(`stat -c '%a %F %n' run.sh private.key link empty-dir 2>&1; readlink link; ls -d lib/nested/.git 2>&1 | tail -n 1`)
		for _, want := range []string{"755 regular file run.sh", "600 regular file private.key", "symbolic link link", "directory empty-dir"} {
			if !strings.Contains(out, want) {
				t.Errorf("want %q after the first sync:\n%s", want, out)
			}
		}
		if !strings.Contains(out, "a.txt\n") || !strings.Contains(out, "No such file") {
			t.Errorf("the symlink should keep its target and the nested repository's .git should not arrive:\n%s", out)
		}
		if out := vm("ls devkit.yaml .devkit 2>&1"); !strings.Contains(out, "No such file") || strings.Contains(out, "sync.git") {
			t.Errorf("devkit's own files must not be copied into the workspace: %s", out)
		}
		// What was sent for the sync is not left lying in the VM.
		if out, _ := s.shell("ls /tmp/devkit-sync-* 2>&1"); !strings.Contains(out, "No such file") {
			t.Errorf("the sync left its files in the VM's /tmp: %s", out)
		}
	})

	t.Run("edits on one side each are both kept", func(t *testing.T) {
		vm(`printf 'two, edited in the VM\n' > b.txt && mkdir -p dist node_modules/dep && echo built > dist/out && echo dep > node_modules/dep/i`)
		write("a.txt", "one, edited on the Mac\n")
		write("new.txt", "new on the Mac\n")
		if err := os.Remove(mac("src/c.txt")); err != nil {
			t.Fatal(err)
		}
		out, ok := sync()
		if !ok {
			t.Fatalf("sync should succeed when the two sides changed different files:\n%s", out)
		}
		is(t, "a.txt", "one, edited on the Mac\n")
		is(t, "b.txt", "two, edited in the VM\n")
		is(t, "new.txt", "new on the Mac\n")
		is(t, "dist/out", "built\n")
		is(t, "node_modules/dep/i", "dep\n")
		if got := vm("ls src/c.txt 2>&1"); !strings.Contains(got, "No such file") {
			t.Errorf("a file deleted on the Mac should be deleted in the VM: %s", got)
		}
		// The user should be told what was kept, since it now differs from
		// the Mac.
		if !strings.Contains(out, "b.txt") {
			t.Errorf("sync should say which files changed in the VM were kept:\n%s", out)
		}
	})

	t.Run("a file changed on both sides stops the sync, whole", func(t *testing.T) {
		vm(`printf 'one, edited in the VM too\n' > a.txt`)
		write("a.txt", "one, edited on the Mac again\n")
		write("new.txt", "second Mac change\n")
		out, ok := sync()
		if ok {
			t.Fatalf("sync should fail when a file changed on both sides:\n%s", out)
		}
		if !strings.Contains(out, "a.txt") || !strings.Contains(out, "--overwrite") {
			t.Errorf("the refusal should name the file and say how to let the Mac win:\n%s", out)
		}
		if strings.Contains(out, "b.txt") && strings.Contains(out, "changed on both") {
			// b.txt changed in the VM only: it is not in conflict.
			t.Logf("note: b.txt is mentioned in the refusal:\n%s", out)
		}
		is(t, "a.txt", "one, edited in the VM too\n")
		is(t, "new.txt", "new on the Mac\n") // nothing half-applied
		is(t, "b.txt", "two, edited in the VM\n")
	})

	t.Run("--overwrite takes the Mac's version of the files in conflict only", func(t *testing.T) {
		out, ok := sync("--overwrite")
		if !ok {
			t.Fatalf("sync --overwrite should succeed:\n%s", out)
		}
		is(t, "a.txt", "one, edited on the Mac again\n")
		is(t, "new.txt", "second Mac change\n")
		is(t, "b.txt", "two, edited in the VM\n")
	})

	t.Run("a file the VM made where the Mac now adds one", func(t *testing.T) {
		vm(`printf 'made in the VM\n' > clash.txt`)
		write("clash.txt", "made on the Mac\n")
		out, ok := sync()
		if ok || !strings.Contains(out, "clash.txt") {
			t.Fatalf("sync should refuse and name clash.txt:\n%s", out)
		}
		is(t, "clash.txt", "made in the VM\n")
		if out, ok := sync("--overwrite"); !ok {
			t.Fatalf("sync --overwrite should succeed:\n%s", out)
		}
		is(t, "clash.txt", "made on the Mac\n")
	})

	t.Run("commits made in the VM survive", func(t *testing.T) {
		// What the walkthrough's second way of working does: commit in the
		// VM, then sync again later.
		out := vm(`git init -q . 2>/dev/null; git checkout -q -b vm-work 2>&1; printf 'two, committed in the VM\n' > b.txt && git add b.txt && git -c user.name=t -c user.email=t@t commit -q -m 'in the VM' && printf 'uncommitted in the VM\n' > notes.txt && git log --oneline | head -n 1`)
		if !strings.Contains(out, "in the VM") {
			t.Fatalf("could not commit in the VM: %s", out)
		}
		write("a.txt", "one, a third Mac edit\n")
		if out, ok := sync(); !ok {
			t.Fatalf("sync should succeed:\n%s", out)
		}
		is(t, "a.txt", "one, a third Mac edit\n")
		is(t, "b.txt", "two, committed in the VM\n")
		is(t, "notes.txt", "uncommitted in the VM\n")
		if out := vm("git log --oneline | head -n 1; git status --porcelain | grep -c . "); !strings.Contains(out, "in the VM") {
			t.Errorf("the VM's own repository should still have its commit: %s", out)
		}
	})

	t.Run("modes and deletions keep following the Mac", func(t *testing.T) {
		if err := os.Chmod(mac("private.key"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(mac("a.txt"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(mac("empty-dir")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(mac("link")); err != nil {
			t.Fatal(err)
		}
		if out, ok := sync(); !ok {
			t.Fatalf("sync should succeed:\n%s", out)
		}
		out := vm(`stat -c '%a %n' private.key a.txt 2>&1; ls -d link 2>&1 | tail -n 1`)
		if !strings.Contains(out, "640 private.key") || !strings.Contains(out, "755 a.txt") || !strings.Contains(out, "No such file") {
			t.Errorf("mode changes and a deleted symlink should arrive:\n%s", out)
		}
	})

	t.Run("devkit up says when it could not sync, and still comes up", func(t *testing.T) {
		vm(`printf 'VM side\n' > a.txt`)
		write("a.txt", "Mac side\n")
		out, err := s.run("up", "--no-install")
		if err != nil {
			t.Fatalf("devkit up should still succeed when the workspace cannot be synced:\n%s", out)
		}
		if !strings.Contains(out, "a.txt") || !strings.Contains(out, "--overwrite") {
			t.Errorf("devkit up should say the workspace was not synced, which file, and how to resolve it:\n%s", out)
		}
		is(t, "a.txt", "VM side\n")
		if out, ok := sync("--overwrite"); !ok {
			t.Fatalf("sync --overwrite should succeed:\n%s", out)
		}
		is(t, "a.txt", "Mac side\n")
	})

	t.Run("a directory in the VM where the Mac adds a file stops the sync, not devkit up", func(t *testing.T) {
		vm(`mkdir clash && printf 'vm\n' > clash/inner`)
		write("clash", "a file on the Mac\n")
		write("late.txt", "must not arrive while the sync is refused\n")
		out, ok := sync()
		if ok || !strings.Contains(out, "clash") {
			t.Errorf("sync should refuse and name what is in the way (ok=%v):\n%s", ok, out)
		}
		is(t, "clash/inner", "vm\n")
		if got := vm("ls late.txt 2>&1"); !strings.Contains(got, "No such file") {
			t.Errorf("a refused sync must apply nothing, but late.txt arrived: %s", got)
		}
		if out, err := s.run("up", "--no-install"); err != nil || !strings.Contains(out, "clash") {
			t.Errorf("devkit up should succeed and say the workspace was not synced (err=%v):\n%s", err, out)
		}
		is(t, "clash/inner", "vm\n")
		// Moving it out of the way in the VM lets the sync through.
		vm("mv clash clash.mine")
		if out, ok := sync(); !ok {
			t.Fatalf("sync should succeed once nothing is in the way:\n%s", out)
		}
		is(t, "clash", "a file on the Mac\n")
		is(t, "late.txt", "must not arrive while the sync is refused\n")
		is(t, "clash.mine/inner", "vm\n")
	})

	t.Run("a new VM gets everything again", func(t *testing.T) {
		s.mustRun("rm", "--force")
		s.mustRun("up", "--no-install")
		is(t, "a.txt", "Mac side\n")
		is(t, "b.txt", "two\n") // the Mac's b.txt: the VM's edits went with the old VM
		is(t, "new.txt", "second Mac change\n")
		if got := vm("ls notes.txt dist 2>&1"); strings.Count(got, "No such file") != 2 {
			t.Errorf("a new VM should hold only what the Mac has: %s", got)
		}
	})

	t.Run("nothing of this lands in the project on the Mac", func(t *testing.T) {
		// devkit's snapshots are kept outside the project, where a project
		// cannot plant anything: the directory holds what the test wrote.
		if _, err := os.Lstat(mac(".devkit")); err == nil {
			t.Errorf("devkit sync left a .devkit in the project directory")
		}
		if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v: %s", err, out)
		}
		cmd := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
		cmd.Dir = dir
		var b bytes.Buffer
		cmd.Stdout = &b
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "devkit") && !strings.Contains(b.String(), "devkit.yaml") || strings.Contains(b.String(), "sync.git") {
			t.Errorf("git status in the project lists devkit's own state:\n%s", b.String())
		}
	})
}
