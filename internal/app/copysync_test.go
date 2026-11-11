package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
)

// copyProject is a copied project whose VM is running, provisioned, and a
// local directory standing in for the sandbox user's HOME, which it
// returns with the project directory, the current directory.
func copyProject(t *testing.T) (f *fakelima.Fake, dir, guest string) {
	t.Helper()
	f = upProject(t, "Running")
	provisioned(f, "current")
	guest = f.LocalGuest()
	dir, _ = os.Getwd()
	return f, dir, guest
}

func syncOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	var cobraOut string
	out := captureStdout(t, func() { cobraOut, err = runDevkit(t, "", append([]string{"sync"}, args...)...) })
	return out + cobraOut, err
}

func TestSyncKeepsVMEditsAndRefusesConflicts(t *testing.T) {
	_, dir, guest := copyProject(t)
	ws := func(rel string) string { return filepath.Join(guest, "workspace", rel) }
	mac := func(rel string) string { return filepath.Join(dir, rel) }
	must(t, os.WriteFile(mac("b.txt"), []byte("b\n"), 0o644))
	if out, err := syncOut(t); err != nil {
		t.Fatalf("first sync: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(ws("main.txt")); string(b) != "code\n" {
		t.Fatalf("main.txt in the VM: %q", b)
	}

	must(t, os.WriteFile(ws("b.txt"), []byte("b, the VM's\n"), 0o644))
	must(t, os.WriteFile(mac("main.txt"), []byte("code, the Mac's\n"), 0o644))
	out, err := syncOut(t)
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Kept the VM's own changes, which now differ from this Mac: b.txt") {
		t.Errorf("sync should say which VM changes it kept:\n%s", out)
	}

	must(t, os.WriteFile(ws("main.txt"), []byte("code, the VM's\n"), 0o644))
	must(t, os.WriteFile(mac("main.txt"), []byte("code, the Mac's again\n"), 0o644))
	out, err = syncOut(t)
	if err == nil {
		t.Fatalf("a file changed on both sides should fail the sync:\n%s", out)
	}
	for _, want := range []string{"not synced", "main.txt", "Nothing in the VM was changed", "devkit sync --overwrite"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should say %q:\n%v", want, err)
		}
	}
	if b, _ := os.ReadFile(ws("main.txt")); string(b) != "code, the VM's\n" {
		t.Errorf("a refused sync changed main.txt: %q", b)
	}
	if out, err := syncOut(t, "--overwrite"); err != nil {
		t.Fatalf("sync --overwrite: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(ws("main.txt")); string(b) != "code, the Mac's again\n" {
		t.Errorf("--overwrite should take the Mac's main.txt: %q", b)
	}
	if b, _ := os.ReadFile(ws("b.txt")); string(b) != "b, the VM's\n" {
		t.Errorf("--overwrite must keep the VM's other changes: %q", b)
	}
}

// The snapshots are kept with the VM's state on the Mac, not in the
// project, which gains nothing; devkit rm removes them with the VM.
func TestSyncStateStaysOutOfTheProject(t *testing.T) {
	_, dir, guest := copyProject(t)
	before := listDir(t, dir)
	if out, err := syncOut(t); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if after := listDir(t, dir); after != before {
		t.Errorf("the project directory changed:\n before %s\n after  %s", before, after)
	}
	repo := filepath.Join(vmStateDir(demoVM), "sync.git")
	if !isDir(repo) {
		t.Fatalf("the snapshots should be kept in %s", repo)
	}
	for _, p := range []string{".devkit", "devkit.yaml"} {
		if _, err := os.Lstat(filepath.Join(guest, "workspace", p)); err == nil {
			t.Errorf("%s reached the VM", p)
		}
	}
	if out, err := runDevkit(t, "", "rm", "--force"); err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	if _, err := os.Lstat(repo); err == nil {
		t.Error("devkit rm should remove the snapshots with the VM")
	}
}

// listDir lists every path under dir with its size.
func listDir(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	must(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %d\n", strings.TrimPrefix(p, dir), info.Size())
		return nil
	}))
	return b.String()
}

func TestSyncReportsWhatItCannotCopy(t *testing.T) {
	_, dir, _ := copyProject(t)
	must(t, syscall.Mkfifo(filepath.Join(dir, "a-pipe"), 0o644))
	out, err := syncOut(t)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, `Not copied, a named pipe: "a-pipe"`) {
		t.Errorf("a file that cannot be copied must be reported:\n%s", out)
	}
	must(t, os.WriteFile("devkit.yaml", []byte("name: demo\nexclude: [node_modules]\nnetwork:\n  mode: open\n"), 0o644))
	gitIn(t, dir, "init", "-q")
	out, err = syncOut(t)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := strings.Count(out, "a .git path"); n != 1 || !strings.Contains(out, "more") {
		t.Errorf("the .git paths git cannot carry should be one line, capped:\n%s", out)
	}
}

func TestSyncOverwriteIsForCopiedProjects(t *testing.T) {
	f := upProject(t, "Running")
	provisioned(f, "current")
	must(t, os.WriteFile("devkit.yaml", []byte("name: demo\nsource: mount\nnetwork:\n  mode: open\n"), 0o644))
	if _, err := runDevkit(t, "", "sync", "--overwrite"); err == nil || !strings.Contains(err.Error(), "copied projects") {
		t.Errorf("--overwrite on a mounted project should be refused, got %v", err)
	}
}

// Paths come from the VM: nothing in them may reach the terminal as
// control characters or reorder what is shown.
func TestSyncSanitisesTheVMsPaths(t *testing.T) {
	f := upProject(t, "Running")
	provisioned(f, "current")
	f.OnShell(`devkit-sync "`, "devkit-conflict \x1b]0;owned\x07evil\u202etxt.exe\ndevkit-exit=3\n", 0)
	out, err := syncOut(t)
	if err == nil {
		t.Fatalf("want a refusal:\n%s", out)
	}
	if strings.ContainsAny(err.Error(), "\x1b\x07\u202e") {
		t.Errorf("control characters from the VM reached the message: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "evil") {
		t.Errorf("the path should still be shown: %q", err.Error())
	}
}

func TestUpComesUpWhenTheWorkspaceCannotBeSynced(t *testing.T) {
	f := upProject(t, "Stopped")
	provisioned(f, "current")
	f.OnShell(`devkit-sync "`, "devkit-conflict main.txt\ndevkit-exit=3\n", 0)
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "up", "--no-install") })
	if err != nil {
		t.Fatalf("up should not fail on a conflict: %v\n%s", err, out)
	}
	for _, want := range []string{"main.txt", "devkit sync --overwrite", "Ready", "The workspace was NOT synced"} {
		if !strings.Contains(out, want) {
			t.Errorf("up should say %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out[strings.Index(out, "Ready"):], "NOT synced") {
		t.Errorf("the reminder should come after Ready, where it is seen:\n%s", out)
	}
	if mentions(f.Calls(), "git reset") {
		t.Error("no .git may be set up over a workspace that was not synced")
	}
}
