package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
	"github.com/jurajpiar/devkit/internal/gitx"
)

// pushFixture is a project on the host with a remote, plus a stand-in for
// the VM's workspace that has one new commit, and the bundle the VM would
// send. The fake limactl replays the VM's side.
type pushFixture struct {
	f              *fakelima.Fake
	host, remote   string
	vmHead, marker string
}

func newPushFixture(t *testing.T, vmBranch string) *pushFixture {
	t.Helper()
	f, _ := fakeHome(t)
	host, _ := hostRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitIn(t, host, "init", "-q", "--bare", remote)
	gitIn(t, host, "remote", "set-url", "origin", remote)
	gitIn(t, host, "push", "-q", "origin", "main")
	gitIn(t, host, "fetch", "-q", "origin")
	marker := filepath.Join(t.TempDir(), "hook-ran")
	must(t, os.WriteFile(filepath.Join(host, ".git", "hooks", "pre-push"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755))

	snap, err := gitx.TakeSnapshot(context.Background(), host)
	if err != nil || snap == nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snap.Close() })
	vm := snap.Dir
	gitIn(t, vm, "reset", "-q", "--hard")
	gitIn(t, vm, "config", "user.name", "Agent")
	gitIn(t, vm, "config", "user.email", "agent@vm")
	must(t, os.MkdirAll(filepath.Join(vm, ".github", "workflows"), 0o755))
	must(t, os.WriteFile(filepath.Join(vm, ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(vm, "feature.txt"), []byte("done\n"), 0o644))
	gitIn(t, vm, "add", ".")
	gitIn(t, vm, "commit", "-qm", "add feature\x1b[2J")
	bundle := filepath.Join(t.TempDir(), "vm.bundle")
	gitIn(t, vm, "bundle", "create", "-q", bundle, "refs/heads/main", "^"+gitIn(t, host, "rev-parse", "HEAD"))
	data, err := os.ReadFile(bundle)
	must(t, err)

	f.SetInstances(fakelima.Instance{Name: "devkit-pushproj", Status: "Running"})
	f.OnShell("symbolic-ref --short -q HEAD", vmBranch, 0)
	f.OnShell("git bundle create", "devkit-exit=0", 0)
	f.OnShell("devkit-push-", string(data), 0)

	must(t, os.WriteFile(filepath.Join(host, "devkit.yaml"), []byte("name: pushproj\nsource: copy\n"), 0o644))
	gitIn(t, host, "add", "devkit.yaml")
	wd, _ := os.Getwd()
	must(t, os.Chdir(host))
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return &pushFixture{f: f, host: host, remote: remote, vmHead: gitIn(t, vm, "rev-parse", "HEAD"), marker: marker}
}

func TestPushReviewsThenPushesWithHostCredentialsAndNoHooks(t *testing.T) {
	p := newPushFixture(t, "main")
	out, err := runDevkit(t, "y\n", "push")
	if err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if got := gitIn(t, p.remote, "rev-parse", "main"); got != p.vmHead {
		t.Errorf("remote main = %s, want the VM's commit %s", got, p.vmHead)
	}
	if _, err := os.Stat(p.marker); err == nil {
		t.Error("the host's pre-push hook ran")
	}
	if got := gitIn(t, p.host, "rev-parse", "refs/heads/main"); got == p.vmHead {
		t.Error("the host's own branch must not move")
	}
}

func TestPushShowsWhatItWouldPush(t *testing.T) {
	newPushFixture(t, "main")
	// Capture what push prints; the prompt is answered "n".
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	_, err := runDevkit(t, "n\n", "push")
	w.Close()
	os.Stdout = old
	buf := make([]byte, 1<<16)
	n, _ := r.Read(buf)
	shown := string(buf[:n])
	if err == nil {
		t.Error("declining should end with an error so scripts notice")
	}
	for _, want := range []string{"add feature", "Agent <agent@vm>", ".github/workflows/ci.yml", "feature.txt"} {
		if !strings.Contains(shown, want) {
			t.Errorf("review should show %q:\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "\x1b") {
		t.Error("escape sequences from the VM must not reach the terminal")
	}
}

func TestPushDeclinedLeavesTheRemoteAlone(t *testing.T) {
	p := newPushFixture(t, "main")
	before := gitIn(t, p.remote, "rev-parse", "main")
	if _, err := runDevkit(t, "n\n", "push"); err == nil {
		t.Error("declining should fail")
	}
	if gitIn(t, p.remote, "rev-parse", "main") != before {
		t.Error("the remote changed after declining")
	}
	if gitIn(t, p.host, "rev-parse", gitx.QuarantineRef("pushproj", "main")) != p.vmHead {
		t.Error("the reviewed commits should stay available on the host")
	}
}

func TestPushRefusesAHostileBranchName(t *testing.T) {
	p := newPushFixture(t, "--upload-pack=touch /tmp/pwned")
	if _, err := runDevkit(t, "y\n", "push"); err == nil {
		t.Fatal("a branch name that is an option must be refused")
	}
	if mentions(p.f.Calls(), "git bundle create") {
		t.Error("nothing should be bundled for an invalid branch")
	}
	if out, _ := exec.Command("git", "-C", p.host, "for-each-ref", "refs/devkit").Output(); len(out) != 0 {
		t.Errorf("no quarantine ref expected: %s", out)
	}
}

// The default remote is the pushed branch's upstream, not the --to
// branch's.
func TestPushDefaultsToTheSourceBranchsUpstream(t *testing.T) {
	p := newPushFixture(t, "main")
	fork := filepath.Join(t.TempDir(), "fork.git")
	gitIn(t, p.host, "clone", "-q", "--bare", "--no-local", p.remote, fork)
	gitIn(t, p.host, "remote", "add", "fork", fork)
	gitIn(t, p.host, "config", "branch.main.remote", "fork")
	gitIn(t, p.host, "config", "branch.release.remote", "origin")
	if out, err := runDevkit(t, "", "push", "--yes", "--to", "release"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if gitIn(t, fork, "rev-parse", "release") != p.vmHead {
		t.Error("main tracks fork, so its push goes to fork")
	}
	if out, _ := exec.Command("git", "-C", p.remote, "rev-parse", "-q", "--verify", "release").Output(); len(out) != 0 {
		t.Error("origin must not receive it")
	}
}
