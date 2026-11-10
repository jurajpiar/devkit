package app

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
	"github.com/jurajpiar/devkit/internal/gitx"
	"github.com/jurajpiar/devkit/internal/project"
)

// allowLocalClones lets the tests clone from a path; devkit itself accepts
// only https and ssh.
func allowLocalClones(t *testing.T) {
	t.Helper()
	oldN, oldC := normalizeCloneURL, cloneRepo
	normalizeCloneURL = func(raw string) (string, string, error) {
		if strings.HasPrefix(raw, "file://") {
			return raw, "", nil
		}
		return oldN(raw)
	}
	cloneRepo = func(ctx context.Context, url, branch, dst string, out io.Writer) error {
		args := []string{"clone", "-q", "--bare", "--depth", "1", "--no-tags", "--template="}
		if branch != "" {
			args = append(args, "--branch", branch)
		}
		cmd := exec.CommandContext(ctx, "git", append(args, "--", url, dst)...)
		cmd.Stdout, cmd.Stderr = out, out
		return cmd.Run()
	}
	oldF := fetchUpstream
	fetchUpstream = func(ctx context.Context, repo, branch, ref string, out io.Writer) error {
		cmd := exec.CommandContext(ctx, "git", "-C", repo, "fetch", "-q", "--no-tags", "origin", "+refs/heads/"+branch+":"+ref)
		cmd.Stdout, cmd.Stderr = out, out
		return cmd.Run()
	}
	t.Cleanup(func() { normalizeCloneURL, cloneRepo, fetchUpstream = oldN, oldC, oldF })
}

func upstreamRepo(t *testing.T) string {
	t.Helper()
	dir, _ := hostRepo(t)
	must(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.27.3\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, ".envrc"), []byte("touch /tmp/devkit-envrc-ran\n"), 0o644))
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-qm", "go")
	return dir
}

func inDir(t *testing.T, dir string) {
	t.Helper()
	wd, _ := os.Getwd()
	must(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })
}

func TestCloneWritesConfigWithoutCheckingOut(t *testing.T) {
	fakeHome(t)
	allowLocalClones(t)
	up := upstreamRepo(t)
	parent := t.TempDir()
	inDir(t, parent)
	if out, err := runDevkit(t, "", "clone", "file://"+up, "proj"); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	dst := filepath.Join(parent, "proj")
	entries, _ := os.ReadDir(dst)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != ".devkit,devkit.yaml" {
		t.Errorf("the project's files must not be written on the host; %s holds %v", dst, names)
	}
	cfg, err := project.Load(filepath.Join(dst, "devkit.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source != project.SourceGit || cfg.Repo != "file://"+up || cfg.Branch != "main" {
		t.Errorf("source %q repo %q branch %q", cfg.Source, cfg.Repo, cfg.Branch)
	}
	if cfg.Tools.Versions["go"] != "1.27" {
		t.Errorf("detection from git objects: versions = %v", cfg.Tools.Versions)
	}
	if bare := gitIn(t, filepath.Join(dst, project.LockDir, "repo.git"), "rev-parse", "--is-bare-repository"); bare != "true" {
		t.Error("the host copy should be bare")
	}
}

func TestCloneRefusesAnExistingDirectory(t *testing.T) {
	fakeHome(t)
	allowLocalClones(t)
	parent := t.TempDir()
	inDir(t, parent)
	must(t, os.Mkdir(filepath.Join(parent, "proj"), 0o755))
	if _, err := runDevkit(t, "", "clone", "file://"+upstreamRepo(t), "proj"); err == nil {
		t.Error("an existing directory must not be reused")
	}
}

func TestRootTakesARepositoryURL(t *testing.T) {
	fakeHome(t)
	allowLocalClones(t)
	parent := t.TempDir()
	inDir(t, parent)
	up := upstreamRepo(t)
	if out, err := runDevkit(t, "", "file://"+up, "--branch", "main", "--network", "open"); err != nil {
		t.Fatalf("devkit <url>: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(parent, filepath.Base(up), "devkit.yaml")); err != nil {
		t.Errorf("devkit <url> should clone into the repository's name: %v", err)
	}
	cfg, err := project.Load(filepath.Join(parent, filepath.Base(up), "devkit.yaml"))
	if err != nil || cfg.Network.Mode != project.NetworkOpen {
		t.Errorf("flags given to devkit <url> should apply: %v %+v", err, cfg)
	}
	_, err = runDevkit(t, "", "upp")
	if err == nil || !strings.Contains(err.Error(), "unknown command") || !strings.Contains(err.Error(), "did you mean up") {
		t.Errorf("a typo should still be an unknown command with suggestions, got %v", err)
	}
}

// clonedProject runs devkit clone and returns the project directory.
func clonedProject(t *testing.T) (dir, upstream string) {
	t.Helper()
	allowLocalClones(t)
	upstream = upstreamRepo(t)
	parent := t.TempDir()
	inDir(t, parent)
	if out, err := runDevkit(t, "", "clone", "file://"+upstream, "proj"); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	dir = filepath.Join(parent, "proj")
	inDir(t, dir)
	return dir, upstream
}

func TestGitSourceDeliversTheCloneToTheVM(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	f.Reset()
	if err := syncSource(context.Background(), cfg, dir); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	_, streams := tarStreams(calls, f.Inputs())
	if len(streams) != 1 {
		t.Fatalf("want one .git stream, got %d", len(streams))
	}
	vm := t.TempDir()
	untar(t, streams[0], vm)
	if gitIn(t, vm, "rev-parse", "HEAD") != gitIn(t, upstream, "rev-parse", "HEAD") {
		t.Error("the VM should get the cloned commit")
	}
	if !mentions(calls, "git reset -q --hard") {
		t.Error("the VM checks the files out itself")
	}
	if mentions(calls, "git clone") {
		t.Error("the VM must not clone over the network: the host already has the repository")
	}
}

func TestGitSourceSyncBringsNewUpstreamCommits(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(upstream, "later.txt"), []byte("l\n"), 0o644))
	gitIn(t, upstream, "add", ".")
	gitIn(t, upstream, "commit", "-qm", "later")
	f.SetInstances(fakelima.Instance{Name: cfg.VMName(), Status: "Running"})
	provisioned(f, "current")
	f.OnShell(`/.git" && echo yes`, "yes", 0)
	f.Reset()
	if out, err := runDevkit(t, "", "sync"); err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	bare := filepath.Join(dir, project.LockDir, "repo.git")
	if gitIn(t, bare, "rev-parse", "HEAD") != gitIn(t, upstream, "rev-parse", "HEAD") {
		t.Error("the host copy should have fetched the new commit")
	}
	calls := f.Calls()
	if !hasVerb(calls, "copy") || !mentions(calls, "merge --ff-only") {
		t.Errorf("the new commits should reach the VM as a bundle and fast-forward there: %v", calls)
	}
	if mentions(calls, "pull") {
		t.Error("the VM must not pull over the network")
	}
}

func hasVerb(calls [][]string, verb string) bool {
	for _, c := range calls {
		if len(c) > 0 && c[0] == verb {
			return true
		}
	}
	return false
}

func TestPushFromAClonedProject(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	bare := filepath.Join(dir, project.LockDir, "repo.git")
	// The remote has the full history, as a real one would.
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitIn(t, bare, "clone", "-q", "--bare", "--no-local", upstream, remote)
	gitIn(t, bare, "remote", "set-url", "origin", remote)

	snap, err := gitx.TakeSnapshot(context.Background(), bare)
	if err != nil || snap == nil {
		t.Fatal(err)
	}
	defer snap.Close()
	vm := snap.Dir
	gitIn(t, vm, "reset", "-q", "--hard")
	gitIn(t, vm, "config", "user.name", "Agent")
	gitIn(t, vm, "config", "user.email", "agent@vm")
	must(t, os.WriteFile(filepath.Join(vm, "new.txt"), []byte("n\n"), 0o644))
	gitIn(t, vm, "add", ".")
	gitIn(t, vm, "commit", "-qm", "from the vm")
	b := filepath.Join(t.TempDir(), "b.bundle")
	gitIn(t, vm, "bundle", "create", "-q", b, "refs/heads/main", "^"+gitIn(t, bare, "rev-parse", "HEAD"))
	data, _ := os.ReadFile(b)
	f.SetInstances(fakelima.Instance{Name: cfg.VMName(), Status: "Running"})
	f.OnShell("symbolic-ref --short -q HEAD", "main", 0)
	f.OnShell("git bundle create", "devkit-exit=0", 0)
	f.OnShell("devkit-push-", string(data), 0)

	// A push to another remote, such as a fork, must not move the cached
	// origin branch.
	fork := filepath.Join(t.TempDir(), "fork.git")
	gitIn(t, bare, "clone", "-q", "--bare", "--no-local", remote, fork)
	gitIn(t, bare, "remote", "add", "fork", fork)
	before := gitIn(t, bare, "rev-parse", "refs/heads/main")
	if out, err := runDevkit(t, "", "push", "--yes", "--remote", "fork"); err != nil {
		t.Fatalf("push to fork: %v\n%s", err, out)
	}
	if gitIn(t, fork, "rev-parse", "main") != gitIn(t, vm, "rev-parse", "HEAD") {
		t.Error("the fork should have the VM's commit")
	}
	if gitIn(t, bare, "rev-parse", "refs/heads/main") != before {
		t.Error("a push to a fork must leave the cached origin branch alone")
	}

	if out, err := runDevkit(t, "", "push", "--yes"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	want := gitIn(t, vm, "rev-parse", "HEAD")
	if gitIn(t, remote, "rev-parse", "main") != want {
		t.Error("the remote should have the VM's commit")
	}
	if gitIn(t, bare, "rev-parse", "refs/heads/main") != want {
		t.Error("the host copy should record what was pushed, so the next review starts there")
	}

	// The Mac now has the commit, so the VM has nothing new to send; a
	// push to a destination that still lacks it must go ahead anyway.
	fork2 := filepath.Join(t.TempDir(), "fork2.git")
	gitIn(t, bare, "clone", "-q", "--bare", "--no-local", upstream, fork2)
	gitIn(t, bare, "remote", "add", "fork2", fork2)
	f.OnShell(want, "devkit-tip="+want+"\ndevkit-exit=4", 0)
	if out, err := runDevkit(t, "", "push", "--yes", "--remote", "fork2"); err != nil {
		t.Fatalf("push to fork2: %v\n%s", err, out)
	}
	if gitIn(t, fork2, "rev-parse", "main") != want {
		t.Error("fork2 should get the commit the Mac already holds")
	}

	// A branch that does not exist on the remote yet is not "nothing to
	// push", even though the Mac holds every commit.
	if out, err := runDevkit(t, "", "push", "--yes", "--to", "release"); err != nil {
		t.Fatalf("push --to release: %v\n%s", err, out)
	}
	if gitIn(t, remote, "rev-parse", "release") != want {
		t.Error("release should be created on origin")
	}
}

func TestUpstreamScriptMovesOnlyTheConfiguredBranch(t *testing.T) {
	up := upstreamRepo(t)
	base := gitIn(t, up, "rev-parse", "HEAD")
	vm := t.TempDir()
	gitIn(t, vm, "clone", "-q", "--no-local", up, ".")
	gitIn(t, vm, "switch", "-q", "-c", "feature")
	must(t, os.WriteFile(filepath.Join(up, "new.txt"), []byte("n\n"), 0o644))
	gitIn(t, up, "add", ".")
	gitIn(t, up, "commit", "-qm", "upstream moved")
	gitIn(t, up, "update-ref", "refs/devkit/upstream/main", "HEAD")
	b := filepath.Join(t.TempDir(), "u.bundle")
	gitIn(t, up, "bundle", "create", "-q", b, "refs/devkit/upstream/main", "^"+base)
	cmd := exec.Command("bash", "-c", upstreamScript("$HOME/"+filepath.Base(vm), b, "main", "refs/devkit/upstream/main"))
	cmd.Env = append(os.Environ(), "HOME="+filepath.Dir(vm))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if gitIn(t, vm, "rev-parse", "feature") != base {
		t.Error("the checked-out feature branch must not move")
	}
	if gitIn(t, vm, "rev-parse", "main") != gitIn(t, up, "rev-parse", "HEAD") {
		t.Errorf("main should fast-forward to origin/main:\n%s", out)
	}
}

func TestFailedHandOverKeepsTheMacsBranch(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	bare := filepath.Join(dir, project.LockDir, "repo.git")
	before := gitIn(t, bare, "rev-parse", "refs/heads/main")
	must(t, os.WriteFile(filepath.Join(upstream, "later.txt"), []byte("l\n"), 0o644))
	gitIn(t, upstream, "add", ".")
	gitIn(t, upstream, "commit", "-qm", "later")
	f.SetInstances(fakelima.Instance{Name: cfg.VMName(), Status: "Running"})
	provisioned(f, "current")
	f.OnShell(`/.git" && echo yes`, "yes", 0)
	f.OnShell("refs/remotes/origin/main", "could not apply", 1)
	if _, err := runDevkit(t, "", "sync"); err == nil {
		t.Fatal("a failed hand-over should fail sync")
	}
	if gitIn(t, bare, "rev-parse", "refs/heads/main") != before {
		t.Error("the Mac's branch must stay where the VM is, so the next sync retries")
	}
}

// An upstream branch that moved back has no new commits to bundle. Sync
// must record the move, not fail on an empty bundle forever after.
func TestSyncAfterUpstreamRewinds(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	bare := filepath.Join(dir, project.LockDir, "repo.git")
	start := gitIn(t, upstream, "rev-parse", "HEAD")
	must(t, os.WriteFile(filepath.Join(upstream, "later.txt"), []byte("l\n"), 0o644))
	gitIn(t, upstream, "add", ".")
	gitIn(t, upstream, "commit", "-qm", "later")
	f.SetInstances(fakelima.Instance{Name: cfg.VMName(), Status: "Running"})
	provisioned(f, "current")
	f.OnShell(`/.git" && echo yes`, "yes", 0)
	if out, err := runDevkit(t, "", "sync"); err != nil {
		t.Fatalf("first sync: %v\n%s", err, out)
	}
	gitIn(t, upstream, "reset", "-q", "--hard", start)
	f.Reset()
	if out, err := runDevkit(t, "", "sync"); err != nil {
		t.Fatalf("sync after a rewind: %v\n%s", err, out)
	}
	calls := f.Calls()
	if hasVerb(calls, "copy") {
		t.Error("a rewind has no commits to send")
	}
	if !mentions(calls, "update-ref refs/remotes/origin/main "+start) {
		t.Error("the VM's origin/main should move back")
	}
	if gitIn(t, bare, "rev-parse", "refs/heads/main") != start {
		t.Error("the Mac's copy should record the rewind")
	}
}

// A target that cleans to an existing directory must be refused before
// anything is created, so cleanup can never remove a directory clone did
// not make.
func TestCloneNeverTargetsAnExistingDirectory(t *testing.T) {
	fakeHome(t)
	allowLocalClones(t)
	up := upstreamRepo(t)
	parent := t.TempDir()
	inDir(t, parent)
	sentinel := filepath.Join(parent, "mine.txt")
	must(t, os.WriteFile(sentinel, []byte("keep"), 0o644))
	for _, target := range []string{"missing/..", "./", "missing/../.", parent} {
		if _, err := runDevkit(t, "", "clone", "file://"+up, target); err == nil {
			t.Errorf("clone into %q should be refused", target)
		}
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("the current directory was touched")
	}
	if _, err := os.Stat(filepath.Join(parent, "devkit.yaml")); err == nil {
		t.Error("nothing may be written into an existing directory")
	}
}

func TestSyncLeavesNoStagingRefs(t *testing.T) {
	f, _ := fakeHome(t)
	dir, upstream := clonedProject(t)
	cfg, err := project.Load(filepath.Join(dir, "devkit.yaml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(upstream, "later.txt"), []byte("l\n"), 0o644))
	gitIn(t, upstream, "add", ".")
	gitIn(t, upstream, "commit", "-qm", "later")
	f.SetInstances(fakelima.Instance{Name: cfg.VMName(), Status: "Running"})
	provisioned(f, "current")
	f.OnShell(`/.git" && echo yes`, "yes", 0)
	if out, err := runDevkit(t, "", "sync"); err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	bare := filepath.Join(dir, project.LockDir, "repo.git")
	if refs := gitIn(t, bare, "for-each-ref", "refs/devkit/upstream"); refs != "" {
		t.Errorf("each sync stages under its own ref and removes it: %s", refs)
	}
	if gitIn(t, bare, "rev-parse", "refs/heads/main") != gitIn(t, upstream, "rev-parse", "HEAD") {
		t.Error("the delivered commit should be recorded")
	}
}
