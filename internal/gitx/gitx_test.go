package gitx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo makes a work tree with a secret committed and then deleted, a tag,
// a second branch, a stash, a hook, and a token in the remote URL: all of
// what a fresh clone would not carry.
func repo(t *testing.T) (dir, secretBlob string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "secret.env", "API_KEY=hunter2\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-qm", "one")
	secretBlob = git(t, dir, "rev-parse", "HEAD:secret.env")
	git(t, dir, "tag", "v1")
	git(t, dir, "branch", "other")
	git(t, dir, "rm", "-q", "secret.env")
	write(t, dir, "app.txt", "hello\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-qm", "two")
	write(t, dir, "app.txt", "work in progress\n")
	git(t, dir, "stash", "-q")
	git(t, dir, "remote", "add", "origin", "https://user:ghp_token@github.com/org/repo.git")
	git(t, dir, "config", "credential.helper", "store")
	write(t, dir, ".git/hooks/post-checkout", "#!/bin/sh\necho hooked\n")
	return dir, secretBlob
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotIsAFreshClone(t *testing.T) {
	src, secret := repo(t)
	head := git(t, src, "rev-parse", "HEAD")
	s, err := TakeSnapshot(context.Background(), src)
	if err != nil || s == nil {
		t.Fatalf("snapshot: %v %v", s, err)
	}
	defer s.Close()
	if s.Branch != "main" || s.Head != head {
		t.Errorf("branch %q head %q, want main %s", s.Branch, s.Head, head)
	}
	entries, _ := os.ReadDir(s.Dir)
	if len(entries) != 1 || entries[0].Name() != ".git" {
		t.Fatalf("snapshot dir should hold only .git, has %v", entries)
	}
	if n := git(t, s.Dir, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("history: %s commits, want 1", n)
	}
	if git(t, s.Dir, "rev-parse", "HEAD") != head {
		t.Error("HEAD should be the host's commit")
	}
	objs := git(t, s.Dir, "cat-file", "--batch-all-objects", "--batch-check")
	if strings.Contains(objs, secret) {
		t.Error("a secret deleted from history must not be in the snapshot")
	}
	if refs := git(t, s.Dir, "for-each-ref", "--format=%(refname)"); refs != "refs/heads/main" {
		t.Errorf("only the current branch should exist, got:\n%s", refs)
	}
	if hooks, _ := os.ReadDir(filepath.Join(s.Dir, ".git", "hooks")); len(hooks) != 0 {
		t.Errorf("no hooks may be copied, found %v", hooks)
	}
	cfg, _ := os.ReadFile(filepath.Join(s.Dir, ".git", "config"))
	for _, bad := range []string{"ghp_token", "user:", "credential", "ignorecase", "precomposeunicode"} {
		if strings.Contains(string(cfg), bad) {
			t.Errorf("config must not contain %q:\n%s", bad, cfg)
		}
	}
	if u := git(t, s.Dir, "config", "remote.origin.url"); u != "https://github.com/org/repo.git" {
		t.Errorf("origin = %q, want the URL without credentials", u)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, ".git", "FETCH_HEAD")); err == nil {
		t.Error("FETCH_HEAD names the host path; remove it")
	}
	if strings.Contains(string(cfg), src) {
		t.Error("the snapshot must not record the host path")
	}
}

func TestSnapshotDetachedHead(t *testing.T) {
	src, _ := repo(t)
	git(t, src, "checkout", "-q", "--detach", "HEAD~1")
	s, err := TakeSnapshot(context.Background(), src)
	if err != nil || s == nil {
		t.Fatalf("snapshot: %v", err)
	}
	defer s.Close()
	if s.Branch != "" {
		t.Errorf("branch = %q, want detached", s.Branch)
	}
	if git(t, s.Dir, "rev-parse", "HEAD") != git(t, src, "rev-parse", "HEAD") {
		t.Error("detached HEAD should point at the host's commit")
	}
}

func TestSnapshotUnbornAndNonRepos(t *testing.T) {
	unborn := t.TempDir()
	git(t, unborn, "init", "-q", "-b", "trunk")
	s, err := TakeSnapshot(context.Background(), unborn)
	if err != nil || s == nil {
		t.Fatalf("unborn: %v", err)
	}
	defer s.Close()
	if s.Head != "" || s.Branch != "trunk" {
		t.Errorf("unborn: head %q branch %q", s.Head, s.Branch)
	}
	if got := git(t, s.Dir, "symbolic-ref", "HEAD"); got != "refs/heads/trunk" {
		t.Errorf("unborn HEAD = %q", got)
	}

	if s, err := TakeSnapshot(context.Background(), t.TempDir()); s != nil || err != nil {
		t.Errorf("a plain directory has no snapshot: %v %v", s, err)
	}
	// A subdirectory of a repository is not the repository: its .git would
	// describe files that were never copied.
	src, _ := repo(t)
	sub := filepath.Join(src, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if s, err := TakeSnapshot(context.Background(), sub); s != nil || err != nil {
		t.Errorf("a subdirectory has no snapshot: %v %v", s, err)
	}
}

func TestSanitizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:tok@github.com/org/repo.git": "https://github.com/org/repo.git",
		"https://tok@github.com/org/repo":          "https://github.com/org/repo",
		"https://github.com/org/repo?token=x#frag": "https://github.com/org/repo",
		"git@github.com:org/repo.git":              "git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git":        "ssh://git@github.com/org/repo.git",
		"ssh://git:pw@github.com/org/repo.git":     "ssh://git@github.com/org/repo.git",
		"/Users/me/repo":                           "",
		"file:///Users/me/repo":                    "",
		"ext::sh -c touch% /tmp/pwned":             "",
		"":                                         "",
	} {
		if got := SanitizeURL(in); got != want {
			t.Errorf("SanitizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}
