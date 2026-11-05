package gitx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in, want string
		note     bool
	}{
		{"https://github.com/org/repo", "https://github.com/org/repo", false},
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git", false},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git", false},
		{"ssh://git@github.com/org/repo.git", "ssh://git@github.com/org/repo.git", false},
		{"github.com/org/repo", "https://github.com/org/repo", false},
		{"git://github.com/org/repo", "https://github.com/org/repo", true},
		{"git://github.com/org/repo.git", "https://github.com/org/repo.git", true},
	}
	for _, c := range cases {
		got, note, err := NormalizeURL(c.in)
		if err != nil || got != c.want || (note != "") != c.note {
			t.Errorf("NormalizeURL(%q) = %q, %q, %v; want %q, note %v", c.in, got, note, err, c.want, c.note)
		}
	}
	for _, bad := range []string{
		"", "-uhttps://x", "--upload-pack=touch /tmp/x", "file:///etc", "/Users/me/repo", "../repo",
		"ext::sh -c 'touch /tmp/x'", "fd::3", "http://github.com/org/repo", "https://", "github.com",
		"https://github.com/org/repo\nfoo", "ssh://-oProxyCommand=x/repo", "git@-oProxyCommand=x:repo",
	} {
		if got, _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) = %q, want an error", bad, got)
		}
	}
}

func TestCloneBareChecksOutNothingAndRunsNoHooks(t *testing.T) {
	upstream, _ := repo(t)
	git(t, upstream, "checkout", "-q", "-b", "dev")
	commitIn(t, upstream, "dev.txt", "d\n", "dev work")
	git(t, upstream, "checkout", "-q", "main")
	dst := filepath.Join(t.TempDir(), "repo.git")
	allowFileProtocol = true
	t.Cleanup(func() { allowFileProtocol = false })
	if err := CloneBare(context.Background(), "file://"+upstream, "", dst, os.Stderr); err != nil {
		t.Fatal(err)
	}
	if b := git(t, dst, "rev-parse", "--is-bare-repository"); b != "true" {
		t.Error("the host copy must be bare: no files of the project are written out")
	}
	if n := git(t, dst, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("history: %s commits, want 1", n)
	}
	if hooks, _ := os.ReadDir(filepath.Join(dst, "hooks")); len(hooks) != 0 {
		t.Errorf("no sample hooks expected, got %v", hooks)
	}
	if refs := git(t, dst, "for-each-ref", "--format=%(refname)"); refs != "refs/heads/main" {
		t.Errorf("only the default branch should arrive: %s", refs)
	}

	dev := filepath.Join(t.TempDir(), "dev.git")
	if err := CloneBare(context.Background(), "file://"+upstream, "dev", dev, os.Stderr); err != nil {
		t.Fatal(err)
	}
	if b := git(t, dev, "symbolic-ref", "--short", "HEAD"); b != "dev" {
		t.Errorf("--branch dev: HEAD on %s", b)
	}
}

func TestCloneBareRefusesLocalProtocols(t *testing.T) {
	upstream, _ := repo(t)
	if err := CloneBare(context.Background(), "file://"+upstream, "", filepath.Join(t.TempDir(), "x.git"), os.Stderr); err == nil {
		t.Error("only https and ssh may be cloned")
	}
}

func TestExtractFilesReadsMarkersWithoutACheckout(t *testing.T) {
	upstream, _ := repo(t)
	commitIn(t, upstream, "package.json", `{"name":"x"}`, "pkg")
	commitIn(t, upstream, "sub/go.mod", "module x\n", "nested")
	must(t, os.Symlink("/etc/passwd", filepath.Join(upstream, "go.mod")))
	git(t, upstream, "add", "go.mod")
	git(t, upstream, "commit", "-qm", "symlink")
	dst := t.TempDir()
	if err := ExtractFiles(context.Background(), upstream, "HEAD", []string{"package.json", "go.mod", "missing.txt", "../escape", "sub/go.mod"}, dst); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 1 || entries[0].Name() != "package.json" {
		t.Errorf("only the regular top-level marker should be written, got %v", entries)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "package.json")); !strings.Contains(string(b), `"name":"x"`) {
		t.Errorf("package.json = %q", b)
	}
}

func TestSnapshotOfABareRepository(t *testing.T) {
	upstream, secret := repo(t)
	bare := filepath.Join(t.TempDir(), "repo.git")
	git(t, upstream, "clone", "-q", "--bare", "--no-local", upstream, bare)
	s, err := TakeSnapshot(context.Background(), bare)
	if err != nil || s == nil {
		t.Fatalf("snapshot of bare: %v %v", s, err)
	}
	defer s.Close()
	if s.Branch != "main" || s.Head == "" {
		t.Errorf("branch %q head %q", s.Branch, s.Head)
	}
	if git(t, s.Dir, "rev-parse", "--is-bare-repository") != "false" {
		t.Error("the VM gets a normal repository")
	}
	if strings.Contains(git(t, s.Dir, "cat-file", "--batch-all-objects", "--batch-check"), secret) {
		t.Error("history leaked")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
