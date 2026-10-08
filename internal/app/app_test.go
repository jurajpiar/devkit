package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

func TestSlugAndRepoName(t *testing.T) {
	cases := map[string]string{
		"My Project":    "my-project",
		"foo_bar.baz":   "foo-bar-baz",
		"---":           "sandbox",
		"UPPER":         "upper",
		"ok-already-12": "ok-already-12",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"git@github.com:user/repo.git":     "repo",
		"https://github.com/user/repo":     "repo",
		"https://github.com/user/repo.git": "repo",
	} {
		if got := repoName(in); got != want {
			t.Errorf("repoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNodeMajor(t *testing.T) {
	for in, want := range map[string]string{"node:22-alpine": "22", "20.11.1": "20", "lts": "", "node:lts-alpine": ""} {
		if got := nodeMajor(in); got != want {
			t.Errorf("nodeMajor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderConfigParses(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	c.Tools.Node = "22"
	c.SSHPort = 2230
	got, err := project.Parse([]byte(renderConfig(c)))
	if err != nil {
		t.Fatalf("rendered config does not parse: %v\n%s", err, renderConfig(c))
	}
	if got.Name != "demo" || got.SSHPort != 2230 || got.Tools.Node != "22" || len(got.Network.Allow) != len(project.DefaultAllow) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	c.Source = project.SourceGit
	c.Repo = "https://github.com/x/y.git"
	if _, err := project.Parse([]byte(renderConfig(c))); err != nil {
		t.Fatalf("git config does not parse: %v", err)
	}
}

func TestSSHBlockAddRemove(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	content := "Host other\n  HostName 1.2.3.4\n"
	content = removeSSHBlock(content, "demo") + "\n" + sshBlock(c)
	if !strings.Contains(content, "Host devkit-demo") || !strings.Contains(content, "Host other") {
		t.Fatalf("block not added:\n%s", content)
	}
	// Adding again must replace, not duplicate.
	again := removeSSHBlock(content, "demo") + "\n" + sshBlock(c)
	if strings.Count(again, "Host devkit-demo") != 1 {
		t.Fatalf("block duplicated:\n%s", again)
	}
	removed := removeSSHBlock(again, "demo")
	if strings.Contains(removed, "devkit") || !strings.Contains(removed, "Host other") {
		t.Fatalf("block not removed cleanly:\n%q", removed)
	}
	if removeSSHBlock(sshBlock(c), "demo") != "" {
		t.Fatal("removing the only block should leave an empty file")
	}
}

func TestSetNetworkMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devkit.yaml")
	c := project.Default()
	c.Name = "demo"
	if err := os.WriteFile(path, []byte(renderConfig(c)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setNetworkMode(path, "none"); err != nil {
		t.Fatal(err)
	}
	got, err := project.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.Mode != project.NetworkNone {
		t.Fatalf("mode = %s", got.Network.Mode)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# allowlist | open | none") {
		t.Fatal("comments were lost")
	}
	if err := setNetworkMode(path, "paranoid"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
