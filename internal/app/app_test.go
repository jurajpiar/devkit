package app

import (
	"os"
	"os/exec"
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

func TestWriteSSHConfigPutsBlockFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".ssh", "config")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ServerAliveInterval 37\nForwardAgent yes\nHost *\n  Port 22\n  User someone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := project.Default()
	c.Name = "demo"
	if err := writeSSHConfig(c); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.HasPrefix(s, "# BEGIN devkit demo ") {
		t.Fatalf("managed block must come first so OpenSSH's first-match rules pick it:\n%s", s)
	}
	if !strings.Contains(s, "ServerAliveInterval 37\nForwardAgent yes\nHost *\n  Port 22\n  User someone\n") {
		t.Fatalf("existing config lost:\n%s", s)
	}
	// Ask ssh itself how the file resolves: our host gets our settings, other
	// hosts keep the user's global options, and the sandbox never gets the agent.
	if ssh, err := exec.LookPath("ssh"); err == nil {
		effective := func(host string) string {
			out, err := exec.Command(ssh, "-G", "-F", path, host).Output()
			if err != nil {
				t.Fatalf("ssh -G %s: %v", host, err)
			}
			return string(out)
		}
		other := effective("elsewhere")
		if !strings.Contains(other, "serveraliveinterval 37\n") || !strings.Contains(other, "port 22\n") {
			t.Fatalf("global options must still apply to other hosts:\n%s", other)
		}
		ours := effective("devkit-demo")
		if !strings.Contains(ours, "port 2222\n") || !strings.Contains(ours, "forwardagent no\n") || !strings.Contains(ours, "serveraliveinterval 37\n") {
			t.Fatalf("devkit host should get its port, no agent forwarding, and still inherit globals:\n%s", ours)
		}
	}
	// Second write is idempotent.
	if err := writeSSHConfig(c); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != s {
		t.Fatalf("rewrite changed the file:\n%s\n---\n%s", s, again)
	}
}

func TestFindSourceIgnoresWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "egressproxy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmd", "egressproxy", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEVKIT_SRC", "")
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if src, err := findSource(); err == nil && strings.HasPrefix(src, dir) {
		t.Fatalf("proxy source must not be taken from the sandboxed project: %s", src)
	}
	t.Setenv("DEVKIT_SRC", dir)
	if src, err := findSource(); err != nil || src != dir {
		t.Fatalf("DEVKIT_SRC should be honoured: %v %q", err, src)
	}
}
