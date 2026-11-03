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

func TestRenderConfigParses(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	c.Tools.Manager = project.ManagerMise
	c.Tools.Versions = map[string]string{"node": "22", "go": "1.27"}
	c.Tools.Packages = []string{"pkg-config"}
	c.Install = "make deps"
	c.SSHPort = 2230
	got, err := project.Parse([]byte(renderConfig(c)))
	if err != nil {
		t.Fatalf("rendered config does not parse: %v\n%s", err, renderConfig(c))
	}
	if got.Name != "demo" || got.SSHPort != 2230 || got.Tools.Manager != project.ManagerMise ||
		got.Tools.Versions["node"] != "22" || got.Tools.Versions["go"] != "1.27" ||
		len(got.Tools.Packages) != 1 || len(got.Network.Allow) != len(project.DefaultAllow) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got.Install != "" {
		t.Fatal("install is only ever written by the user, not by init")
	}
	for _, m := range []string{project.ManagerNix, project.ManagerNone} {
		c.Tools.Manager = m
		c.Tools.Versions = nil
		if got, err := project.Parse([]byte(renderConfig(c))); err != nil || got.Tools.Manager != m {
			t.Fatalf("%s config does not round-trip: %v", m, err)
		}
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

func TestInstallScript(t *testing.T) {
	c := project.Default()
	c.Tools.Manager = project.ManagerMise
	s := installScript(c)
	for _, want := range []string{
		`cd "$HOME/workspace" 2>/dev/null || exit 0`,
		"pnpm install --frozen-lockfile", "yarn install --frozen-lockfile", "npm ci",
		"go mod download", "cargo fetch --locked", "uv sync --frozen", "bundle install",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
	if strings.Contains(s, "nix develop") {
		t.Error("mise mode must not call nix")
	}

	c.Install = "make deps && echo it's done"
	s = installScript(c)
	if !strings.HasSuffix(s, "make deps && echo it's done") || strings.Contains(s, "npm ci") {
		t.Errorf("install: must replace the generic script:\n%s", s)
	}

	c.Tools.Manager = project.ManagerNix
	s = installScript(c)
	want := `if [ -f flake.nix ]; then exec nix develop --command bash -lc 'make deps && echo it'\''s done'; fi`
	if !strings.Contains(s, want) {
		t.Errorf("nix mode should run the install inside the dev shell with safe quoting:\n%s", s)
	}
}

func TestShellScript(t *testing.T) {
	c := project.Default()
	c.Tools.Manager = project.ManagerMise
	if got := shellScript(c, nil); got != `cd $HOME/workspace 2>/dev/null; exec bash -l` {
		t.Errorf("mise shell: %q", got)
	}
	if got := shellScript(c, []string{"node", "--version"}); !strings.HasSuffix(got, "; node --version") {
		t.Errorf("mise command: %q", got)
	}
	c.Tools.Manager = project.ManagerNix
	got := shellScript(c, []string{"go", "version"})
	if !strings.Contains(got, `nix develop --command bash -lc 'go version'`) || !strings.HasSuffix(got, "; go version") {
		t.Errorf("nix command should run in the dev shell and fall back without a flake: %q", got)
	}
}

func TestRenderFlake(t *testing.T) {
	f := renderFlake(map[string]string{"node": "22", "go": "1.27", "python": "3.12", "ruby": "3.3.6", "java": "21", "rust": "latest"})
	for _, want := range []string{
		`inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05"`,
		"packages = with pkgs; [ go_1_27 jdk21 nodejs_22 python312 ruby_3_3 cargo rustc rustfmt clippy ];",
		`"aarch64-linux" "x86_64-linux"`,
	} {
		if !strings.Contains(f, want) {
			t.Errorf("flake missing %q:\n%s", want, f)
		}
	}
	if !strings.Contains(renderFlake(nil), "[ git ]") {
		t.Error("an empty version set should still produce a usable shell")
	}
}

func TestPrintableStripsControlCharacters(t *testing.T) {
	in := "evil\x1b[2J\x1b]0;pwned\x07.example\r\n\x7f"
	if got := printable(in); got != "evil[2J]0;pwned.example" {
		t.Errorf("printable(%q) = %q", in, got)
	}
}

func TestTargetConfigByName(t *testing.T) {
	cmd := rootCmd
	for _, in := range []string{"devkit-demo", "demo"} {
		c, err := targetConfig(cmd, []string{in})
		if err != nil || c.VMName() != "devkit-demo" || c.SSHHost() != "devkit-demo" {
			t.Errorf("targetConfig(%q) = %v, %v", in, c, err)
		}
	}
	for _, in := range []string{"bad name", "../x", "DEVKIT-UP"} {
		if _, err := targetConfig(cmd, []string{in}); err == nil {
			t.Errorf("targetConfig(%q) should be rejected", in)
		}
	}
}
