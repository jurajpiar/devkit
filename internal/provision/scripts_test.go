package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

// TestRenderedScriptsParse renders the system and user scripts for every
// combination of network mode, toolchain manager and source mode, and checks
// each with bash -n and, where installed, ShellCheck at error severity. CI
// sets DEVKIT_REQUIRE_SHELLCHECK=1 so a missing ShellCheck fails rather than
// skipping silently.
func TestRenderedScriptsParse(t *testing.T) {
	shellcheck, err := exec.LookPath("shellcheck")
	if err != nil && os.Getenv("DEVKIT_REQUIRE_SHELLCHECK") != "" {
		t.Fatal("shellcheck is required (DEVKIT_REQUIRE_SHELLCHECK) but not installed")
	}
	dir := t.TempDir()
	n := 0
	for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone} {
		for _, mgr := range []string{project.ManagerMise, project.ManagerNix, project.ManagerNone} {
			for _, src := range []string{project.SourceCopy, project.SourceMount} {
				p := params(func(c *project.Config) {
					c.Network.Mode = mode
					c.Tools.Manager = mgr
					c.Source = src
					// One manager's variants also carry a service, so its
					// rendering is checked in every network mode.
					if mgr == project.ManagerNone {
						c.Services.Postgres = &project.Postgres{Port: 5433, User: "u", Password: "p", Database: "d"}
					}
				})
				for kind, render := range map[string]func(Params) (string, error){"system": System, "user": User} {
					s, err := render(p)
					if err != nil {
						t.Fatal(err)
					}
					name := strings.Join([]string{kind, mode, mgr, src}, "-")
					path := filepath.Join(dir, name+".sh")
					if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
						t.Fatal(err)
					}
					n++
					if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
						t.Errorf("%s does not parse: %s", name, out)
					}
					if shellcheck != "" {
						if out, err := exec.Command(shellcheck, "--severity=error", "--shell=bash", path).CombinedOutput(); err != nil {
							t.Errorf("shellcheck %s:\n%s", name, out)
						}
					}
				}
			}
		}
	}
	if n != 36 {
		t.Errorf("expected 36 scripts, rendered %d", n)
	}
}
