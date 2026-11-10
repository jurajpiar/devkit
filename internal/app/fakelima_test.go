package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// These tests run devkit's commands against a fake limactl (see
// internal/fakelima) with a temporary HOME, so they check what devkit asks
// Lima to do, and what it does to ~/.ssh/config and ~/.devkit, without a VM
// and without touching the real ones.

func fakeHome(t *testing.T) (*fakelima.Fake, string) {
	t.Helper()
	f := fakelima.Install(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	return f, home
}

// run executes a devkit command line and restores the flags it may set,
// because cobra keeps flag values between Execute calls.
func runDevkit(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	if stdin != "" {
		r, w, _ := os.Pipe()
		w.WriteString(stdin)
		w.Close()
		old := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = old }()
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	defer func() {
		rootCmd.SetArgs(nil)
		resetFlags(rootCmd)
	}()
	err := rootCmd.Execute()
	return out.String(), err
}

// resetFlags returns every flag of c and its subcommands to its default.
func resetFlags(c *cobra.Command) {
	reset := func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	}
	c.Flags().VisitAll(reset)
	c.PersistentFlags().VisitAll(reset)
	for _, sub := range c.Commands() {
		resetFlags(sub)
	}
}

func hasCall(calls [][]string, want ...string) bool {
	for _, c := range calls {
		if reflect.DeepEqual(c, want) {
			return true
		}
	}
	return false
}

func mentions(calls [][]string, s string) bool {
	for _, c := range calls {
		for _, a := range c {
			if strings.Contains(a, s) {
				return true
			}
		}
	}
	return false
}

func TestReconcileVM(t *testing.T) {
	const name = "devkit-demo"
	ctx := context.Background()
	writeLimaYAML := func(content string) {
		if err := os.MkdirAll(lima.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := lima.WriteConfig(name, content); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		label  string
		inst   *lima.Instance
		stored string // the instance's lima.yaml, "" for none
		want   []string
	}{
		// Each ends by checking the provision stamp ("shell").
		{"new VM", nil, "", []string{"validate", "create", "start", "shell"}},
		{"running, config unchanged", &lima.Instance{Name: name, Status: "Running"}, "rendered", []string{"shell"}},
		{"running, config changed", &lima.Instance{Name: name, Status: "Running"}, "old", []string{"stop", "start", "shell"}},
		{"stopped, config unchanged", &lima.Instance{Name: name, Status: "Stopped"}, "rendered", []string{"start", "shell"}},
		{"stopped, config changed", &lima.Instance{Name: name, Status: "Stopped"}, "old", []string{"start", "shell"}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			f, home := fakeHome(t)
			provisioned(f, "current")
			if c.stored != "" {
				writeLimaYAML(c.stored)
			}
			if err := reconcileVM(ctx, name, "rendered", c.inst, lima.Start); err != nil {
				t.Fatal(err)
			}
			if got := f.Verbs(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("limactl calls = %v, want %v", got, c.want)
			}
			if c.inst != nil && c.stored != "" && c.stored != "rendered" {
				if b, _ := os.ReadFile(lima.ConfigPath(name)); string(b) != "rendered" {
					t.Errorf("a changed config must be written to the instance, got %q", b)
				}
			}
			if c.inst == nil {
				if b, _ := os.ReadFile(filepath.Join(home, ".devkit", "instances", name+".yaml")); string(b) != "rendered" {
					t.Errorf("a new VM's config must be kept for create, got %q", b)
				}
			}
		})
	}
}

func sshBlocksFor(t *testing.T, names ...string) {
	t.Helper()
	for i, n := range names {
		c := project.Default()
		c.Name = n
		c.SSHPort = 2222 + i
		if err := writeSSHConfig(c); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRmByNameDeletesOnlyThatVM(t *testing.T) {
	f, home := fakeHome(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-demo", Status: "Running"}, fakelima.Instance{Name: "devkit-other", Status: "Running"})
	sshBlocksFor(t, "demo", "other")
	if _, err := runDevkit(t, "", "rm", "--force", "demo"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if !hasCall(calls, "delete", "devkit-demo", "--force") {
		t.Errorf("want delete of devkit-demo, got %q", calls)
	}
	if mentions(calls, "devkit-other") {
		t.Errorf("rm demo must never name another VM: %q", calls)
	}
	cfg, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if strings.Contains(string(cfg), "BEGIN devkit demo ") || !strings.Contains(string(cfg), "BEGIN devkit other ") {
		t.Errorf("only demo's SSH block should go:\n%s", cfg)
	}
}

func TestRmAsksAndAcceptsNo(t *testing.T) {
	f, _ := fakeHome(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-demo", Status: "Running"})
	if _, err := runDevkit(t, "n\n", "rm", "demo"); err != nil {
		t.Fatal(err)
	}
	if mentions(f.Calls(), "delete") {
		t.Errorf("answering no must delete nothing: %q", f.Calls())
	}
}

func TestRmOfAMissingVMDeletesNothing(t *testing.T) {
	f, _ := fakeHome(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-other", Status: "Running"})
	if _, err := runDevkit(t, "", "rm", "--force", "ghost"); err != nil {
		t.Fatal(err)
	}
	if mentions(f.Calls(), "delete") {
		t.Errorf("a VM that does not exist must not be deleted: %q", f.Calls())
	}
}

func TestDownStopsOnlyARunningVM(t *testing.T) {
	f, _ := fakeHome(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-up", Status: "Running"}, fakelima.Instance{Name: "devkit-off", Status: "Stopped"})
	runDevkit(t, "", "down", "up")
	runDevkit(t, "", "down", "off")
	calls := f.Calls()
	if !hasCall(calls, "stop", "devkit-up") {
		t.Errorf("a running VM should be stopped: %q", calls)
	}
	if hasCall(calls, "stop", "devkit-off") {
		t.Errorf("a stopped VM should be left alone: %q", calls)
	}
}

func TestShellRefusesAVMThatIsNotRunning(t *testing.T) {
	f, home := fakeHome(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-demo", Status: "Stopped"})
	cfgPath := filepath.Join(home, "devkit.yaml")
	os.WriteFile(cfgPath, []byte("name: demo\n"), 0o644)
	_, err := runDevkit(t, "", "shell", "--config", cfgPath, "true")
	if err == nil || !strings.Contains(err.Error(), "is stopped") {
		t.Errorf("shell on a stopped VM should say so, got %v", err)
	}
	if mentions(f.Calls(), "shell") {
		t.Errorf("no shell should be opened: %q", f.Calls())
	}
}

func TestWarnIfStale(t *testing.T) {
	old := provisionIDFor
	defer func() { provisionIDFor = old }()
	provisionIDFor = func(context.Context, *project.Config) string { return "want0000000" }
	cfg := project.Default()
	cfg.Name = "demo"
	cases := []struct {
		label, out string
		code       int
		want       string // substring of the warning, "" for silence
	}{
		{"current", "want0000000\n", 0, ""},
		{"older policy", "old11111111\n", 0, "applied an older devkit policy (old11111111; this devkit expects want0000000)"},
		{"no stamp, from before the feature", "", 0, "predates the current devkit's sandbox policy"},
		{"ssh failed", "", 255, ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			f, _ := fakeHome(t)
			if c.label == "no stamp, from before the feature" {
				// Like real cat on a missing file: it fails unless the
				// command tolerates that with "|| true".
				f.OnShell("provision.id 2>/dev/null || true", "", 0)
				f.OnShell("provision.id", "", 1)
			} else {
				f.OnShell("provision.id", c.out, c.code)
			}
			var w bytes.Buffer
			warnIfStaleTo(context.Background(), cfg, &w)
			if c.want == "" && w.Len() != 0 {
				t.Errorf("should be silent, got %q", w.String())
			}
			if c.want != "" && !strings.Contains(w.String(), c.want) {
				t.Errorf("want %q in %q", c.want, w.String())
			}
			if c.want != "" && !strings.Contains(w.String(), "devkit down && devkit up") {
				t.Error("the warning must say how to fix it")
			}
		})
	}
}
