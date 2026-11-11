package lima

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
)

func TestListAndGetParseLimactlOutput(t *testing.T) {
	f := fakelima.Install(t)
	f.SetInstances(fakelima.Instance{Name: "devkit-a", Status: "Running"}, fakelima.Instance{Name: "other", Status: "Stopped"})
	ctx := context.Background()
	list, err := List(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "devkit-a" || !list[0].Running() || list[1].Running() {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if got, _ := Get(ctx, "other"); got == nil || got.Status != "Stopped" {
		t.Errorf("Get(other) = %+v", got)
	}
	if got, _ := Get(ctx, "missing"); got != nil {
		t.Errorf("Get(missing) should be nil, got %+v", got)
	}
}

func TestCommandsPassTheExpectedArguments(t *testing.T) {
	f := fakelima.Install(t)
	ctx := context.Background()
	steps := []struct {
		run  func() error
		want []string
	}{
		{func() error { return Create(ctx, "devkit-a", "/tmp/a.yaml") }, []string{"create", "--tty=false", "--name", "devkit-a", "/tmp/a.yaml"}},
		{func() error { return Start(ctx, "devkit-a") }, []string{"start", "--tty=false", "devkit-a"}},
		{func() error { return Stop(ctx, "devkit-a") }, []string{"stop", "devkit-a"}},
		{func() error { return Delete(ctx, "devkit-a", true) }, []string{"delete", "devkit-a", "--force"}},
		{func() error { return Delete(ctx, "devkit-a", false) }, []string{"delete", "devkit-a"}},
		{func() error { return Validate(ctx, "/tmp/a.yaml") }, []string{"validate", "/tmp/a.yaml"}},
		{func() error { _, err := Exec(ctx, "devkit-a", "echo hi"); return err }, []string{"shell", "devkit-a", "--", "bash", "-lc", "echo hi"}},
	}
	for _, s := range steps {
		f.Reset()
		if err := s.run(); err != nil {
			t.Fatalf("%v: %v", s.want, err)
		}
		if got := f.Calls(); len(got) != 1 || !reflect.DeepEqual(got[0], s.want) {
			t.Errorf("want %q, got %q", s.want, got)
		}
	}
}

func TestExecReturnsOutputAndReportsFailure(t *testing.T) {
	f := fakelima.Install(t)
	f.OnShell("cat /etc/devkit/provision.id", "abc123\n", 0)
	f.OnShell("false-cmd", "", 3)
	ctx := context.Background()
	if out, err := Exec(ctx, "devkit-a", "cat /etc/devkit/provision.id"); err != nil || out != "abc123\n" {
		t.Errorf("Exec = %q, %v", out, err)
	}
	if _, err := Exec(ctx, "devkit-a", "false-cmd"); err == nil || !strings.HasPrefix(err.Error(), "limactl shell:") {
		t.Errorf("a failing command should surface as an error, got %v", err)
	}
}

func TestVersionAndCheckInstalled(t *testing.T) {
	fakelima.Install(t)
	if v, err := Version(context.Background()); err != nil || !strings.Contains(v, "2.2.1") {
		t.Errorf("Version = %q, %v", v, err)
	}
	if err := CheckInstalled(); err != nil {
		t.Errorf("CheckInstalled with limactl on PATH: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := CheckInstalled(); err != ErrNotInstalled {
		t.Errorf("without limactl, want ErrNotInstalled, got %v", err)
	}
}

// A command spanning several lines, as devkit's install script does, is
// recorded as one call with its argument intact.
func TestFakeRecordsMultilineCommandsAsOneCall(t *testing.T) {
	f := fakelima.Install(t)
	cmd := "cd ~/workspace\nif [ -f package.json ]; then\n  npm ci\nfi"
	if _, err := Exec(context.Background(), "devkit-a", cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := Exec(context.Background(), "devkit-a", "echo two"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 || calls[0][len(calls[0])-1] != cmd || calls[1][0] != "shell" {
		t.Errorf("want two calls with the multi-line command intact, got %q", calls)
	}
}

// List must not ask limactl for whole instances (the plain "json" format):
// that prints each instance's config, provisioning scripts included, on one
// line, and limactl fails the entire listing once a line passes 64 KiB. It
// must still ask for every field Instance holds.
func TestListAsksOnlyForTheFieldsInstanceHolds(t *testing.T) {
	f := fakelima.Install(t)
	if _, err := List(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || len(calls[0]) != 3 || calls[0][0] != "list" || calls[0][1] != "--format" {
		t.Fatalf("calls = %q, want one list --format <template>", calls)
	}
	format := calls[0][2]
	if format == "json" || format == "yaml" || strings.Contains(format, "{{json .}}") || strings.Contains(format, ".Config") {
		t.Fatalf("list asks for whole instances: %q", format)
	}
	typ := reflect.TypeFor[Instance]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if want := fmt.Sprintf(`"%s":{{json .%s}}`, tag, field.Name); !strings.Contains(format, want) {
			t.Errorf("list format %q lacks %s", format, want)
		}
	}
}
