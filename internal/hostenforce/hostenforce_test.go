package hostenforce

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRenderMatchesTheSpikeProfile(t *testing.T) {
	got, err := Render(Profile{LimaHome: "/Users/alice/.lima", SSHPort: 2223, ProxyPort: 13128})
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, l := range strings.Split(got, "\n") {
		if l != "" && !strings.HasPrefix(l, ";") {
			rules = append(rules, l)
		}
	}
	want := []string{
		`(version 1)`,
		`(allow default)`,
		`(deny network-outbound)`,
		`(allow network-outbound (remote unix-socket (path-regex #"^/Users/alice/\.lima/")))`,
		`(allow network-outbound (remote ip "localhost:2223"))`,
		`(allow network-outbound (remote ip "localhost:13128"))`,
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("profile rules:\n%s\nwant:\n%s", strings.Join(rules, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderWithoutAProxyOmitsItsRule(t *testing.T) {
	got, err := Render(Profile{LimaHome: "/Users/alice/.lima", SSHPort: 2223})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "(remote ip ") != 1 || !strings.Contains(got, `"localhost:2223"`) {
		t.Errorf("only the SSH forward should be allowed:\n%s", got)
	}
}

// Unix sockets are never allowed wholesale: that let Lima's DNS resolve
// through the Mac's resolver socket in the spike.
func TestRenderNeverAllowsEveryUnixSocket(t *testing.T) {
	got, _ := Render(Profile{LimaHome: "/Users/alice/.lima", SSHPort: 2223, ProxyPort: 1})
	if strings.Contains(got, "(remote unix-socket)") || strings.Count(got, "unix-socket") != 1 {
		t.Errorf("unix sockets must be limited to Lima's home:\n%s", got)
	}
	if strings.Contains(got, "(allow network*)") || strings.Contains(got, "(allow network-outbound)") {
		t.Errorf("no unconditional network allowance:\n%s", got)
	}
}

func TestRenderQuotesRegexMetacharacters(t *testing.T) {
	got, err := Render(Profile{LimaHome: "/Users/a.b/x+y (1)/[lima]|*?^$/", SSHPort: 2222})
	if err != nil {
		t.Fatal(err)
	}
	want := `#"^/Users/a\.b/x\+y \(1\)/\[lima\]\|\*\?\^\$/"`
	if !strings.Contains(got, want) {
		t.Errorf("want %s in:\n%s", want, got)
	}
}

func TestRenderRefusesWhatTheSyntaxCannotCarry(t *testing.T) {
	for _, home := range []string{
		`/Users/a"b/.lima`, `/Users/a\b/.lima`, "/Users/a\nb/.lima", "/Users/a\rb", "/Users/a\tb",
		"/Users/a\x00b", "/Users/a\x1bb", "/Users/a\x7fb", "relative/.lima", "", "/",
	} {
		if s, err := Render(Profile{LimaHome: home, SSHPort: 2222}); err == nil {
			t.Errorf("%q should be refused, got:\n%s", home, s)
		}
	}
	for _, p := range []Profile{
		{LimaHome: "/l", SSHPort: 0}, {LimaHome: "/l", SSHPort: 70000},
		{LimaHome: "/l", SSHPort: 22, ProxyPort: -1}, {LimaHome: "/l", SSHPort: 22, ProxyPort: 65536},
	} {
		if _, err := Render(p); err == nil {
			t.Errorf("%+v should be refused", p)
		}
	}
}

func TestWriteProfileIsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "devkit-demo")
	path, err := WriteProfile(dir, Profile{LimaHome: "/Users/alice/.lima", SSHPort: 2222, ProxyPort: 3000})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || path != filepath.Join(dir, ProfileFile) {
		t.Errorf("profile %s has mode %v, want 0600", path, fi.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"localhost:3000"`) {
		t.Errorf("profile content:\n%s", data)
	}
	if _, err := WriteProfile(dir, Profile{LimaHome: `/x"y`, SSHPort: 2222}); err == nil {
		t.Error("a refused profile must not be written")
	}
	if after, _ := os.ReadFile(path); string(after) != string(data) {
		t.Error("a refused profile must leave the previous one in place")
	}
}

func TestStartArgsWrapOnlyStart(t *testing.T) {
	got := StartArgs("/p/network.sb", "devkit-demo")
	want := []string{SandboxExec, "-f", "/p/network.sb", "limactl", "start", "--tty=false", "devkit-demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCheckRefusesWhereItCannotEnforce(t *testing.T) {
	oldOS, oldExec := goos, sandboxExec
	defer func() { goos, sandboxExec = oldOS, oldExec }()

	goos, sandboxExec = "linux", oldExec
	if err := Check(); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("not macOS: want a refusal naming macOS, got %v", err)
	}
	goos, sandboxExec = "darwin", filepath.Join(t.TempDir(), "sandbox-exec")
	if err := Check(); err == nil || !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("no sandbox-exec: want a refusal, got %v", err)
	}
	os.WriteFile(sandboxExec, []byte("#!/bin/sh\n"), 0o644)
	if err := Check(); err == nil {
		t.Error("a sandbox-exec that is not executable must be refused")
	}
	os.Chmod(sandboxExec, 0o755)
	if err := Check(); err != nil {
		t.Errorf("an executable sandbox-exec on macOS should pass: %v", err)
	}
}
