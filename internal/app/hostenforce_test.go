package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/embedded"
	"github.com/jurajpiar/devkit/internal/fakelima"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
)

func hostConfig(t *testing.T, mod func(*project.Config)) *project.Config {
	t.Helper()
	c := project.Default()
	c.Name = "demo"
	c.Network.Enforce = project.EnforceHost
	c.Network.Allow = []string{"example.com"}
	if mod != nil {
		mod(c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHostAllowlist(t *testing.T) {
	c := hostConfig(t, func(c *project.Config) { c.Network.Allow = []string{"example.com", "archive.ubuntu.com"} })
	got := hostAllowlist(c)
	want := append([]string{"example.com", "archive.ubuntu.com"}, provision.RootHosts(c)...)
	seen := map[string]int{}
	for _, h := range got {
		seen[h]++
	}
	for _, h := range want {
		if seen[h] != 1 {
			t.Errorf("%s should appear once in %v", h, got)
		}
	}
	if len(seen) != len(got) {
		t.Errorf("duplicates in %v", got)
	}
	open := hostConfig(t, func(c *project.Config) { c.Network.Mode = project.NetworkOpen })
	if got := hostAllowlist(open); len(got) != 1 || got[0] != "*" {
		t.Errorf("open mode allows everything (web ports only): got %v", got)
	}
}

func TestHostProxyPortIsChosenOnceAndKept(t *testing.T) {
	fakeHome(t)
	a, err := hostProxyPort("devkit-demo")
	if err != nil || a < 1024 {
		t.Fatalf("port %d, %v", a, err)
	}
	b, _ := hostProxyPort("devkit-demo")
	if a != b {
		t.Errorf("the port must be stable per VM: %d then %d", a, b)
	}
	other, _ := hostProxyPort("devkit-other")
	if other == a {
		t.Error("another VM gets its own port")
	}
	fi, err := os.Stat(vmStateDir("devkit-demo"))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir must be private: %v %v", fi.Mode(), err)
	}
}

// The host proxy is a detached "devkit hostproxy" (here: this test binary,
// see TestMain) that outlives devkit up, is reused while healthy and its
// allowlist unchanged, restarted when the allowlist changes, and stopped by
// down and rm.
func TestHostProxyLifecycle(t *testing.T) {
	fakeHome(t)
	ctx := context.Background()
	c := hostConfig(t, nil)
	name := c.VMName()
	t.Cleanup(func() { stopHostProxy(name) })

	port, err := ensureHostProxy(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := runningHostProxy(name)
	if !ok || st.Port != port {
		t.Fatalf("host proxy should be up on %d: %+v %v", port, st, ok)
	}
	if p, _ := hostProxyPort(name); p != port {
		t.Errorf("the port in use must be the persisted one: %d vs %d", port, p)
	}
	// It enforces the allowlist and logs to the Mac.
	refused := connectStatus(t, port, "elsewhere.test:443")
	if !strings.HasPrefix(refused, "403") {
		t.Errorf("a host off the allowlist must be refused, got %q", refused)
	}
	if log, _ := os.ReadFile(filepath.Join(vmStateDir(name), hostProxyLog)); !strings.Contains(string(log), "BLOCKED CONNECT elsewhere.test:443") {
		t.Errorf("the host log must record the decision:\n%s", log)
	}

	if _, err := ensureHostProxy(ctx, c); err != nil {
		t.Fatal(err)
	}
	if again, _ := runningHostProxy(name); again.PID != st.PID {
		t.Errorf("a healthy proxy with the same allowlist must be reused: pid %d then %d", st.PID, again.PID)
	}

	c.Network.Allow = []string{"example.org"}
	if p, err := ensureHostProxy(ctx, c); err != nil || p != port {
		t.Fatalf("restart: port %d, %v", p, err)
	}
	changed, _ := runningHostProxy(name)
	if changed.PID == st.PID {
		t.Error("a changed allowlist must restart the proxy")
	}
	if processAlive(st.PID) {
		t.Error("the old proxy must be gone")
	}

	if err := stopHostProxy(name); err != nil {
		t.Fatal(err)
	}
	if _, ok := runningHostProxy(name); ok {
		t.Error("stop must leave no running proxy")
	}
	if processAlive(changed.PID) {
		t.Error("stop must end the process")
	}
	if p, _ := hostProxyPort(name); p != port {
		t.Error("stop keeps the port for the next start")
	}
}

// If the proxy cannot start, the VM must not start: there is no unproxied
// fallback in host mode.
func TestHostProxyFailsClosedWhenItsPortIsTaken(t *testing.T) {
	fakeHome(t)
	c := hostConfig(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	os.MkdirAll(vmStateDir(c.VMName()), 0o700)
	os.WriteFile(filepath.Join(vmStateDir(c.VMName()), hostProxyPortFile), []byte(strconv.Itoa(port)), 0o600)
	if _, err := ensureHostProxy(context.Background(), c); err == nil || !strings.Contains(err.Error(), "host proxy") {
		t.Errorf("a proxy that cannot listen must fail devkit up, got %v", err)
	}
	if _, ok := runningHostProxy(c.VMName()); ok {
		t.Error("nothing may be recorded as running")
	}
}

// fakeSandboxExec replaces sandbox-exec for app tests: it records its
// arguments, checks that the host proxy answers before the VM starts, writes
// the ha.pid Lima's host agent would, then runs the wrapped command (the
// fake limactl).
func fakeSandboxExec(t *testing.T) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	script := filepath.Join(dir, "sandbox-exec")
	body := `#!/bin/bash
echo "$*" >> "` + log + `"
profile="$2"
port="$(grep -o 'localhost:[0-9]*' "$profile" | tail -n 1 | cut -d: -f2)"
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "proxy-up $port" >> "` + log + `"; fi
name="${*: -1}"
mkdir -p "$LIMA_HOME/$name" && echo 4242 > "$LIMA_HOME/$name/ha.pid"
shift 2
exec "$@"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	oldCheck, oldArgs := hostEnforceCheck, sandboxStartArgs
	t.Cleanup(func() { hostEnforceCheck, sandboxStartArgs = oldCheck, oldArgs })
	hostEnforceCheck = func() error { return nil }
	sandboxStartArgs = func(profile, name string) []string {
		args := oldArgs(profile, name)
		args[0] = script
		return args
	}
	return log
}

// upFixture prepares a temporary HOME for a devkit up against the fake
// limactl: a cached proxy binary, an answer for the proxy service check, and
// devkit.yaml. It returns the config path.
func upFixture(t *testing.T, f *fakelima.Fake, home, yaml string) string {
	t.Helper()
	cache := filepath.Join(home, ".devkit", "cache", "egressproxy-linux-"+goruntime.GOARCH)
	os.MkdirAll(filepath.Dir(cache), 0o755)
	os.WriteFile(cache, []byte("fake proxy binary"), 0o755)
	f.OnShell("systemctl is-active", "active\n", 0)
	os.MkdirAll(lima.Home(), 0o755) // limactl create makes it
	path := filepath.Join(home, "devkit.yaml")
	os.WriteFile(path, []byte(yaml), 0o644)
	return path
}

const hostYAML = "name: demo\ntools:\n  manager: none\nnetwork:\n  mode: allowlist\n  enforce: host\n  allow: [example.com]\n"

func TestUpInHostModeStartsTheProxyThenTheVMUnderTheProfile(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAML)
	calls := fakeSandboxExec(t)
	t.Cleanup(func() { stopHostProxy("devkit-demo") })

	if out, err := runDevkit(t, "", "up", "--config", cfgPath, "--no-sync", "--no-install"); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	port, _ := hostProxyPort("devkit-demo")
	sandboxed, _ := os.ReadFile(calls)
	profile := filepath.Join(vmStateDir("devkit-demo"), "network.sb")
	wantStart := "-f " + profile + " limactl start --tty=false devkit-demo"
	if !strings.Contains(string(sandboxed), wantStart) {
		t.Errorf("start must run under the profile; sandbox-exec saw:\n%s", sandboxed)
	}
	if !strings.Contains(string(sandboxed), fmt.Sprintf("proxy-up %d", port)) {
		t.Errorf("the host proxy must answer before the VM starts:\n%s", sandboxed)
	}
	if strings.Count(string(sandboxed), "limactl") != 1 {
		t.Errorf("only start is sandboxed, create is not (it downloads the image):\n%s", sandboxed)
	}
	if !hasCall(f.Calls(), "create", "--tty=false", "--name", "devkit-demo", filepath.Join(home, ".devkit", "instances", "devkit-demo.yaml")) {
		t.Errorf("create must run directly: %q", f.Calls())
	}
	prof, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prof), fmt.Sprintf(`"localhost:%d"`, port)) || !strings.Contains(string(prof), `"localhost:2222"`) {
		t.Errorf("profile must allow the SSH forward and the host proxy:\n%s", prof)
	}
	if !strings.Contains(string(prof), regexpQuote(lima.Home())) {
		t.Errorf("profile must name Lima's home:\n%s", prof)
	}
	rendered, _ := os.ReadFile(filepath.Join(home, ".devkit", "instances", "devkit-demo.yaml"))
	if !strings.Contains(string(rendered), fmt.Sprintf("-upstream 192.168.5.2:%d", port)) {
		t.Error("the VM must be provisioned to use the host proxy")
	}
	if rec, _ := os.ReadFile(filepath.Join(vmStateDir("devkit-demo"), hostAgentPIDFile)); strings.TrimSpace(string(rec)) != "4242" {
		t.Errorf("the host agent's pid must be recorded after a sandboxed start, got %q", rec)
	}
	if _, ok := runningHostProxy("devkit-demo"); !ok {
		t.Error("the host proxy must outlive devkit up")
	}
}

func regexpQuote(s string) string {
	r := strings.NewReplacer(".", `\.`, "+", `\+`, "(", `\(`, ")", `\)`)
	return r.Replace(s)
}

func TestUpInHostModeRefusesWhereItCannotEnforce(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAML)
	fakeSandboxExec(t)
	hostEnforceCheck = func() error { return errors.New("network.enforce: host needs /usr/bin/sandbox-exec, which is missing") }
	_, err := runDevkit(t, "", "up", "--config", cfgPath, "--no-sync", "--no-install")
	if err == nil || !strings.Contains(err.Error(), "sandbox-exec") {
		t.Fatalf("up must refuse, got %v", err)
	}
	for _, v := range f.Verbs() {
		if v == "create" || v == "start" {
			t.Errorf("nothing may be created or started: %v", f.Verbs())
		}
	}
	if _, ok := runningHostProxy("devkit-demo"); ok {
		t.Error("no proxy may be started")
	}
}

func TestUpInHostModeDoesNotStartTheVMWithoutItsProxy(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAML)
	calls := fakeSandboxExec(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	os.MkdirAll(vmStateDir("devkit-demo"), 0o700)
	os.WriteFile(filepath.Join(vmStateDir("devkit-demo"), hostProxyPortFile), []byte(strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)), 0o600)
	if _, err := runDevkit(t, "", "up", "--config", cfgPath, "--no-sync", "--no-install"); err == nil {
		t.Fatal("up must fail when the host proxy cannot start")
	}
	if b, _ := os.ReadFile(calls); len(b) != 0 {
		t.Errorf("the VM must not start: %s", b)
	}
	if hasCall(f.Calls(), "start", "--tty=false", "devkit-demo") {
		t.Error("the VM must not start unsandboxed either")
	}
}

// A VM whose config is unchanged and already running is not restarted, so
// up must say when it is running without the profile.
func TestUpInHostModeWarnsAboutAVMStartedElsewhere(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := upFixture(t, f, home, hostYAML)
	fakeSandboxExec(t)
	t.Cleanup(func() { stopHostProxy("devkit-demo") })
	if out, err := runDevkit(t, "", "up", "--config", cfgPath, "--no-sync", "--no-install"); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	f.SetInstances(fakelima.Instance{Name: "devkit-demo", Status: "Running"})
	// Lima's lima.yaml is what create wrote; the fake does not, so copy it.
	rendered, _ := os.ReadFile(filepath.Join(home, ".devkit", "instances", "devkit-demo.yaml"))
	lima.WriteConfig("devkit-demo", string(rendered))
	os.WriteFile(filepath.Join(lima.Dir("devkit-demo"), "ha.pid"), []byte("999\n"), 0o644)
	var w bytes.Buffer
	warnIfUnconfinedTo(context.Background(), mustLoad(t, cfgPath), &w)
	if !strings.Contains(w.String(), "host enforcement is off") || !strings.Contains(w.String(), "devkit down") {
		t.Errorf("want a loud warning with the fix, got %q", w.String())
	}
}

func mustLoad(t *testing.T, path string) *project.Config {
	t.Helper()
	c, err := project.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWarnIfUnconfined(t *testing.T) {
	host := hostConfig(t, nil)
	guest := project.Default()
	guest.Name = "demo"
	cases := []struct {
		label        string
		cfg          *project.Config
		current, rec string // "" for no file
		warn         bool
	}{
		{"guest mode", guest, "100", "", false},
		{"started by devkit", host, "100", "100", false},
		{"started elsewhere", host, "200", "100", true},
		{"never recorded", host, "200", "", true},
		{"not running", host, "", "100", false},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			fakeHome(t)
			name := c.cfg.VMName()
			os.MkdirAll(lima.Dir(name), 0o755)
			os.MkdirAll(vmStateDir(name), 0o700)
			if c.current != "" {
				os.WriteFile(filepath.Join(lima.Dir(name), "ha.pid"), []byte(c.current), 0o644)
			}
			if c.rec != "" {
				os.WriteFile(filepath.Join(vmStateDir(name), hostAgentPIDFile), []byte(c.rec), 0o600)
			}
			var w bytes.Buffer
			warnIfUnconfinedTo(context.Background(), c.cfg, &w)
			if c.warn != (w.Len() > 0) {
				t.Errorf("warn = %v, got %q", c.warn, w.String())
			}
			if c.warn && (!strings.Contains(w.String(), "devkit down") || !strings.Contains(w.String(), "devkit up")) {
				t.Errorf("the warning must say how to fix it: %q", w.String())
			}
		})
	}
}

func TestDownAndRmStopTheHostProxy(t *testing.T) {
	for _, verb := range []string{"down", "rm"} {
		t.Run(verb, func(t *testing.T) {
			f, _ := fakeHome(t)
			c := hostConfig(t, nil)
			name := c.VMName()
			t.Cleanup(func() { stopHostProxy(name) })
			if _, err := ensureHostProxy(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			st, _ := runningHostProxy(name)
			f.SetInstances(fakelima.Instance{Name: name, Status: "Running"})
			args := []string{verb, "demo"}
			if verb == "rm" {
				args = []string{verb, "--force", "demo"}
			}
			if out, err := runDevkit(t, "", args...); err != nil {
				t.Fatalf("%s: %v\n%s", verb, err, out)
			}
			if _, ok := runningHostProxy(name); ok || processAlive(st.PID) {
				t.Errorf("%s must stop the host proxy", verb)
			}
			_, err := os.Stat(vmStateDir(name))
			if verb == "rm" && err == nil {
				t.Error("rm must remove the VM's host state")
			}
			if verb == "down" && err != nil {
				t.Error("down keeps the host state (the port stays the VM's)")
			}
		})
	}
}

func TestLogsInHostModeShowTheHostLog(t *testing.T) {
	f, home := fakeHome(t)
	cfgPath := filepath.Join(home, "devkit.yaml")
	os.WriteFile(cfgPath, []byte(hostYAML), 0o644)
	f.SetInstances(fakelima.Instance{Name: "devkit-demo", Status: "Running"})
	os.MkdirAll(vmStateDir("devkit-demo"), 0o700)
	os.WriteFile(filepath.Join(vmStateDir("devkit-demo"), hostProxyLog), []byte("one\n[EGRESS] BLOCKED CONNECT evil.test:443\n"), 0o600)
	out, err := runDevkit(t, "", "logs", "--config", cfgPath, "-n", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "BLOCKED CONNECT evil.test:443") || strings.Contains(out, "one\n") {
		t.Errorf("logs should show the last line of the host log, got %q", out)
	}
	if mentions(f.Calls(), provision.EgressLog) {
		t.Error("in host mode the host log is the authoritative one")
	}
}

// connectStatus asks the proxy on port for a tunnel and returns the status.
func connectStatus(t *testing.T, port int, target string) string {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	return strings.TrimPrefix(strings.SplitN(string(buf[:n]), "\r\n", 2)[0], "HTTP/1.1 ")
}

// The stale-VM check must expect the host-mode fingerprint, or every
// host-enforced VM would be reported stale.
func TestExpectedProvisionIDInHostMode(t *testing.T) {
	_, home := fakeHome(t)
	cache := filepath.Join(home, ".devkit", "cache", "egressproxy-linux-"+goruntime.GOARCH)
	os.MkdirAll(filepath.Dir(cache), 0o755)
	os.WriteFile(cache, []byte("fake proxy binary"), 0o755)
	c := hostConfig(t, nil)
	if got := expectedProvisionID(context.Background(), c); got != "" {
		t.Errorf("before any host-mode up there is nothing to expect, got %q", got)
	}
	port, _ := hostProxyPort(c.VMName())
	want, err := provision.Fingerprint(provision.Params{
		Config: c, User: hostUser(), EgressSHA256: embedded.SHA256([]byte("fake proxy binary")),
		HostProxy: fmt.Sprintf("192.168.5.2:%d", port),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := expectedProvisionID(context.Background(), c); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
