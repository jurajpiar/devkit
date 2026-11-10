package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
	"github.com/jurajpiar/devkit/internal/lima"
)

// The provision stamp is written by the system script only when every step
// succeeded. These tests check that devkit treats a running VM without one
// as unprotected: up stops it and fails, shell and sync refuse it.

const demoVM = "devkit-demo"

// provisioned makes the fake VM report a provision stamp.
func provisioned(f *fakelima.Fake, id string) {
	f.OnShell(stampMarker, stampMarker+"="+id+"\n", 0)
}

// unprovisioned makes the fake VM report that it has no stamp.
func unprovisioned(f *fakelima.Fake) {
	f.OnShell(stampMarker, stampMarker+"-missing\n", 0)
}

// upProject is a project directory with a devkit.yaml in open mode (so up
// needs no proxy binary), the current directory for the rest of the test.
func upProject(t *testing.T, status string) *fakelima.Fake {
	t.Helper()
	f, _ := fakeHome(t)
	t.Setenv("DEVKIT_SRC", "")
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "devkit.yaml"), []byte("name: demo\nnetwork:\n  mode: open\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "main.txt"), []byte("code\n"), 0o644))
	inDir(t, dir)
	must(t, os.MkdirAll(lima.Dir(demoVM), 0o755))
	if status != "" {
		f.SetInstances(fakelima.Instance{Name: demoVM, Status: status})
	}
	// After a build the proxy binary is embedded and up installs it, then
	// waits for its service; without a build there is none and this answer
	// goes unused. The tests must pass either way.
	f.OnShell("systemctl is-active", "active\n", 0)
	return f
}

// captureStdout runs fn and returns what it printed, since devkit up prints
// to os.Stdout rather than cobra's writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	must(t, err)
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// afterStart returns the calls made after the last "limactl start".
func afterStart(t *testing.T, f *fakelima.Fake) ([][]string, [][]byte) {
	t.Helper()
	calls, inputs := f.Calls(), f.Inputs()
	last := -1
	for i, c := range calls {
		if c[0] == "start" {
			last = i
		}
	}
	if last < 0 {
		t.Fatalf("no start: %q", calls)
	}
	return calls[last+1:], inputs[last+1:]
}

// nothingSentAfterStart fails if anything but the stamp check, a status
// query or a stop reached the VM after it was started.
func nothingSentAfterStart(t *testing.T, f *fakelima.Fake) {
	t.Helper()
	calls, inputs := afterStart(t, f)
	for i, c := range calls {
		if inputs[i] != nil {
			t.Errorf("a tar stream reached the VM after a failed provisioning: %q", c)
		}
		switch c[0] {
		case "list", "stop":
			continue
		case "shell":
			if strings.Contains(c[len(c)-1], stampMarker) {
				continue
			}
		}
		t.Errorf("nothing may run in the VM after a failed provisioning, got %q", c)
	}
}

func stoppedAfterStart(t *testing.T, f *fakelima.Fake) bool {
	t.Helper()
	calls, _ := afterStart(t, f)
	return hasCall(calls, "stop", demoVM)
}

func TestUpStopsAVMWhoseProvisioningDidNotFinish(t *testing.T) {
	f := upProject(t, "Stopped")
	unprovisioned(f)
	// An earlier boot's failure must not be reported as this boot's.
	must(t, os.WriteFile(filepath.Join(lima.Dir(demoVM), "serialv.log"),
		[]byte("devkit-progress: provisioning started\ndevkit-progress: failed: an old failure (line 1, exit 1)\n"), 0o644))
	f.OnStartSerial(demoVM, "[  1.0] kernel noise\n"+
		"devkit-progress: provisioning started\n"+
		"devkit-progress: checking base packages (installed on first boot)\n"+
		"devkit-progress: warning: something soft\n"+
		"devkit-progress: checking extra packages\n"+
		"devkit-progress: failed: $APT install -y --no-install-recommends $WANT_PKGS\x1b[2J (line 355, exit 100)\n")
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "up") })
	if err == nil {
		t.Fatalf("up must fail when provisioning did not finish:\n%s", out)
	}
	msg := err.Error()
	t.Logf("error:\n%s", msg)
	for _, want := range []string{"provisioning", "checking extra packages", "$APT install -y --no-install-recommends $WANT_PKGS", "line 355, exit 100", "stopped", "devkit up"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error should mention %q:\n%s", want, msg)
		}
	}
	for _, bad := range []string{"\x1b", "an old failure", "something soft"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the error must not contain %q:\n%s", bad, msg)
		}
	}
	if strings.Contains(out, "Ready") {
		t.Errorf("up must not print Ready:\n%s", out)
	}
	if !stoppedAfterStart(t, f) {
		t.Errorf("the VM must be stopped: %q", f.Calls())
	}
	nothingSentAfterStart(t, f)
}

func TestUpStopsAVMWhoseStartFailedWithoutAStamp(t *testing.T) {
	f := upProject(t, "Running")
	must(t, lima.WriteConfig(demoVM, "an older config"))
	unprovisioned(f)
	f.Fail("start", 1)
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "up") })
	if err == nil || !strings.Contains(err.Error(), "provisioning") || !strings.Contains(err.Error(), "limactl start") {
		t.Fatalf("up should fail, naming provisioning and the start error, got %v\n%s", err, out)
	}
	if strings.Contains(out, "Ready") {
		t.Errorf("up must not print Ready:\n%s", out)
	}
	if !stoppedAfterStart(t, f) {
		t.Errorf("a VM left running by a failed start must be stopped: %q", f.Calls())
	}
	nothingSentAfterStart(t, f)
}

// A start that fails and leaves the VM stopped exposes nothing: the start
// error is the answer, and there is nothing to check or stop.
func TestUpStartErrorOnAStoppedVM(t *testing.T) {
	f := upProject(t, "Stopped")
	unprovisioned(f)
	f.Fail("start", 1)
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "up") })
	if err == nil || !strings.Contains(err.Error(), "limactl start") {
		t.Fatalf("want the start error, got %v", err)
	}
	if strings.Contains(out, "Ready") {
		t.Errorf("up must not print Ready:\n%s", out)
	}
	calls, _ := afterStart(t, f)
	for _, c := range calls {
		if c[0] != "list" {
			t.Errorf("only the status may be read after a failed start of a stopped VM: %q", c)
		}
	}
}

func TestUpSaysSoWhenStoppingFails(t *testing.T) {
	f := upProject(t, "Stopped")
	unprovisioned(f)
	f.Fail("stop", 1)
	var err error
	captureStdout(t, func() { _, err = runDevkit(t, "", "up") })
	if err == nil || !strings.Contains(err.Error(), "could not be stopped") || !strings.Contains(err.Error(), "devkit down") {
		t.Fatalf("up should say the VM is still running and how to stop it, got %v", err)
	}
}

func TestUpWithAStampProceeds(t *testing.T) {
	f := upProject(t, "Stopped")
	provisioned(f, "some-id")
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "up") })
	if err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Ready") {
		t.Errorf("up should finish with Ready:\n%s", out)
	}
	calls, inputs := afterStart(t, f)
	if hasCall(calls, "stop", demoVM) {
		t.Errorf("a provisioned VM must not be stopped: %q", calls)
	}
	sent := false
	for _, in := range inputs {
		sent = sent || in != nil
	}
	if !sent {
		t.Error("the source should be copied in")
	}
}

// A VM that is already running with the current config is not restarted,
// but one without a stamp is no safer for that.
func TestReconcileStopsARunningVMWithoutAStamp(t *testing.T) {
	f, _ := fakeHome(t)
	must(t, os.MkdirAll(lima.Dir(demoVM), 0o755))
	must(t, lima.WriteConfig(demoVM, "rendered"))
	unprovisioned(f)
	err := reconcileVM(context.Background(), demoVM, "rendered", &lima.Instance{Name: demoVM, Status: "Running"})
	if err == nil || !strings.Contains(err.Error(), "provisioning") {
		t.Fatalf("want a provisioning error, got %v", err)
	}
	if !hasCall(f.Calls(), "stop", demoVM) {
		t.Errorf("the VM must be stopped: %q", f.Calls())
	}
}

func TestShellAndSyncRefuseAVMWithoutAStamp(t *testing.T) {
	for _, args := range [][]string{{"shell", "true"}, {"sync"}} {
		t.Run(args[0], func(t *testing.T) {
			f := upProject(t, "Running")
			unprovisioned(f)
			_, err := runDevkit(t, "", args...)
			if err == nil || !strings.Contains(err.Error(), "provisioning") || !strings.Contains(err.Error(), "devkit up") {
				t.Fatalf("%s should refuse and point at devkit up, got %v", args[0], err)
			}
			for i, c := range f.Calls() {
				if c[0] == "shell" && !strings.Contains(c[len(c)-1], stampMarker) || f.Inputs()[i] != nil || c[0] == "copy" {
					t.Errorf("nothing may run in the VM: %q", c)
				}
			}
		})
	}
}

func TestShellAndSyncWorkWithAStaleStamp(t *testing.T) {
	old := provisionIDFor
	defer func() { provisionIDFor = old }()
	for _, args := range [][]string{{"shell", "true"}, {"sync"}} {
		t.Run(args[0], func(t *testing.T) {
			f := upProject(t, "Running")
			provisioned(f, "old11111111")
			if out, err := runDevkit(t, "", args...); err != nil {
				t.Fatalf("%s on a provisioned VM: %v\n%s", args[0], err, out)
			}
			ran := false
			for i, c := range f.Calls() {
				last := c[len(c)-1]
				ran = ran || (c[0] == "shell" && strings.HasSuffix(last, "; true")) || f.Inputs()[i] != nil
			}
			if !ran {
				t.Errorf("%s should have reached the VM: %q", args[0], f.Calls())
			}
		})
	}
}

func TestProvisioningReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	old := "devkit-progress: provisioning started\ndevkit-progress: failed: old (line 1, exit 1)\n"
	now := "devkit-progress: provisioning started\ndevkit-progress: applying the firewall\ndevkit-progress: note: n\n"
	must(t, os.WriteFile(path, []byte(old+now), 0o644))
	step, failed := provisioningReport(path, int64(len(old)))
	if step != "applying the firewall" || failed != "" {
		t.Errorf("got step %q, failed %q", step, failed)
	}
	// Without an offset, the latest boot's lines.
	step, failed = provisioningReport(path, 0)
	if step != "applying the firewall" || failed != "" {
		t.Errorf("from 0: got step %q, failed %q", step, failed)
	}
	// A log that shrank was started afresh: read it from the beginning.
	step, _ = provisioningReport(path, 1<<20)
	if step != "applying the firewall" {
		t.Errorf("a truncated log: got step %q", step)
	}
	if step, failed := provisioningReport(filepath.Join(t.TempDir(), "none"), 0); step != "" || failed != "" {
		t.Errorf("a missing log reports nothing, got %q %q", step, failed)
	}
}
