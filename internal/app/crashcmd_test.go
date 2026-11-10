package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/fakelima"
)

// Commands against a fake Lima whose serialv.log holds what the guest's
// kernel console printed.

const oopsLines = "[  300.000001] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008\n" +
	"[  300.000101] Internal error: Oops: 0000000096000004 [#1] SMP\n"

// crashProject is a project with a devkit.yaml, the VM in status, and its
// serial log holding log. It returns the config path.
func crashProject(t *testing.T, status, log string) (*fakelima.Fake, string) {
	t.Helper()
	f := upProject(t, status)
	provisioned(f, "current")
	writeLog(t, serialLog(demoVM), bootLines+log)
	cwd, _ := os.Getwd()
	return f, filepath.Join(cwd, "devkit.yaml")
}

func verbCalled(f *fakelima.Fake, verb, contains string) bool {
	for _, c := range f.Calls() {
		if c[0] == verb && strings.Contains(strings.Join(c, " "), contains) {
			return true
		}
	}
	return false
}

func TestShellWarnsAboutAnUnacknowledgedCrash(t *testing.T) {
	_, cfg := crashProject(t, "Running", oopsLines)
	out, err := runDevkit(t, "", "shell", "--config", cfg, "true")
	if err != nil {
		t.Fatalf("shell: %v\n%s", err, out)
	}
	for _, want := range []string{
		"a kernel crash report",
		"Unable to handle kernel NULL pointer dereference",
		"failed attempt to break out",
		"simply a bug",
		"devkit rm",
		"devkit audit --ack-crashes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("shell's warning should contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "panicked") {
		t.Errorf("an Oops without a panic is not a panicked VM:\n%s", out)
	}
}

func TestShellIsSilentWithoutCrashes(t *testing.T) {
	_, cfg := crashProject(t, "Running", "")
	out, err := runDevkit(t, "", "shell", "--config", cfg, "true")
	if err != nil {
		t.Fatalf("shell: %v\n%s", err, out)
	}
	if strings.Contains(out, "crash") {
		t.Errorf("no crash, no warning:\n%s", out)
	}
}

func TestShellOnAPanickedVM(t *testing.T) {
	f, cfg := crashProject(t, "Running", panicFixture(t))
	out, err := runDevkit(t, "", "shell", "--config", cfg, "true")
	if err == nil || !strings.Contains(err.Error(), "panicked") || !strings.Contains(err.Error(), "devkit down") {
		t.Fatalf("shell on a panicked VM must say so: %v\n%s", err, out)
	}
	if !strings.Contains(out, "will not respond") || !strings.Contains(out, "Kernel panic - not syncing") {
		t.Errorf("the warning should say the VM panicked and show the report:\n%s", out)
	}
	if verbCalled(f, "shell", "") {
		t.Errorf("nothing can reach a panicked guest; no shell may be tried: %q", f.Calls())
	}
}

func auditCode(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return -1
}

func TestAuditReportsCrashesAndAcknowledges(t *testing.T) {
	f, cfg := crashProject(t, "Running", oopsLines)
	f.OnShell("devkit-audit", "", 0)
	out, err := runDevkit(t, "", "audit", "--config", cfg)
	if auditCode(err) != 1 {
		t.Fatalf("an unacknowledged crash is a finding: exit 1, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "Kernel crash reports") || !strings.Contains(out, "Internal error: Oops") {
		t.Errorf("audit should report the crash in its own section:\n%s", out)
	}
	if !verbCalled(f, "shell", "devkit-audit") {
		t.Error("the trust audit still runs")
	}

	out, err = runDevkit(t, "", "audit", "--config", cfg, "--ack-crashes")
	if err != nil || !strings.Contains(out, "Acknowledged 1 kernel crash report") {
		t.Fatalf("--ack-crashes: %v\n%s", err, out)
	}
	out, err = runDevkit(t, "", "audit", "--config", cfg)
	if err != nil {
		t.Fatalf("after the acknowledgement the audit is clean, got %v\n%s", err, out)
	}
	if strings.Contains(out, "Internal error: Oops") {
		t.Errorf("an acknowledged crash is not shown again:\n%s", out)
	}
	out, _ = runDevkit(t, "", "shell", "--config", cfg, "true")
	if strings.Contains(out, "crash report") {
		t.Errorf("an acknowledged crash is not warned about:\n%s", out)
	}
}

func TestAuditWithoutCrashes(t *testing.T) {
	f, cfg := crashProject(t, "Running", "")
	f.OnShell("devkit-audit", "", 0)
	out, err := runDevkit(t, "", "audit", "--config", cfg)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Kernel crash reports: none") {
		t.Errorf("the section should say none were found:\n%s", out)
	}
}

func TestAuditDoesNotClaimCoverageBeforeTheConsoleIsConnected(t *testing.T) {
	f := upProject(t, "Running")
	provisioned(f, "current")
	writeLog(t, serialLog(demoVM), "devkit-progress: provisioning started\ndevkit-progress: done\n")
	f.OnShell("devkit-audit", "", 0)
	out, err := runDevkit(t, "", "audit")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "none") || !strings.Contains(out, "next restart") {
		t.Errorf("a boot without the kernel console cannot report crashes, and must say so:\n%s", out)
	}
}

func TestAuditOnAPanickedVM(t *testing.T) {
	f, cfg := crashProject(t, "Running", panicFixture(t))
	out, err := runDevkit(t, "", "audit", "--config", cfg)
	if auditCode(err) != 1 {
		t.Fatalf("a panicked VM is a finding: exit 1, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "has panicked") || !strings.Contains(out, "will not respond") || !strings.Contains(out, "devkit down") {
		t.Errorf("audit should say the kernel panicked and what to do:\n%s", out)
	}
	if verbCalled(f, "shell", "") {
		t.Errorf("nothing can reach a panicked guest: %q", f.Calls())
	}
}

func TestUpScansBeforeRestarting(t *testing.T) {
	f, _ := crashProject(t, "Stopped", oopsLines)
	// Lima starts the VM with a new serial log.
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines)
	var out string
	var err error
	stdout := captureStdout(t, func() { out, err = runDevkit(t, "", "up", "--no-sync", "--no-install") })
	if err != nil {
		t.Fatalf("up: %v\n%s%s", err, out, stdout)
	}
	if b, _ := os.ReadFile(serialLog(demoVM)); strings.Contains(string(b), "Oops") {
		t.Fatal("the fake should have truncated the log")
	}
	st := loadCrashState(demoVM)
	if len(st.Crashes) != 1 {
		t.Fatalf("the crash from before the restart must be kept: %+v", st.Crashes)
	}
	if !strings.Contains(out+stdout, "Internal error: Oops") {
		t.Errorf("up should warn about it:\n%s%s", out, stdout)
	}
	// And it is still reported afterwards.
	f.SetInstances(fakelima.Instance{Name: demoVM, Status: "Running"})
	out, _ = runDevkit(t, "", "shell", "true")
	if !strings.Contains(out, "Internal error: Oops") {
		t.Errorf("shell after up should still warn:\n%s", out)
	}
}

func TestUpRestartsAPanickedVM(t *testing.T) {
	f, _ := crashProject(t, "Running", panicFixture(t))
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines)
	var out string
	var err error
	stdout := captureStdout(t, func() { out, err = runDevkit(t, "", "up", "--no-sync", "--no-install") })
	if err != nil {
		t.Fatalf("up: %v\n%s%s", err, out, stdout)
	}
	if !hasCall(f.Calls(), "stop", "--force", demoVM) || !verbCalled(f, "start", demoVM) {
		t.Errorf("a panicked VM cannot shut down: up forces it off and starts it: %q", f.Calls())
	}
	st := loadCrashState(demoVM)
	if len(st.Crashes) != 1 || st.LastPanic {
		t.Errorf("after the restart the crash stays reported and the VM is not panicked: %+v", st)
	}
}

func TestDownScansAndForcesAPanickedVMOff(t *testing.T) {
	f, cfg := crashProject(t, "Running", panicFixture(t))
	out, err := runDevkit(t, "", "down", "--config", cfg)
	if err != nil {
		t.Fatalf("down: %v\n%s", err, out)
	}
	if !hasCall(f.Calls(), "stop", "--force", demoVM) {
		t.Errorf("a panicked kernel cannot shut down cleanly: down forces it off: %q", f.Calls())
	}
	if st := loadCrashState(demoVM); len(st.Crashes) != 1 {
		t.Errorf("down must record the crash before the next start truncates the log: %+v", st.Crashes)
	}
}

func TestDownStopsAHealthyVMGracefully(t *testing.T) {
	f, cfg := crashProject(t, "Running", oopsLines)
	if out, err := runDevkit(t, "", "down", "--config", cfg); err != nil {
		t.Fatalf("down: %v\n%s", err, out)
	}
	if !hasCall(f.Calls(), "stop", demoVM) {
		t.Errorf("a VM that has not panicked is stopped normally: %q", f.Calls())
	}
	if st := loadCrashState(demoVM); len(st.Crashes) != 1 {
		t.Errorf("down must record the crash: %+v", st.Crashes)
	}
}

func TestLsShowsAPanickedVM(t *testing.T) {
	f, _ := crashProject(t, "Running", panicFixture(t))
	f.SetInstances(fakelima.Instance{Name: demoVM, Status: "Running"}, fakelima.Instance{Name: "devkit-other", Status: "Running"})
	var err error
	out := captureStdout(t, func() { _, err = runDevkit(t, "", "ls") })
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, demoVM+" "):
			if !strings.Contains(l, "kernel panicked") {
				t.Errorf("ls should show the panic: %q", l)
			}
		case strings.HasPrefix(l, "devkit-other "):
			if strings.Contains(l, "kernel") {
				t.Errorf("only the panicked VM: %q", l)
			}
		}
	}
}
