package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// upMerged runs devkit up with the command's output and os.Stdout in one
// stream, so the order of a warning and "Ready" can be checked.
func upMerged(t *testing.T) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetOut(os.Stdout)
		rootCmd.SetErr(os.Stdout)
		rootCmd.SetArgs([]string{"up", "--no-sync", "--no-install"})
		defer func() {
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
			rootCmd.SetArgs(nil)
			resetFlags(rootCmd)
		}()
		err = rootCmd.Execute()
	})
	return out, err
}

func TestUpWarnsAboutACrashDuringTheBoot(t *testing.T) {
	f, _ := crashProject(t, "Stopped", "")
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines+oopsLines)
	out, err := upMerged(t)
	if err != nil {
		t.Fatalf("an Oops is not a panic: up goes on with a warning, got %v\n%s", err, out)
	}
	warn := strings.Index(out, "Unable to handle kernel NULL pointer dereference")
	ready := strings.Index(out, "Ready.")
	if warn < 0 || ready < 0 || warn > ready {
		t.Errorf("up must warn about a crash in this boot before it says Ready:\n%s", out)
	}
	if !strings.Contains(out, "devkit audit --ack-crashes") || strings.Contains(out, "panicked") {
		t.Errorf("the usual warning, and no panic:\n%s", out)
	}
	if st := loadCrashState(demoVM); len(st.Crashes) != 1 {
		t.Errorf("the crash is kept until acknowledged: %+v", st.Crashes)
	}
	if verbCalled(f, "stop", demoVM) {
		t.Errorf("a provisioned VM that survived an Oops is not stopped: %q", f.Calls())
	}
}

func TestUpFailsOnAPanicDuringTheBoot(t *testing.T) {
	panicked := panicFixture(t) // read before the project changes directory
	f, _ := crashProject(t, "Stopped", "")
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines+panicked)
	out, err := upMerged(t)
	if err == nil || !strings.Contains(err.Error(), "panicked") || !strings.Contains(err.Error(), "devkit down") {
		t.Fatalf("up on a VM that panicked during its boot must fail and say so: %v\n%s", err, out)
	}
	if strings.Contains(out, "Ready") {
		t.Errorf("a panicked VM is not ready:\n%s", out)
	}
	if !strings.Contains(out, "will not respond") || strings.Count(out, "Kernel panic - not syncing") != 1 {
		t.Errorf("the warning should say the VM panicked and show the report, once:\n%s", out)
	}
	panickedBootChecks(t, f)
}

// panickedBootChecks checks what up leaves after a boot whose kernel
// panicked: the VM forced off, never asked to shut down, and the report kept.
func panickedBootChecks(t *testing.T, f *fakelima.Fake) {
	t.Helper()
	calls, _ := afterStart(t, f)
	if !hasCall(calls, "stop", "--force", demoVM) {
		t.Errorf("a panicked kernel cannot shut down: up must force the VM off: %q", calls)
	}
	if hasCall(calls, "stop", demoVM) {
		t.Errorf("a graceful stop of a panicked kernel only waits: %q", calls)
	}
	st := loadCrashState(demoVM)
	if len(st.Crashes) != 1 || !st.Crashes[0].Panic {
		t.Errorf("the crash state must hold the panic for audit and later commands: %+v", st.Crashes)
	}
}

// The stamp probe cannot answer from a panicked kernel: up must not wait
// for it, nor take the panic for a provisioning failure.
func TestUpDoesNotWaitOnTheStampOfAPanickedBoot(t *testing.T) {
	panicked := panicFixture(t)
	f := upProject(t, "Stopped")
	f.OnShellHang(stampMarker, 20*time.Second)
	writeLog(t, serialLog(demoVM), bootLines)
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines+panicked)
	began := time.Now()
	out, err := upMerged(t)
	if took := time.Since(began); took > 10*time.Second {
		t.Errorf("up waited %v on a guest that cannot answer", took)
	}
	if err == nil || !strings.Contains(err.Error(), "panicked") || strings.Contains(err.Error(), "provisioning") {
		t.Fatalf("want the panic error, not a provisioning failure: %v\n%s", err, out)
	}
	if strings.Contains(out, "Ready") || strings.Contains(out, "provisioning did not finish") {
		t.Errorf("a panicked VM is neither ready nor a provisioning failure:\n%s", out)
	}
	if !strings.Contains(out, "will not respond") || strings.Count(out, "Kernel panic - not syncing") != 1 {
		t.Errorf("the panic should be reported, once:\n%s", out)
	}
	if calls, _ := afterStart(t, f); mentions(calls, stampMarker) {
		t.Errorf("no stamp probe may be sent to a panicked guest: %q", calls)
	}
	panickedBootChecks(t, f)
}

// A kernel that panics while the stamp probe waits: the probe fails, and
// the log, read again, says why.
func TestUpReadsTheLogAgainWhenTheStampProbeFails(t *testing.T) {
	panicked := panicFixture(t)
	f := upProject(t, "Stopped")
	f.OnShellHang(stampMarker, 2*time.Second)
	writeLog(t, serialLog(demoVM), bootLines)
	f.TruncateSerialOnStart(demoVM)
	f.OnStartSerial(demoVM, bootLines)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			for _, c := range f.Calls() {
				if c[0] == "shell" && strings.Contains(c[len(c)-1], stampMarker) {
					fh, err := os.OpenFile(serialLog(demoVM), os.O_APPEND|os.O_WRONLY, 0)
					if err == nil {
						fh.WriteString(panicked)
						fh.Close()
					}
					return
				}
			}
		}
	}()
	out, err := upMerged(t)
	close(stop)
	<-done
	if err == nil || !strings.Contains(err.Error(), "panicked") || strings.Contains(err.Error(), "provisioning") {
		t.Fatalf("want the panic error, not a provisioning failure: %v\n%s", err, out)
	}
	if strings.Contains(out, "Ready") || strings.Contains(out, "provisioning did not finish") {
		t.Errorf("a panicked VM is neither ready nor a provisioning failure:\n%s", out)
	}
	if strings.Count(out, "Kernel panic - not syncing") != 1 {
		t.Errorf("the panic should be reported, once:\n%s", out)
	}
	panickedBootChecks(t, f)
}
