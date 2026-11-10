//go:build darwin

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKernelCrashIsReported checks kernel crash detection on a real VM: the
// guest kernel's console reaches the Mac from the second boot, a real
// kernel panic is found in the serial log there, a panicked VM that Lima
// still calls Running is named as such, the report survives a restart, and
// acknowledging it clears it.
func TestKernelCrashIsReported(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2ecrash-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	setYAML(t, filepath.Join(dir, "devkit.yaml"), "# sudo: false", "sudo: true")

	// First boot: the drop-in is written, but this kernel has no console
	// on hvc0, and devkit must say so rather than claim coverage.
	upOut := s.mustRun("up", "--no-install")
	if !strings.Contains(upOut, "crash reporting to the Mac starts after the VM's next restart") {
		t.Fatalf("the first up should say crash reporting starts after the next restart:\n%s", upOut)
	}
	if out, _ := s.run("audit"); !strings.Contains(out, "Kernel crash reports: not available on this boot") {
		t.Errorf("before the restart the audit must not claim to see crashes:\n%s", out)
	}

	// Second boot: the console is connected.
	s.mustRun("down")
	upOut = s.mustRun("up", "--no-install")
	if strings.Contains(upOut, "next restart") {
		t.Errorf("after the restart the console should be connected:\n%s", upOut)
	}
	out := s.mustRun("shell", "true")
	if strings.Contains(out, "crash") || strings.Contains(out, "panicked") {
		t.Fatalf("a healthy VM gets no crash warning:\n%s", out)
	}
	if out, _ := s.run("audit"); !strings.Contains(out, "Kernel crash reports: none") {
		t.Errorf("with the console connected the audit should find none:\n%s", out)
	}

	// Crash the kernel as root. The session dies with it, so the command
	// runs in the background under a timeout and its error is expected.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	crash := exec.CommandContext(ctx, devkit, "shell", "sudo sh -c 'echo c > /proc/sysrq-trigger'")
	crash.Dir = dir
	crash.WaitDelay = 5 * time.Second
	if err := crash.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- crash.Wait() }()
	t.Cleanup(func() { cancel(); <-done })

	// devkit ls reads the serial log on the Mac; Lima still says Running.
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, _ = s.run("ls")
		if strings.Contains(out, "kernel panicked") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("devkit ls never showed the panic:\n%s", out)
		}
		time.Sleep(3 * time.Second)
	}
	out, err := s.run("audit")
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Errorf("audit on a panicked VM should exit 1, got %v", err)
	}
	for _, want := range []string{"has panicked", "will not respond", "Kernel panic - not syncing: sysrq triggered crash", "devkit down"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit should report %q:\n%s", want, out)
		}
	}

	// devkit down forces the dead VM off; up brings it back, and the
	// crash is still reported until it is acknowledged.
	s.mustRun("down")
	upOut = s.mustRun("up", "--no-install")
	if !strings.Contains(upOut, "Kernel panic - not syncing") {
		t.Errorf("up should still report the unacknowledged crash:\n%s", upOut)
	}
	out = s.mustRun("shell", "true")
	if !strings.Contains(out, "kernel crash report") || strings.Contains(out, "has panicked") {
		t.Errorf("after the restart: the crash is reported, the VM is not panicked:\n%s", out)
	}
	if out, _ = s.run("ls"); strings.Contains(out, "kernel panicked") || !strings.Contains(out, "kernel crash reported") {
		t.Errorf("ls after the restart:\n%s", out)
	}

	out = s.mustRun("audit", "--ack-crashes")
	if !strings.Contains(out, "Acknowledged 1 kernel crash report") {
		t.Errorf("--ack-crashes:\n%s", out)
	}
	out = s.mustRun("shell", "true")
	if strings.Contains(out, "crash report") {
		t.Errorf("an acknowledged crash is not warned about:\n%s", out)
	}
	if out, _ = s.run("audit"); strings.Contains(out, "Kernel panic - not syncing") {
		t.Errorf("an acknowledged crash is not in the audit:\n%s", out)
	}
}
