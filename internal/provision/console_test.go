package provision

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const consoleSection = "# ---- kernel console on hvc0: crash reports reach the Mac ----"

// The kernel's console goes to hvc0, which Lima records on the Mac, through
// a grub drop-in: every configuration gets it.
func TestSystemScriptConnectsTheKernelConsole(t *testing.T) {
	for name, p := range guestVariants() {
		s, err := System(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			consoleSection,
			"CONSOLE_DROPIN=/etc/default/grub.d/99-devkit-console.cfg",
			`CONSOLE_WANT='GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT console=hvc0"'`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: system script missing %q", name, want)
			}
		}
		if b := consoleBlock(s); b == "" || strings.Contains(b, "reboot") || strings.Contains(b, "shutdown") {
			t.Errorf("%s: the console change must wait for the next boot, never reboot", name)
		}
	}
}

// consoleBlock is the console section of a rendered system script, up to
// the next section, or "".
func consoleBlock(s string) string {
	sec := strings.Index(s, consoleSection)
	if sec < 0 {
		return ""
	}
	rest := strings.Index(s[sec+len(consoleSection):], "\n# ---- ")
	if rest < 0 {
		return ""
	}
	return s[sec : sec+len(consoleSection)+rest]
}

// runConsoleSection runs the script's own console block with bash, its
// paths moved into dir, the progress helpers writing to dir/hvc0, and
// update-grub replaced by a stub that records its calls and exits with
// grubExit (or is missing when grubExit < 0). The running kernel's command
// line is cmdline.
func runConsoleSection(t *testing.T, dir, cmdline string, grubExit int) (console string, grubCalls int) {
	t.Helper()
	s, _ := System(params(nil))
	start := strings.Index(s, "step() {")
	end := strings.Index(s, "trap 'on_error")
	block := consoleBlock(s)
	if start < 0 || end < 0 || block == "" {
		t.Fatal("helpers, trap or console section not found")
	}
	end += strings.Index(s[end:], "\n") + 1

	consolePath := filepath.Join(dir, "hvc0")
	os.Remove(consolePath) // this boot's lines only
	grubDir := filepath.Join(dir, "grub.d")
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte(cmdline+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(bin, "update-grub"))
	if grubExit >= 0 {
		stub := fmt.Sprintf("#!/bin/sh\necho call >> %q\necho 'grub: something went wrong' >&2\nexit %d\n", filepath.Join(dir, "grub-calls"), grubExit)
		if err := os.WriteFile(filepath.Join(bin, "update-grub"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Appended: each step opens the console afresh, which would truncate a file.
	helpers := strings.ReplaceAll(s[start:end], "> /dev/hvc0", ">> "+consolePath)
	block = strings.ReplaceAll(block, "/etc/default/grub.d", grubDir)
	block = strings.ReplaceAll(block, "/proc/cmdline", cmdlinePath)
	script := "set -euo pipefail\n" + helpers + "\n" + block + "\necho reached-the-end\n"
	cmd := exec.Command("bash", "-c", script)
	// update-grub lives in /usr/sbin on Ubuntu: leave that off PATH so only
	// the stub can be found.
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the console block must never fail provisioning: %v\n%s", err, b)
	}
	if !strings.Contains(string(b), "reached-the-end") {
		t.Fatalf("the console block must not stop the script:\n%s", b)
	}
	c, _ := os.ReadFile(consolePath)
	calls, _ := os.ReadFile(filepath.Join(dir, "grub-calls"))
	return string(c), strings.Count(string(calls), "call")
}

func TestConsoleDropInIsWrittenAndUpdateGrubRunsOnlyOnChange(t *testing.T) {
	dir := t.TempDir()
	const before = "BOOT_IMAGE=/vmlinuz root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyAMA0"
	console, calls := runConsoleSection(t, dir, before, 0)
	if calls != 1 {
		t.Errorf("update-grub should run once when the drop-in is new, ran %d times", calls)
	}
	got, err := os.ReadFile(filepath.Join(dir, "grub.d", "99-devkit-console.cfg"))
	if err != nil || string(got) != `GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT console=hvc0"`+"\n" {
		t.Errorf("drop-in = %q, %v", got, err)
	}
	if !strings.Contains(console, "devkit-progress: note: ") || !strings.Contains(console, "next restart") {
		t.Errorf("without console=hvc0 on the running kernel, a note must say reporting starts after the next restart; console got %q", console)
	}

	// The next boot, same content: no update-grub. The kernel now has it.
	console, calls = runConsoleSection(t, dir, before+" console=hvc0", 0)
	if calls != 1 {
		t.Errorf("update-grub must not run again for an unchanged drop-in (total calls %d)", calls)
	}
	if strings.Contains(console, "next restart") {
		t.Errorf("once the kernel has the console, no note: %q", console)
	}

	// Edited by someone: rewritten, and update-grub runs again.
	os.WriteFile(filepath.Join(dir, "grub.d", "99-devkit-console.cfg"), []byte("GRUB_CMDLINE_LINUX_DEFAULT=quiet\n"), 0o644)
	_, calls = runConsoleSection(t, dir, before+" console=hvc0", 0)
	if calls != 2 {
		t.Errorf("a changed drop-in must be rewritten and update-grub run (total calls %d)", calls)
	}
}

func TestConsoleUpdateGrubFailureOnlyWarns(t *testing.T) {
	dir := t.TempDir()
	console, calls := runConsoleSection(t, dir, "console=ttyAMA0", 1)
	if calls != 1 {
		t.Errorf("update-grub calls = %d", calls)
	}
	if !strings.Contains(console, "devkit-progress: warning: ") || !strings.Contains(console, "update-grub failed") {
		t.Errorf("a failing update-grub must be warned about on the console: %q", console)
	}
	if strings.Contains(console, "devkit-progress: failed:") {
		t.Errorf("a failing update-grub must not be reported as a provisioning failure: %q", console)
	}
	// Removed, so that the next boot tries again.
	if _, err := os.Stat(filepath.Join(dir, "grub.d", "99-devkit-console.cfg")); err == nil {
		t.Error("after a failed update-grub the drop-in must be removed so the next boot retries")
	}
	_, calls = runConsoleSection(t, dir, "console=ttyAMA0", 1)
	if calls != 2 {
		t.Errorf("the next boot must retry update-grub (total calls %d)", calls)
	}
}

func TestConsoleMissingUpdateGrubOnlyWarns(t *testing.T) {
	dir := t.TempDir()
	console, _ := runConsoleSection(t, dir, "console=ttyAMA0", -1)
	if !strings.Contains(console, "devkit-progress: warning: ") || !strings.Contains(console, "update-grub") {
		t.Errorf("a missing update-grub must be warned about: %q", console)
	}
	if strings.Contains(console, "failed:") {
		t.Errorf("not a provisioning failure: %q", console)
	}
	if _, err := os.Stat(filepath.Join(dir, "grub.d", "99-devkit-console.cfg")); err == nil {
		t.Error("without update-grub the drop-in would do nothing; it should not be written")
	}
}
