package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testdata/serial-panic.txt is the real kernel panic from the detection
// spike (spikes/detect/results/04-...), as the Mac read it from the VM's
// serialv.log: "echo c > /proc/sysrq-trigger" on Ubuntu 24.04 arm64 under
// vz, with console=hvc0.
func panicFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "serial-panic.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// bootLines is what else a serial log holds once the console is connected:
// kernel boot lines, systemd's status lines with their colours, devkit's
// progress lines and getty's prompt.
const bootLines = "\x1b[2J\x1b[01;01HBdsDxe: loading Boot0001 \"UEFI Misc Device\"\r\n" +
	"[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x610f0000]\r\n" +
	"[    0.000000] Linux version 6.8.0-147-generic (buildd@bos03-arm64-012) #147-Ubuntu SMP PREEMPT_DYNAMIC\r\n" +
	"[    0.000000] KASLR enabled\r\n" +
	"[    0.412345] audit: initializing netlink subsys (disabled)\r\n" +
	"[    1.203311] EXT4-fs (vda1): mounted filesystem with ordered data mode.\r\n" +
	"[\x1b[0;32m  OK  \x1b[0m] Started \x1b[0;1;39msystemd-journald.service\x1b[0m - Journal Service.\r\n" +
	"[\x1b[0;32m  OK  \x1b[0m] Reached target \x1b[0;1;39mnetwork-online.target\x1b[0m - Network is Online.\r\n" +
	"[\x1b[0;1;31mFAILED\x1b[0m] Failed to start \x1b[0;1;39mBUG: unit.service\x1b[0m.\r\n" +
	"devkit-progress: provisioning started\n" +
	"devkit-progress: checking base packages (installed on first boot)\n" +
	"devkit-progress: note: kernel crash reporting to the Mac starts after the VM's next restart (devkit down, then devkit up)\n" +
	"devkit-progress: done\n" +
	"\r\nUbuntu 24.04.3 LTS devkit-demo hvc0\r\n\r\ndevkit-demo login: \r\n"

func writeLog(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendLog(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, st *crashState, path string) {
	t.Helper()
	if err := scanCrashLog(st, path); err != nil {
		t.Fatal(err)
	}
}

func TestCrashScanFindsTheRealPanicOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+panicFixture(t))
	st := &crashState{}
	scan(t, st, path)
	if len(st.Crashes) != 1 {
		t.Fatalf("want one crash report, got %d: %+v", len(st.Crashes), st.Crashes)
	}
	c := st.Crashes[0]
	if !strings.HasPrefix(c.Lines[0], "[   65.337711] Kernel panic - not syncing: sysrq triggered crash") {
		t.Errorf("first line = %q", c.Lines[0])
	}
	if !c.Panic || !st.LastPanic {
		t.Error("a kernel panic must be recorded as one")
	}
	if !st.ConsoleSeen {
		t.Error("kernel lines in the log mean the console is connected")
	}
	if len(c.Lines) < 5 || len(c.Lines) > crashReportLines {
		t.Errorf("the report should keep its following lines, bounded: %d lines", len(c.Lines))
	}
	// With the console's CRLF line endings, the same.
	st = &crashState{}
	writeLog(t, path, strings.ReplaceAll(bootLines+panicFixture(t), "\n", "\r\n"))
	scan(t, st, path)
	if len(st.Crashes) != 1 || strings.Contains(st.Crashes[0].Lines[0], "\r") {
		t.Errorf("CRLF: %+v", st.Crashes)
	}
}

func TestCrashScanIgnoresBootLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines)
	st := &crashState{}
	scan(t, st, path)
	if len(st.Crashes) != 0 || st.LastPanic {
		t.Errorf("boot, systemd and devkit lines are not crashes: %+v", st.Crashes)
	}
	if !st.ConsoleSeen {
		t.Error("the boot lines show the console is connected")
	}
}

func TestCrashScanSaysWhenTheConsoleIsNotConnected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	// A first boot: only devkit's own lines and getty reach the log.
	writeLog(t, path, "devkit-progress: provisioning started\ndevkit-progress: done\n\r\ndevkit-demo login: ")
	st := &crashState{}
	scan(t, st, path)
	if st.ConsoleSeen {
		t.Error("without kernel lines the console is not connected on this boot")
	}
	if w := crashWarning("devkit-demo", st, true); w != "" {
		t.Errorf("nothing to warn about: %q", w)
	}
}

// Text the sandbox user can influence appears in kernel lines, but never at
// the start of the message; devkit's and systemd's lines are not kernel
// lines at all.
func TestCrashScanIsNotFooledByForgeries(t *testing.T) {
	for _, l := range []string{
		"[  120.123456] audit: type=1400 comm=\"BUG: unable to\" exe=\"/tmp/BUG: unable to\"",
		"[  120.123456] python3[2211]: segfault BUG: unable to handle kernel NULL pointer",
		"devkit-progress: Kernel panic - not syncing: forged",
		"devkit-progress: [  120.123456] Kernel panic - not syncing: forged",
		"devkit-progress: warning: Oops: something",
		"something else [  120.123456] Kernel panic - not syncing: forged",
		" [  120.123456] Kernel panic - not syncing: indented",
		"[  120.123456]  Kernel panic - not syncing: two spaces",
		"[  120.12] Kernel panic - not syncing: short micros",
		"[  120.123456]Kernel panic - not syncing: no space",
		"[  120.123456] Out of memory: Killed process 3101 (Oops:) total-vm:10264kB, anon-rss:2048kB",
		"[  120.123456] oom-kill:constraint=CONSTRAINT_NONE,task=Oops:,pid=3101,uid=1000",
		"[\x1b[0;32m  OK  \x1b[0m] Started Kernel panic.service.",
		"[  OK  ] Started BUG: forged.service.",
		"devkit-demo login: Oops: forged",
		"devkit-demo login: devkit-progress: [  120.123456] BUG: forged",
		"Ubuntu 24.04.3 LTS devkit-demo hvc0 Kernel panic",
	} {
		path := filepath.Join(t.TempDir(), "serialv.log")
		writeLog(t, path, bootLines+l+"\r\n")
		st := &crashState{}
		scan(t, st, path)
		if len(st.Crashes) != 0 || st.LastPanic {
			t.Errorf("%q must not be taken for a crash: %+v", l, st.Crashes)
		}
	}
}

func TestCrashScanSignatures(t *testing.T) {
	for _, sig := range crashSignatures {
		path := filepath.Join(t.TempDir(), "serialv.log")
		writeLog(t, path, bootLines+"[  120.123456] "+sig+" something\n")
		st := &crashState{}
		scan(t, st, path)
		if len(st.Crashes) != 1 {
			t.Errorf("%q should be a crash report", sig)
		}
	}
}

func TestCrashScanStripsTerminalNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+"\r\x1b[0m\x1b]0;title\x07[   65.337711] Kernel panic - not syncing: x\x1b[31m\x1b[2J\xc2\x9b2J\r\n")
	st := &crashState{}
	scan(t, st, path)
	if len(st.Crashes) != 1 {
		t.Fatalf("a crash line inside terminal noise must still match: %+v", st.Crashes)
	}
	w := crashWarning("devkit-demo", st, false)
	for _, bad := range []string{"\x1b", "\r", "[31m", "[2J", "\u009b", "title"} {
		if strings.Contains(w, bad) {
			t.Errorf("warning contains %q: %q", bad, w)
		}
	}
	if !strings.Contains(w, "[   65.337711] Kernel panic - not syncing: x") {
		t.Errorf("warning should show the line: %q", w)
	}
}

func TestCrashScanBoundsLinesAndMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	// A 20 MB line, then 5 MB of boot lines, then the panic.
	huge := "[  100.000000] " + strings.Repeat("A", 20<<20) + "\n"
	var many strings.Builder
	for many.Len() < 5<<20 {
		many.WriteString("[    1.000000] usb 1-1: new high-speed USB device number 2 using xhci_hcd\r\n")
	}
	writeLog(t, path, bootLines+huge+"[  101.000000] Oops: "+strings.Repeat("B", 1<<20)+"\n"+many.String()+panicFixture(t))
	st := &crashState{}
	start := time.Now()
	scan(t, st, path)
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("scan took %v", d)
	}
	if len(st.Crashes) != 2 {
		t.Fatalf("want the long Oops and the panic, got %d", len(st.Crashes))
	}
	for _, c := range st.Crashes {
		for _, l := range c.Lines {
			if len(l) > crashKeepLine {
				t.Errorf("a kept line is %d bytes", len(l))
			}
		}
	}
	if w := crashWarning("devkit-demo", st, false); len(w) > 4000 {
		t.Errorf("the warning must be bounded, got %d bytes", len(w))
	}
}

func TestCrashScanRestartsOnANewLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+"[  120.000001] BUG: first boot\n"+strings.Repeat("[    2.000000] filler\n", 50))
	st := &crashState{}
	scan(t, st, path)
	// Lima truncates at start: the new log is shorter.
	writeLog(t, path, "[    0.000000] Booting Linux\n[    5.000002] BUG: second boot\n")
	scan(t, st, path)
	if len(st.Crashes) != 2 {
		t.Fatalf("a shorter log is a new one, read from its start: %+v", st.Crashes)
	}
	// And a new log that has already grown past the old offset.
	writeLog(t, path, strings.Repeat("[    0.100000] other filler\n", 200)+"[    7.000003] BUG: third boot\n")
	scan(t, st, path)
	if len(st.Crashes) != 3 {
		t.Fatalf("a log whose start changed is a new one: %+v", st.Crashes)
	}
}

func TestCrashScanNeverReportsTheSameCrashTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+panicFixture(t))
	st := &crashState{}
	scan(t, st, path)
	scan(t, st, path)
	appendLog(t, path, "[   70.000000] later noise\n")
	scan(t, st, path)
	// devkit up expects a new log and reads from the start again.
	st.newLog()
	scan(t, st, path)
	if len(st.Crashes) != 1 {
		t.Errorf("the same crash must be reported once, got %d", len(st.Crashes))
	}
	if !st.LastPanic {
		t.Error("re-reading the log must still know its latest crash is a panic")
	}
}

func TestCrashScanWaitsForACompleteLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+"[  120.123456] Kernel pan")
	st := &crashState{}
	scan(t, st, path)
	if len(st.Crashes) != 0 {
		t.Fatal("an unterminated line is not read yet")
	}
	appendLog(t, path, "ic - not syncing: Fatal exception\n")
	scan(t, st, path)
	if len(st.Crashes) != 1 || !strings.Contains(st.Crashes[0].Key, "Kernel panic - not syncing: Fatal exception") {
		t.Errorf("the completed line must be read whole: %+v", st.Crashes)
	}
}

func TestCrashScanGroupsAnOopsWithItsPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+
		"[  200.100000] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000\n"+
		"[  200.100100] Mem abort info:\n"+
		"[  200.100200] Internal error: Oops: 0000000096000005 [#1] SMP\n"+
		"[  200.100300] Modules linked in: nft_chain_nat\n")
	st := &crashState{}
	scan(t, st, path)
	if st.LastPanic {
		t.Error("an Oops alone is not a panic")
	}
	appendLog(t, path, "[  200.200000] Kernel panic - not syncing: Oops: Fatal exception\n[  200.200100] SMP: stopping secondary CPUs\n")
	scan(t, st, path)
	if len(st.Crashes) != 1 || !st.Crashes[0].Panic || !st.LastPanic {
		t.Fatalf("an Oops and the panic it causes are one report, a panic: %+v", st.Crashes)
	}
	if n := len(st.Crashes[0].Lines); n != 6 {
		t.Errorf("all six lines belong to the report, got %d", n)
	}
	// Much later, in the same boot, another crash is another report.
	appendLog(t, path, "[  900.000000] BUG: soft lockup - CPU#0 stuck for 22s!\n")
	scan(t, st, path)
	if len(st.Crashes) != 2 || st.LastPanic {
		t.Errorf("a later crash is a new report, and the latest is not a panic: %+v", st.Crashes)
	}
}

func TestCrashScanForgetsAPanicAfterAReboot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	writeLog(t, path, bootLines+panicFixture(t)+"[    0.000000] Booting Linux on physical CPU 0x0\n")
	st := &crashState{}
	scan(t, st, path)
	if len(st.Crashes) != 1 || st.LastPanic {
		t.Errorf("after the guest booted again, the crash stays reported but the VM is no longer panicked: %+v last=%v", st.Crashes, st.LastPanic)
	}
}

func TestAckCrashesClearsTheWarning(t *testing.T) {
	fakeHome(t)
	must(t, os.MkdirAll(filepath.Dir(serialLog(demoVM)), 0o755))
	writeLog(t, serialLog(demoVM), bootLines+"[  120.000001] BUG: a bug\n")
	st, err := scanCrashes(demoVM)
	if err != nil || len(st.Crashes) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	if !strings.Contains(crashWarning(demoVM, st, true), "BUG: a bug") {
		t.Error("an unacknowledged crash is warned about")
	}
	if n, err := ackCrashes(demoVM); err != nil || n != 1 {
		t.Fatalf("ack: %d %v", n, err)
	}
	st, _ = scanCrashes(demoVM)
	if w := crashWarning(demoVM, st, true); w != "" {
		t.Errorf("acknowledged: no warning, got %q", w)
	}
	// Even when the log is read from its start again.
	expectNewCrashLog(demoVM)
	st, _ = scanCrashes(demoVM)
	if len(st.Crashes) != 0 {
		t.Errorf("an acknowledged crash must not come back: %+v", st.Crashes)
	}
	// A new crash is reported.
	appendLog(t, serialLog(demoVM), "[  130.000001] BUG: another bug\n")
	st, _ = scanCrashes(demoVM)
	if len(st.Crashes) != 1 {
		t.Errorf("a new crash after the acknowledgement is reported: %+v", st.Crashes)
	}
}
