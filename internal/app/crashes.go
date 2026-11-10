package app

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
)

// Kernel crash reports, read on the Mac from the VM's serial log. The system
// script puts the guest kernel's console on hvc0 (from the boot after the
// first), which Lima records in serialv.log; only root in the guest can
// write there. A failed exploit attempt often crashes the kernel before one
// succeeds, so a crash report is worth showing. After a takeover root can
// silence the console: this catches the noisy attempt, not the clean one.

// crashStateFile keeps, in ~/.devkit/<vm>/, how far the serial log has been
// scanned and the crash reports not yet acknowledged.
const crashStateFile = "kernel-crashes.json"

const (
	crashMaxLine     = 4096     // bytes read of one console line; the rest is skipped
	crashKeepLine    = 512      // bytes of a line kept in a report and its key
	crashReportLines = 24       // lines kept of one report
	crashShowLines   = 8        // lines of the first report shown in a warning
	crashShowWidth   = 160      // characters shown of one line
	crashWindow      = 2.0      // seconds: lines this close to a report's last signature line belong to it
	crashHeadLen     = 64 << 10 // bytes of the log's start that identify it
	crashMaxKept     = 50       // unacknowledged reports kept
	crashMaxSeen     = 500      // keys of reports already found, acknowledged or not
)

// crashSignatures start the kernel's own crash reports. A line matches only
// when one of them is the start of its message, directly after the kernel's
// timestamp: text later in a line, such as a process name, never matches.
var crashSignatures = []string{
	"Kernel panic",
	"Unable to handle kernel",
	"Internal error: Oops",
	"Oops:",
	"Oops -",
	"general protection fault",
	"BUG:",
	"kernel BUG at",
	"KASAN:",
	"UBSAN:",
	"watchdog: BUG",
	"stack-protector: Kernel stack is corrupted",
	"list_add corruption",
	"list_del corruption",
}

// kernelLine is the kernel's console format: "[ <seconds>.<micros>] <message>".
var kernelLine = regexp.MustCompile(`^\[ *([0-9]{1,10})\.([0-9]{6})\] (.*)$`)

// gettyPrompt is a login prompt, which getty prints without a newline, so
// the kernel's next line can follow it on the same console line.
var gettyPrompt = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62} login: `)

type crashReport struct {
	Key   string   `json:"key"` // its first line, which identifies it
	Lines []string `json:"lines"`
	Panic bool     `json:"panic"`
}

type crashState struct {
	// Where the next scan starts, and the start of the log as it was then:
	// Lima begins a new log at every VM start.
	Offset  int64  `json:"offset"`
	HeadLen int64  `json:"head_len"`
	HeadSHA string `json:"head_sha"`
	// Of the current log: whether the kernel console reaches it at all (no
	// kernel line means this boot cannot report a crash), whether its latest
	// crash report is a kernel panic, the last kernel timestamp (one going
	// back means the guest rebooted) and the report still collecting lines.
	ConsoleSeen bool    `json:"console_seen"`
	LastPanic   bool    `json:"last_panic"`
	LastTS      float64 `json:"last_ts"`
	Open        string  `json:"open,omitempty"`
	OpenTS      float64 `json:"open_ts,omitempty"`

	Crashes []crashReport `json:"crashes,omitempty"` // not yet acknowledged
	Seen    []string      `json:"seen,omitempty"`    // never reported twice
}

// newLog forgets what is known about the current log.
func (st *crashState) newLog() {
	st.Offset, st.HeadLen, st.HeadSHA = 0, 0, ""
	st.ConsoleSeen, st.LastPanic, st.LastTS = false, false, 0
	st.Open, st.OpenTS = "", 0
}

func (st *crashState) seen(key string) bool {
	for _, k := range st.Seen {
		if k == key {
			return true
		}
	}
	return false
}

func (st *crashState) open() *crashReport {
	if st.Open == "" {
		return nil
	}
	for i := range st.Crashes {
		if st.Crashes[i].Key == st.Open {
			return &st.Crashes[i]
		}
	}
	return nil
}

// consoleText sanitises one console line from the guest for matching and
// display: terminal escape sequences, carriage returns and other control
// characters, C1 controls and invalid UTF-8 are removed.
func consoleText(b []byte) string {
	var out []byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != 0x1b {
			out = append(out, c)
			continue
		}
		if i+1 >= len(b) {
			break
		}
		switch b[i+1] {
		case '[': // CSI: parameters and intermediates, then a final byte
			j := i + 2
			for j < len(b) && b[j] >= 0x20 && b[j] <= 0x3f {
				j++
			}
			for j < len(b) && b[j] >= 0x20 && b[j] <= 0x2f {
				j++
			}
			i = j // the final byte, skipped by the loop
		case ']', 'P', '_', '^', 'X': // strings: to BEL or ESC \
			j := i + 2
			for j < len(b) && b[j] != 0x07 && b[j] != 0x1b {
				j++
			}
			if j+1 < len(b) && b[j] == 0x1b && b[j+1] == '\\' {
				j++
			}
			i = j
		default: // a two-byte sequence
			i++
		}
	}
	s := printable(string(out))
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// parseKernelLine returns the kernel timestamp and message of a sanitised
// console line, or ok false for anything that is not a kernel line.
func parseKernelLine(s string) (ts float64, msg string, ok bool) {
	if p := gettyPrompt.FindString(s); p != "" {
		s = s[len(p):]
	}
	m := kernelLine.FindStringSubmatch(s)
	if m == nil {
		return 0, "", false
	}
	sec, err1 := strconv.ParseFloat(m[1], 64)
	us, err2 := strconv.ParseFloat(m[2], 64)
	if err1 != nil || err2 != nil {
		return 0, "", false
	}
	return sec + us/1e6, m[3], true
}

// crashSignature is the signature msg starts with, or "".
func crashSignature(msg string) string {
	for _, sig := range crashSignatures {
		if strings.HasPrefix(msg, sig) {
			return sig
		}
	}
	return ""
}

// line takes one sanitised console line.
func (st *crashState) line(s string) {
	ts, msg, ok := parseKernelLine(s)
	if !ok {
		return
	}
	if len(s) > crashKeepLine {
		s = strings.ToValidUTF8(s[:crashKeepLine], "")
	}
	if st.ConsoleSeen && ts < st.LastTS {
		// The guest rebooted within this log: a new boot's lines.
		st.LastPanic, st.Open, st.OpenTS = false, "", 0
	}
	st.ConsoleSeen, st.LastTS = true, ts
	inWindow := st.Open != "" && ts-st.OpenTS <= crashWindow
	sig := crashSignature(msg)
	if sig == "" {
		if !inWindow {
			st.Open = ""
			return
		}
		if r := st.open(); r != nil && len(r.Lines) < crashReportLines {
			r.Lines = append(r.Lines, s)
		}
		return
	}
	isPanic := sig == "Kernel panic"
	if inWindow {
		// The same crash going on: an Oops, then the panic it causes.
		st.OpenTS = ts
		if isPanic {
			st.LastPanic = true
		}
		if r := st.open(); r != nil {
			if len(r.Lines) < crashReportLines {
				r.Lines = append(r.Lines, s)
			}
			r.Panic = r.Panic || isPanic
		}
		return
	}
	st.Open, st.OpenTS, st.LastPanic = s, ts, isPanic
	if st.seen(s) {
		return // found before, acknowledged or not; it still counts as the latest
	}
	st.Seen = append(st.Seen, s)
	if len(st.Seen) > crashMaxSeen {
		st.Seen = st.Seen[len(st.Seen)-crashMaxSeen:]
	}
	if len(st.Crashes) < crashMaxKept {
		st.Crashes = append(st.Crashes, crashReport{Key: s, Lines: []string{s}, Panic: isPanic})
	} else {
		st.Open = "" // counted in Seen, not kept
	}
}

// scanCrashLog reads what the serial log at path holds beyond st.Offset and
// records the crash reports in it. A log that is shorter than the offset, or
// whose start differs from the one seen last, is a new log and is read from
// its start. Only complete lines are read; one longer than crashMaxLine is
// cut, so memory is bounded whatever the log holds.
func scanCrashLog(st *crashState, path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size < st.Offset || size < st.HeadLen {
		st.newLog()
	} else if st.HeadLen > 0 {
		if sum, err := headSHA(f, st.HeadLen); err != nil {
			return err
		} else if sum != st.HeadSHA {
			st.newLog()
		}
	}
	st.HeadLen = min(size, crashHeadLen)
	if st.HeadSHA, err = headSHA(f, st.HeadLen); err != nil {
		return err
	}
	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, size-st.Offset), 64<<10)
	var line []byte
	var pending int64 // bytes of the current line so far
	for {
		chunk, err := r.ReadSlice('\n')
		pending += int64(len(chunk))
		if len(line) < crashMaxLine {
			line = append(line, chunk[:min(len(chunk), crashMaxLine-len(line))]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			// An unterminated last line is not consumed: the next scan
			// reads it again with the rest of it.
			if err == io.EOF {
				return nil
			}
			return err
		}
		st.Offset += pending
		pending = 0
		st.line(consoleText(bytes.TrimRight(line, "\r\n")))
		line = line[:0]
	}
}

// headSHA is the SHA-256 of the first n bytes of f.
func headSHA(f *os.File, n int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, n)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func crashStatePath(name string) string {
	return filepath.Join(vmStateDir(name), crashStateFile)
}

// crashLockFile, beside the state, serialises the commands that read and
// write it: an IDE session and a terminal can run devkit at once.
const crashLockFile = "kernel-crashes.lock"

// lockCrashState takes the advisory lock on the VM's crash state and
// returns the function that releases it. The lock goes with the process
// too, so a killed devkit never leaves it held.
func lockCrashState(name string) (unlock func(), err error) {
	if err := os.MkdirAll(vmStateDir(name), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(vmStateDir(name), crashLockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// updateCrashState runs fn on the VM's crash state under the lock and saves
// the result, unless fn says there is nothing to save. A state that cannot
// be locked is still updated, and the error says why it was not locked.
func updateCrashState(name string, fn func(st *crashState) (save bool, err error)) (*crashState, error) {
	unlock, lerr := lockCrashState(name)
	if lerr == nil {
		defer unlock()
	} else {
		lerr = fmt.Errorf("could not lock the kernel crash state: %w", lerr)
	}
	st, corrupt := readCrashState(name)
	save, err := fn(st)
	if save || corrupt {
		if serr := saveCrashState(name, st); err == nil {
			err = serr
		}
	}
	return st, errors.Join(lerr, err)
}

// loadCrashState reads the VM's crash state without changing it.
func loadCrashState(name string) *crashState {
	st, _ := readCrashState(name)
	return st
}

// readCrashState reads the VM's crash state. A state that cannot be parsed
// would hide reports devkit can no longer know about: it is replaced by an
// empty one, so the next scan reads the serial log from its start and finds
// again the reports still in it, and devkit says so. corrupt reports that.
func readCrashState(name string) (st *crashState, corrupt bool) {
	st = &crashState{}
	data, err := os.ReadFile(crashStatePath(name))
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(data, st); err != nil {
		*st = crashState{}
		fmt.Fprintf(crashStderr, "Warning: VM %s's saved kernel crash state is corrupt (%v); rescanning the serial log from its start. Reports acknowledged before may be shown again.\n", name, err)
		return st, true
	}
	return st, false
}

// saveCrashState writes the state to a new file and renames it into place,
// so a reader sees the old state or the new one, never part of one.
func saveCrashState(name string, st *crashState) error {
	if err := os.MkdirAll(vmStateDir(name), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(vmStateDir(name), crashStateFile+".*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), crashStatePath(name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// scanCrashes brings the VM's crash state up to date with its serial log.
// Failures are reported in the returned error, with the state as far as it
// got.
func scanCrashes(name string) (*crashState, error) {
	return updateCrashState(name, scanInto(name))
}

// scanInto is the update that scans the VM's serial log into a state.
func scanInto(name string) func(st *crashState) (bool, error) {
	return func(st *crashState) (bool, error) {
		if _, err := os.Stat(serialLog(name)); errors.Is(err, os.ErrNotExist) {
			return false, nil // no log yet: nothing to scan, nothing to save
		}
		// What was read before an error is kept.
		return true, scanCrashLog(st, serialLog(name))
	}
}

// checkCrashes is for the commands that use a running VM: it warns about
// unacknowledged crash reports and refuses a VM whose kernel has panicked,
// which would only hang.
func checkCrashes(cmd *cobra.Command, cfg *project.Config) error {
	if warnCrashes(cmd.ErrOrStderr(), cfg.VMName(), true) {
		return errPanicked(cfg.VMName())
	}
	return nil
}

// auditCrashes prints the audit's kernel crash section to w and reports
// whether it holds a finding, and an error when the log could not be read.
// The reports saved before still count when the log cannot be read: both
// can be returned.
func auditCrashes(w io.Writer, name string, running bool) (st *crashState, finding bool, err error) {
	st, err = scanCrashes(name)
	switch {
	case err != nil:
		fmt.Fprintf(w, "Kernel crash reports: could not read VM %s's serial log: %v\n", name, err)
		if st.panicked(running) || len(st.Crashes) > 0 {
			fmt.Fprintf(w, "The reports saved before:\n%s", crashWarning(name, st, running))
			finding = true
		}
	case st.panicked(running) || len(st.Crashes) > 0:
		fmt.Fprintf(w, "Kernel crash reports:\n%s", crashWarning(name, st, running))
		finding = true
	case !st.ConsoleSeen:
		// No kernel line in this boot's log: the console is not connected
		// yet, so silence here says nothing.
		fmt.Fprintf(w, "Kernel crash reports: not available on this boot; the kernel console reaches the Mac from the VM's next restart (devkit down, then devkit up).\n")
	default:
		fmt.Fprintf(w, "Kernel crash reports: none on the serial console (a kernel taken over by root can be kept quiet; see SECURITY.md).\n")
	}
	return st, finding, err
}

// expectNewCrashLog is called just before devkit starts or restarts a VM:
// Lima begins a new serial log then, which the next scan reads from its
// start. Reports already found are not reported again.
func expectNewCrashLog(name string) {
	_, _ = updateCrashState(name, func(st *crashState) (bool, error) {
		st.newLog()
		return true, nil
	})
}

// ackCrashes acknowledges every crash report found so far and returns how
// many there were.
func ackCrashes(name string) (int, error) {
	n := 0
	_, err := updateCrashState(name, func(st *crashState) (bool, error) {
		if save, err := scanInto(name)(st); err != nil {
			return save, err
		}
		n = len(st.Crashes)
		// A report still collecting lines stays open, so its rest is not
		// taken for a new crash.
		st.Crashes = nil
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// panicked reports whether a VM Lima says is running has in fact a
// panicked kernel: its log's latest crash report is a kernel panic.
func (st *crashState) panicked(running bool) bool {
	return running && st.LastPanic
}

// crashWarning is what devkit says about unacknowledged crash reports, or ""
// when there are none. running is whether Lima says the VM is running.
func crashWarning(name string, st *crashState, running bool) string {
	var b strings.Builder
	if st.panicked(running) {
		fmt.Fprintf(&b, "Warning: the kernel of VM %s has panicked: the VM will not respond, although Lima still reports it as running.\n  Run 'devkit down', then 'devkit up'.\n", name)
	}
	if n := len(st.Crashes); n > 0 {
		what := "a kernel crash report"
		if n > 1 {
			what = fmt.Sprintf("%d kernel crash reports", n)
		}
		fmt.Fprintf(&b, "Warning: VM %s's serial console has %s that you have not acknowledged. The first:\n", name, what)
		lines := st.Crashes[0].Lines
		for i, l := range lines {
			if i == crashShowLines {
				fmt.Fprintf(&b, "    ... (%d more lines)\n", len(lines)-i)
				break
			}
			l = consoleText([]byte(l))
			if utf8.RuneCountInString(l) > crashShowWidth {
				l = string([]rune(l)[:crashShowWidth]) + "..."
			}
			fmt.Fprintf(&b, "    %s\n", l)
		}
		b.WriteString("  A kernel crash can be a failed attempt to break out of the sandbox, or simply a bug.\n")
		b.WriteString("  If you cannot explain it, discard the VM with 'devkit rm'; otherwise acknowledge it with 'devkit audit --ack-crashes'.\n")
	}
	return b.String()
}

// warnCrashes scans the VM's serial log and prints crashWarning to w. It
// reports whether the VM's kernel has panicked while Lima says it is
// running, in which case nothing that needs the guest can work.
func warnCrashes(w io.Writer, name string, running bool) bool {
	st, err := scanCrashes(name)
	if err != nil {
		fmt.Fprintf(w, "Warning: could not read VM %s's serial log for kernel crash reports: %v\n", name, err)
	}
	fmt.Fprint(w, crashWarning(name, st, running))
	return st.panicked(running)
}

// newCrashWarning scans the serial log of a VM that is running and warns
// on w about the crash reports whose keys are not in shown, and about a
// panicked kernel. It reports whether the kernel has panicked.
func newCrashWarning(w io.Writer, name string, shown map[string]bool) bool {
	st, err := scanCrashes(name)
	if err != nil {
		fmt.Fprintf(w, "Warning: could not read VM %s's serial log for kernel crash reports: %v\n", name, err)
	}
	fresh := &crashState{LastPanic: st.LastPanic}
	for _, r := range st.Crashes {
		if !shown[r.Key] {
			fresh.Crashes = append(fresh.Crashes, r)
		}
	}
	fmt.Fprint(w, crashWarning(name, fresh, true))
	return st.panicked(true)
}

// errPanicked is returned by commands that need a guest whose kernel has
// panicked.
func errPanicked(name string) error {
	return fmt.Errorf("the kernel of VM %s has panicked, so it will not respond; run 'devkit down', then 'devkit up'", name)
}

// crashStderr is where devkit says that a crash state was corrupt.
var crashStderr io.Writer = os.Stderr
