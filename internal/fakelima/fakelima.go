// Package fakelima puts a stand-in limactl on PATH for tests. It records
// every invocation, serves a canned instance list for "list" (whatever its --format),
// answers "shell" commands from patterns the test sets, and succeeds at
// everything else (create, start, stop, delete, validate, copy) unless a test
// makes a verb fail. It lets the code that drives Lima be tested without a VM.
package fakelima

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Instance is one row of the fake "limactl list".
type Instance struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Dir    string `json:"dir,omitempty"`
}

// Fake is an installed fake limactl.
type Fake struct {
	t   *testing.T
	dir string
	n   int
}

const script = `#!/bin/bash
# fakelima: records argv. Each argument ends with \x1f (unit separator) and
# each call with \x1e (record separator), so arguments may contain newlines.
d="$FAKELIMA_DIR"
{ for a in "$@"; do printf '%s\x1f' "$a"; done; printf '\x1e'; } >> "$d/calls"
# A start appends what the test set as the guest's serial console output to
# the instance's serialv.log, where Lima records it.
last="${*: -1}"
# Like Lima, optionally: a start begins a new serial log.
if [ "$1" = start ] && [ -f "$d/truncate.$last" ]; then
  mkdir -p "$LIMA_HOME/$last"
  : > "$LIMA_HOME/$last/serialv.log"
fi
if [ "$1" = start ] && [ -f "$d/serial.$last" ]; then
  mkdir -p "$LIMA_HOME/$last"
  cat "$d/serial.$last" >> "$LIMA_HOME/$last/serialv.log"
fi
if [ -f "$d/fail.$1" ]; then
  echo "fakelima: $1 failed" >&2
  exit "$(cat "$d/fail.$1")"
fi
case "$1" in
  --version) echo "limactl version 2.2.1-fake"; exit 0 ;;
  list) cat "$d/list.json" 2>/dev/null; exit 0 ;;
  shell)
    cmd="${*: -1}"
    # A command reading a tar stream gets its input saved, numbered like
    # its call, so tests can unpack what would have reached the VM.
    case "$cmd" in *"-xf -"*)
      n="$(tr -cd '\036' < "$d/calls" | wc -c | tr -d ' ')"
      cat > "$d/stdin.$n" ;;
    esac
    for f in "$d"/shell.d/*; do
      [ -f "$f" ] || continue
      pat="$(head -n1 "$f")"
      case "$cmd" in *"$pat"*)
        code="$(sed -n 2p "$f")"
        # A code like "20s" is a guest that does not answer: sleep that
        # long, in a child that keeps the output open as ssh would, first.
        case "$code" in *s) sleep "${code%s}"; code=0 ;; esac
        tail -n +3 "$f"; exit "$code" ;;
      esac
    done
    # A VM that applies every copy sync it is sent, without doing so.
    if [ -f "$d/accept-copysync" ]; then
      case "$cmd" in *"devkit-sync \""*)
        c="$(printf '%s\n' "$cmd" | sed -n "s/.*'\([0-9a-f]\{40\}\)' [01]; echo devkit-exit=.*/\1/p" | tail -n 1)"
        printf 'devkit-synced %s\ndevkit-exit=0\n' "$c"; exit 0 ;;
      esac
    fi
    # A local guest runs what no rule answered, in bash, with its
    # directory as HOME; a tar stream saved above is its input.
    if [ -f "$d/guest" ]; then
      in=/dev/null
      [ -n "${n:-}" ] && in="$d/stdin.$n"
      HOME="$(cat "$d/guest")" bash -c "$cmd" < "$in"; exit $?
    fi
    exit 0 ;;
  copy)
    if [ -f "$d/guest" ]; then cp "$2" "${3#*:}" || exit 1; fi
    exit 0 ;;
esac
exit 0
`

// Install writes the fake, puts it first on PATH for the rest of the test
// and points LIMA_HOME at a temporary directory.
func Install(t *testing.T) *Fake {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(filepath.Join(dir, "shell.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "limactl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKELIMA_DIR", dir)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LIMA_HOME", filepath.Join(dir, "lima"))
	return &Fake{t: t, dir: dir}
}

// SetInstances replaces what "limactl list" prints: one JSON object per line,
// whatever --format asked for.
func (f *Fake) SetInstances(insts ...Instance) {
	f.t.Helper()
	var b strings.Builder
	for _, i := range insts {
		line, _ := json.Marshal(i)
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(f.dir, "list.json"), []byte(b.String()), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// OnShell makes any "limactl shell" whose command contains pattern print out
// and exit with code. Earlier rules win.
func (f *Fake) OnShell(pattern, out string, code int) {
	f.t.Helper()
	f.n++
	body := fmt.Sprintf("%s\n%d\n%s", pattern, code, out)
	if err := os.WriteFile(filepath.Join(f.dir, "shell.d", fmt.Sprintf("%03d", f.n)), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// LocalGuest makes the fake a VM made of a local directory, which it
// returns: "shell" commands that no OnShell rule answers run in bash with
// that directory as HOME (and a tar stream as their input), and "copy"
// copies the file to the destination path as given. It replaces
// AcceptCopySync: the guest applies copy syncs itself.
func (f *Fake) LocalGuest() string {
	f.t.Helper()
	os.Remove(filepath.Join(f.dir, "accept-copysync"))
	home := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(f.dir, "guest"), []byte(home), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return home
}

// AcceptCopySync makes the fake confirm every copy sync script it is
// sent, as a VM that applied the snapshot would, without applying it.
func (f *Fake) AcceptCopySync() {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "accept-copysync"), nil, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// OnShellHang makes any "limactl shell" whose command contains pattern
// hang for d before it succeeds silently, like a guest whose login shell
// blocks. The sleep is a child that holds the output open, as ssh is under
// limactl. Earlier rules win.
func (f *Fake) OnShellHang(pattern string, d time.Duration) {
	f.t.Helper()
	f.n++
	body := fmt.Sprintf("%s\n%ds\n", pattern, int(d.Seconds()))
	if err := os.WriteFile(filepath.Join(f.dir, "shell.d", fmt.Sprintf("%03d", f.n)), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// Fail makes every call whose first argument is verb exit with code.
func (f *Fake) Fail(verb string, code int) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "fail."+verb), []byte(fmt.Sprint(code)), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// OnStartSerial makes "limactl start" of the instance name append out to its
// serialv.log, as Lima records the guest's serial console there.
func (f *Fake) OnStartSerial(name, out string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "serial."+name), []byte(out), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// TruncateSerialOnStart makes "limactl start" of the instance name empty
// its serialv.log first, as Lima does, before appending what OnStartSerial
// set.
func (f *Fake) TruncateSerialOnStart(name string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "truncate."+name), nil, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// Calls returns every invocation so far, as argument lists.
func (f *Fake) Calls() [][]string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if err != nil {
		return nil
	}
	var calls [][]string
	for _, rec := range strings.Split(string(data), "\x1e") {
		if rec == "" {
			continue
		}
		calls = append(calls, strings.Split(strings.TrimSuffix(rec, "\x1f"), "\x1f"))
	}
	return calls
}

// Inputs returns, for each call in Calls order, the tar stream it was fed,
// or nil.
func (f *Fake) Inputs() [][]byte {
	f.t.Helper()
	calls := f.Calls()
	in := make([][]byte, len(calls))
	for i := range calls {
		if data, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("stdin.%d", i+1))); err == nil {
			in[i] = data
		}
	}
	return in
}

// Verbs returns the first argument of every call, for checking sequences.
func (f *Fake) Verbs() []string {
	var v []string
	for _, c := range f.Calls() {
		if len(c) > 0 {
			v = append(v, c[0])
		}
	}
	return v
}

// Reset forgets the calls recorded so far.
func (f *Fake) Reset() {
	os.Remove(filepath.Join(f.dir, "calls"))
	old, _ := filepath.Glob(filepath.Join(f.dir, "stdin.*"))
	for _, p := range old {
		os.Remove(p)
	}
}
