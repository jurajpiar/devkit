package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
)

// stampMarker tags the answer of the stamp probe, so it can be told apart
// from anything a login shell prints.
const stampMarker = "devkit-stamp"

// stampProbe prints stampMarker=<id> when the provision stamp exists, can
// be read and is not empty, and stampMarker-missing otherwise. The system
// script removes the stamp when it starts and writes it back only when every
// step has succeeded. The read is a checked step: a stamp that cannot be
// read proves nothing.
const stampProbe = `if v="$(cat /etc/devkit/provision.id 2>/dev/null)" && [ -n "$v" ]; then printf '` + stampMarker + `=%s\n' "$v"; else echo ` + stampMarker + `-missing; fi`

// readStamp reports whether the running VM has a provision stamp, and its
// value. An empty value is no stamp, whatever the guest printed. An error
// means the answer could not be read.
func readStamp(ctx context.Context, name string) (id string, present bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := lima.Exec(ctx, name, stampProbe)
	if err != nil {
		return "", false, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == stampMarker+"-missing" {
			return "", false, nil
		}
		if v, ok := strings.CutPrefix(l, stampMarker+"="); ok {
			v = strings.TrimSpace(v)
			return v, v != "", nil
		}
	}
	return "", false, errors.New("no answer from the stamp check")
}

// requireProvisioned refuses a running VM whose provisioning did not finish:
// without the stamp there may be no firewall. A stamp from an older policy
// is only warned about, by warnIfStale.
func requireProvisioned(ctx context.Context, cfg *project.Config) error {
	_, present, err := readStamp(ctx, cfg.VMName())
	if err != nil {
		return fmt.Errorf("could not check that VM %s finished provisioning: %v", cfg.VMName(), err)
	}
	if !present {
		return fmt.Errorf("VM %s has not finished provisioning, so its firewall may not be in place; run 'devkit up'", cfg.VMName())
	}
	return nil
}

// confirmProvisioned runs once limactl start has returned, with startErr
// its error, or for a VM that was already running. A running VM without a
// stamp did not finish provisioning and may have no firewall: it is stopped,
// and the error says which step failed. serial is the instance's console
// log and mark where it stood before this boot (the zero mark: read it all).
func confirmProvisioned(ctx context.Context, name string, startErr error, serial string, mark serialMark) error {
	if startErr != nil {
		// A VM that is not running exposes nothing; any other state, or one
		// that cannot be read, is checked like a running one.
		if inst, err := lima.Get(ctx, name); err == nil && (inst == nil || !inst.Running()) {
			return startErr
		}
	}
	_, present, err := readStamp(ctx, name)
	if err == nil && present {
		return startErr
	}

	var b strings.Builder
	fmt.Fprintf(&b, "VM %s did not finish provisioning", name)
	step, failed := provisioningReport(serial, mark)
	switch {
	case err != nil:
		fmt.Fprintf(&b, " as far as devkit can tell: checking for the provision stamp failed: %v", err)
	case step != "" && failed != "":
		fmt.Fprintf(&b, ": step %q failed: %s", step, failed)
	case failed != "":
		fmt.Fprintf(&b, ": %s failed", failed)
	case step != "":
		fmt.Fprintf(&b, " (the last step it reported was %q)", step)
	}
	b.WriteString(".\n")
	if startErr != nil {
		fmt.Fprintf(&b, "limactl start also failed: %v\n", startErr)
	}
	// The stop must happen even when devkit up itself was interrupted.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	fmt.Printf("Stopping VM %s: provisioning did not finish\n", name)
	if err := lima.Stop(stopCtx, name); err != nil {
		fmt.Fprintf(&b, "The VM could not be stopped (%v) and may be running without its firewall: stop it now with 'devkit down'.\n", err)
	} else {
		b.WriteString("The VM was stopped so that it does not run without its firewall.\n")
	}
	b.WriteString("Fix the cause and run 'devkit up' again.")
	return errors.New(b.String())
}

// serialMark is where a serial log stood before a start: its size and, as
// the crash scanner keeps it, a fingerprint of its beginning. Lima begins a
// new log at every start, which may grow to or past the old one's size, so
// the size alone cannot tell this boot's lines from the previous boot's.
type serialMark struct {
	size, headLen int64
	headSHA       string
}

// markSerial is the mark of the log at path now; the zero mark if it is
// missing or unreadable.
func markSerial(path string) serialMark {
	f, err := os.Open(path)
	if err != nil {
		return serialMark{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return serialMark{}
	}
	m := serialMark{size: fi.Size(), headLen: min(fi.Size(), crashHeadLen)}
	if m.headSHA, err = headSHA(f, m.headLen); err != nil {
		return serialMark{}
	}
	return m
}

// since is where this boot's lines begin in f, of the given size: past the
// marked log if f still starts with it, else at the start, because Lima
// began a new log.
func (m serialMark) since(f *os.File, size int64) int64 {
	if m.size == 0 || size < m.size {
		return 0
	}
	if sum, err := headSHA(f, m.headLen); err != nil || sum != m.headSHA {
		return 0
	}
	return m.size
}

// provisioningReport reads the progress lines the system script wrote to
// the serial console since mark (from the start if Lima began a new log)
// and returns, for the last boot in that range, the last step it began and
// the failure its ERR trap reported. Either may be empty. Lines are
// sanitised.
func provisioningReport(path string, mark serialMark) (step, failed string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", ""
	}
	from := mark.since(f, fi.Size())
	// The steps are near the end; do not read a long log whole.
	if fi.Size()-from > 4<<20 {
		from = fi.Size() - 4<<20
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		i := strings.Index(l, progressPrefix)
		if i < 0 {
			continue
		}
		s := strings.TrimSpace(printable(l[i+len(progressPrefix):]))
		switch {
		case s == "provisioning started":
			step, failed = "", ""
		case strings.HasPrefix(s, "failed: "):
			failed = strings.TrimPrefix(s, "failed: ")
		case s == "", s == "done", strings.HasPrefix(s, "warning: "), strings.HasPrefix(s, "note: "):
		default:
			step = s
		}
	}
	return step, failed
}

// serialLog is the instance's serial console log, where Lima records what
// the guest's provisioning reports.
func serialLog(name string) string {
	return filepath.Join(lima.Dir(name), "serialv.log")
}
