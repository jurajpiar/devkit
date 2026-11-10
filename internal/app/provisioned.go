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

// stampProbe prints stampMarker=<id> when the provision stamp exists and
// stampMarker-missing when it does not. The system script removes the stamp
// when it starts and writes it back only when every step has succeeded.
const stampProbe = `if [ -f /etc/devkit/provision.id ]; then printf '` + stampMarker + `=%s\n' "$(cat /etc/devkit/provision.id)"; else echo ` + stampMarker + `-missing; fi`

// readStamp reports whether the running VM has a provision stamp, and its
// value. An error means the answer could not be read.
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
			return v, true, nil
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
// log and from the offset where this boot's lines begin.
func confirmProvisioned(ctx context.Context, name string, startErr error, serial string, from int64) error {
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
	step, failed := provisioningReport(serial, from)
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

// provisioningReport reads the progress lines the system script wrote to
// the serial console since offset from (from the start if the log is now
// shorter, which means Lima began a new one) and returns, for the last boot
// in that range, the last step it began and the failure its ERR trap
// reported. Either may be empty. Lines are sanitised.
func provisioningReport(path string, from int64) (step, failed string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		if fi.Size() < from {
			from = 0
		}
		// The steps are near the end; do not read a long log whole.
		if fi.Size()-from > 4<<20 {
			from = fi.Size() - 4<<20
		}
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

// fileSize is the size of path, or 0.
func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}
