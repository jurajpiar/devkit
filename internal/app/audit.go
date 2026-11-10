package app

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Report stale trust: roots the VM, its runtimes or the project trust that Mozilla no longer does",
	Long: `Report stale trust inside the sandbox.

The reference is Mozilla's current root store, fetched through the proxy and
cached for a day, with the system bundle as the fallback. The audit compares
it with the system bundle, Node's bundled roots, Java's cacerts, certifi
bundles in virtualenvs and toolchains, and certificate files in the project,
and names anything that is trusted but should not be. devkit up runs the
same audit shallowly after installing dependencies; --deep scans every file
in the workspace, including node_modules and vendored trees.

It also reports container images the project names without a digest, read
from its compose files and Dockerfiles (no Docker needed): pinned, unpinned,
and unresolved where a variable has no value devkit can see. That part is a
report and does not affect the exit status.

It also reports the kernel crash reports devkit found in the VM's serial
console, from the boot after the first (see SECURITY.md); --ack-crashes
acknowledges them and does nothing else.

Exit status is 1 when something stale or an unacknowledged kernel crash
report was found, 2 when the audit could not run to a verdict.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Preflight failures are not findings either: status 2, cause kept.
		if err := requireLima(); err != nil {
			return &exitError{code: 2, msg: err.Error()}
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return &exitError{code: 2, msg: err.Error()}
		}
		if ack, _ := cmd.Flags().GetBool("ack-crashes"); ack {
			// Needs no running VM: the reports are read on the Mac.
			n, err := ackCrashes(cfg.VMName())
			if err != nil {
				return &exitError{code: 2, msg: fmt.Sprintf("could not acknowledge the kernel crash reports: %v", err)}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Acknowledged %d kernel crash report(s) of VM %s.\n", n, cfg.VMName())
			return nil
		}
		if err := mustBeRunning(cmd, cfg); err != nil {
			return &exitError{code: 2, msg: err.Error()}
		}
		// The kernel's crash reports, read on the Mac. A panicked guest
		// cannot run the rest.
		crashSt, crashed, crashErr := auditCrashes(cmd.OutOrStdout(), cfg.VMName(), true)
		if crashSt.panicked(true) {
			return &exitError{code: 1, msg: errPanicked(cfg.VMName()).Error()}
		}
		warnRunning(cmd.Context(), cfg)
		script := "devkit-audit"
		if deep, _ := cmd.Flags().GetBool("deep"); deep {
			script += " --deep"
		}
		// Through shellScript so a Nix dev shell's node and keytool are on PATH.
		err = lima.ExecStream(cmd.Context(), cfg.VMName(), shellScript(cfg, []string{script}))
		// An unacknowledged crash report is a finding whatever the trust
		// audit says: 1.
		switch v := auditExit(err); {
		case v == auditStale && crashed:
			return &exitError{code: 1, msg: "stale trust and unacknowledged kernel crash reports found"}
		case v == auditStale:
			return &exitError{code: 1, msg: "stale trust found"}
		case crashed && v == auditClean:
			return &exitError{code: 1, msg: "unacknowledged kernel crash reports found"}
		case crashed:
			return &exitError{code: 1, msg: fmt.Sprintf("unacknowledged kernel crash reports found; the trust audit did not complete: %v", err)}
		case v != auditClean:
			return &exitError{code: 2, msg: fmt.Sprintf("audit did not complete: %v", err)}
		case crashErr != nil:
			return &exitError{code: 2, msg: fmt.Sprintf("could not read the kernel crash reports: %v", crashErr)}
		default:
			return nil
		}
	},
}

// Verdicts of the in-VM audit. The script exits 3 for stale trust and 2 for
// a crash; 1 is what a shell wrapper such as a failing nix develop returns,
// and anything else (ssh, a missing script) is also not a finding.
const (
	auditClean      = 0
	auditStale      = 3
	auditIncomplete = -1
)

// auditExit maps an ExecStream error to a verdict: a finding only when the
// script itself said so, incomplete for every other failure.
func auditExit(err error) int {
	if err == nil {
		return auditClean
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == auditStale {
		return auditStale
	}
	return auditIncomplete
}

// exitError carries a process exit status for the audit command.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }

func init() {
	// A bad flag is not a finding either: keep the 1 = stale, 2 = no verdict
	// contract for failures that happen before RunE.
	auditCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &exitError{code: 2, msg: err.Error()}
	})
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().Bool("deep", false, "scan every file in the workspace, including node_modules and vendored trees")
	auditCmd.Flags().Bool("ack-crashes", false, "acknowledge the kernel crash reports found so far, and do nothing else")
}
