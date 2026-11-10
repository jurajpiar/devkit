package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/embedded"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
)

// warnRunning prints the warnings every command that uses a running VM
// without restarting it owes the user: a stale policy, and under
// network.enforce: host a VM whose network the Mac does not confine.
func warnRunning(ctx context.Context, cfg *project.Config) {
	warnIfStale(ctx, cfg)
	warnIfUnconfined(ctx, cfg)
}

// warnIfStale prints a warning when the running VM applied a policy older or
// otherwise different from what this devkit binary would apply now. Commands
// that use a running VM without reprovisioning (shell, logs, sync, audit) call
// it, since a long-lived VM can silently sit on superseded sandbox rules after
// a devkit upgrade. It is best-effort: any uncertainty stays silent, and it
// never blocks the command.
func warnIfStale(ctx context.Context, cfg *project.Config) {
	warnIfStaleTo(ctx, cfg, os.Stderr)
}

// provisionIDFor is what warnIfStale compares against; tests replace it.
var provisionIDFor = expectedProvisionID

func warnIfStaleTo(ctx context.Context, cfg *project.Config, w io.Writer) {
	want := provisionIDFor(ctx, cfg)
	if want == "" {
		return
	}
	// "|| true": a VM from before the stamp has no file, and that case must
	// reach the warning below rather than look like an ssh failure.
	out, err := lima.Exec(ctx, cfg.VMName(), "cat /etc/devkit/provision.id 2>/dev/null || true")
	if err != nil {
		return
	}
	got := strings.TrimSpace(out)
	if got == want {
		return
	}
	if got == "" {
		// The VM predates the stamp entirely: it is from before this feature.
		fmt.Fprintf(w, "Warning: this VM predates the current devkit's sandbox policy.\n  Run 'devkit down && devkit up' to reprovision it.\n")
		return
	}
	fmt.Fprintf(w, "Warning: this VM applied an older devkit policy (%s; this devkit expects %s).\n  Run 'devkit down && devkit up' to apply the current sandbox policy.\n", got, want)
}

// expectedProvisionID is the fingerprint this binary would write for cfg, or
// "" if it cannot be computed (e.g. the proxy binary is unavailable).
func expectedProvisionID(ctx context.Context, cfg *project.Config) string {
	// Mirror up exactly: in none mode no proxy is dropped in and up renders
	// with an empty hash, so the fingerprint must be computed the same way
	// or every air-gapped VM would look stale.
	sha := ""
	if cfg.Network.Mode != project.NetworkNone {
		bin, err := egressProxyBinary(ctx)
		if err != nil {
			return ""
		}
		sha = embedded.SHA256(bin)
	}
	hostProxy := ""
	if cfg.HostEnforced() {
		// The port up chose and kept; without one, up has never run in
		// host mode and there is nothing to compare.
		data, err := os.ReadFile(filepath.Join(vmStateDir(cfg.VMName()), hostProxyPortFile))
		if err != nil {
			return ""
		}
		hostProxy = hostGateway + ":" + strings.TrimSpace(string(data))
	}
	fp, err := provision.Fingerprint(provision.Params{
		Config:       cfg,
		User:         hostUser(),
		EgressSHA256: sha,
		HostProxy:    hostProxy,
	})
	if err != nil {
		return ""
	}
	return fp
}
