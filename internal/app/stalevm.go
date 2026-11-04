package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jurajpiar/devkit/internal/embedded"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
)

// warnIfStale prints a warning when the running VM applied a policy older or
// otherwise different from what this devkit binary would apply now. Commands
// that use a running VM without reprovisioning (shell, logs, sync, audit) call
// it, since a long-lived VM can silently sit on superseded sandbox rules after
// a devkit upgrade. It is best-effort: any uncertainty stays silent, and it
// never blocks the command.
func warnIfStale(ctx context.Context, cfg *project.Config) {
	want := expectedProvisionID(ctx, cfg)
	if want == "" {
		return
	}
	out, err := lima.Exec(ctx, cfg.VMName(), "cat /etc/devkit/provision.id 2>/dev/null")
	if err != nil {
		return
	}
	got := strings.TrimSpace(out)
	if got == want {
		return
	}
	if got == "" {
		// The VM predates the stamp entirely: it is from before this feature.
		fmt.Fprintf(os.Stderr, "Warning: this VM predates the current devkit's sandbox policy.\n  Run 'devkit down && devkit up' to reprovision it.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Warning: this VM applied an older devkit policy (%s; this devkit expects %s).\n  Run 'devkit down && devkit up' to apply the current sandbox policy.\n", got, want)
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
	fp, err := provision.Fingerprint(provision.Params{
		Config:       cfg,
		User:         hostUser(),
		EgressSHA256: sha,
	})
	if err != nil {
		return ""
	}
	return fp
}
