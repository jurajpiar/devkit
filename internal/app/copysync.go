package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/gitx"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
)

// limaGuest is the project's VM as a copy sync reaches it.
type limaGuest struct{ name string }

func (g limaGuest) Exec(ctx context.Context, command string) (string, error) {
	return lima.Exec(ctx, g.name, command)
}

func (g limaGuest) Put(ctx context.Context, local, name string) (string, error) {
	dst := "/tmp/" + name
	return dst, lima.CopyTo(ctx, g.name, local, dst)
}

// notSyncedError is a copy sync the VM refused, having changed nothing:
// files changed on both sides, or something in the VM in the way of this
// Mac's changes (refused, git's own account of it). devkit up reports it
// and goes on; devkit sync fails with it.
type notSyncedError struct {
	conflicts []string
	refused   []string
}

// maxListed caps the paths a message lists.
const maxListed = 20

func (e *notSyncedError) Error() string {
	var b strings.Builder
	b.WriteString("the workspace was not synced, and nothing in the VM was changed.")
	if len(e.refused) > 0 {
		b.WriteString("\nSomething in the VM is in the way of this Mac's changes:\n")
		b.WriteString(listPaths(e.refused, maxListed, "  ", "\n"))
	}
	if len(e.conflicts) > 0 {
		fmt.Fprintf(&b, "\n%s changed both on this Mac and in the VM since the last sync:\n", plural(len(e.conflicts), "file"))
		b.WriteString(listPaths(e.conflicts, maxListed, "  ", "\n"))
	}
	b.WriteString("\n" + e.remedy())
	return b.String()
}

// remedy says what to do, for the message and for devkit up's reminder.
// --overwrite does not move what is in the way, so it is offered only for
// files changed on both sides, and only once nothing is in the way.
func (e *notSyncedError) remedy() string {
	var steps []string
	if len(e.refused) > 0 {
		steps = append(steps, "Move or remove what is in the way in the VM, then sync again.")
	}
	if len(e.conflicts) > 0 {
		steps = append(steps, "Run 'devkit sync --overwrite' to take this Mac's version of exactly the files changed on both sides; "+
			"the VM's other changes are kept. To keep the VM's versions, commit them in the VM or copy them out first.")
	}
	return strings.Join(steps, " Then: ")
}

// syncCopy brings the project directory into ws as a snapshot (see package
// gitx): what changed on this Mac since the last sync arrives, what the VM
// changed is kept, and a file changed on both sides stops the sync with
// nothing applied, unless overwrite takes this Mac's version of it.
func syncCopy(ctx context.Context, cfg *project.Config, cwd, ws string, overwrite bool) error {
	name := cfg.VMName()
	// Beside the VM's other host-side state, where a project cannot plant
	// anything, and gone with the VM on devkit rm. One sync at a time, from
	// the snapshot until the VM's answer is recorded.
	unlock, err := gitx.LockCopyRepo(copyRepoDir(cfg))
	if err != nil {
		return err
	}
	defer unlock()
	repo, err := gitx.OpenCopyRepo(ctx, copyRepoDir(cfg))
	if err != nil {
		return err
	}
	fmt.Printf("Syncing %s into the VM\n", cwd)
	snap, err := repo.SnapshotOf(ctx, lima.TarCommand(ctx, cwd, cfg.Exclude))
	if err != nil {
		return err
	}
	// Grouped by reason: an exclude list without .git would otherwise
	// print every file of the repository.
	var whys []string
	skipped := map[string][]string{}
	for _, s := range snap.Skipped {
		if skipped[s.Why] == nil {
			whys = append(whys, s.Why)
		}
		skipped[s.Why] = append(skipped[s.Why], fmt.Sprintf("%q", s.Path))
	}
	for _, why := range whys {
		fmt.Printf("Not copied, %s: %s\n", why, listPaths(skipped[why], 5, "", ", "))
	}
	res, err := gitx.DeliverCopy(ctx, repo, snap, limaGuest{name}, ws, overwrite)
	if err != nil {
		return fmt.Errorf("%s", reviewable(err.Error()))
	}
	if !res.Synced {
		return &notSyncedError{conflicts: res.Conflicts, refused: res.Refused}
	}
	if len(res.Skipped) > 0 {
		fmt.Printf("Warning: the VM could not apply the directory or mode of these (the path leads outside the workspace or through a symlink, or something was in the way): %s\n", listPaths(res.Skipped, 5, "", ", "))
	}
	if len(res.Kept) > 0 {
		fmt.Printf("Kept the VM's own changes, which now differ from this Mac: %s\n", listPaths(res.Kept, 5, "", ", "))
	}
	return syncGit(ctx, name, cwd, ws, false, cfg.Exclude)
}

// copyRepoDir is the Mac's private repository of a copied project.
func copyRepoDir(cfg *project.Config) string {
	return filepath.Join(vmStateDir(cfg.VMName()), gitx.CopySyncRepoDir)
}

// listPaths shows at most max paths from the VM, sanitised, each with
// prefix and separated by sep, and how many more there are.
func listPaths(paths []string, max int, prefix, sep string) string {
	var shown []string
	for i, p := range paths {
		if i == max {
			shown = append(shown, fmt.Sprintf("%sand %d more", prefix, len(paths)-max))
			break
		}
		shown = append(shown, prefix+reviewable(p))
	}
	return strings.Join(shown, sep)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
