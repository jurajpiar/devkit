package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jurajpiar/devkit/internal/gitx"
	"github.com/jurajpiar/devkit/internal/lima"
)

// syncGit gives a copied project the .git a fresh clone would have: the
// host's current commit and branch, and nothing else (see package gitx).
// A repository already in the VM is kept, because it may hold commits made
// there that the host has never seen.
//
// repo is the host repository: the project directory for source: copy, or
// devkit clone's bare copy for source: git. With checkout the VM writes the
// files out itself; a copied project already has them.
func syncGit(ctx context.Context, name, repo, ws string, checkout bool, excludes []string) error {
	out, _ := lima.Exec(ctx, name, fmt.Sprintf(`test -e "%s/.git" && echo yes`, ws))
	if strings.TrimSpace(out) == "yes" {
		fmt.Println("Keeping the VM's own git repository")
		return nil
	}
	snap, err := gitx.TakeSnapshot(ctx, repo)
	if err != nil {
		return err
	}
	if snap == nil {
		return nil
	}
	defer snap.Close()
	if err := lima.PipeTar(ctx, name, snap.Dir, ws, nil); err != nil {
		return fmt.Errorf("copy .git into the VM: %w", err)
	}
	// Rebuild the index from HEAD and leave the copied files as they are,
	// so uncommitted host changes show as changes.
	script := fmt.Sprintf(`cd "%s" || exit 1`, ws)
	switch {
	case snap.Head != "" && checkout:
		script += " && git reset -q --hard"
	case snap.Head != "":
		script += " && git reset -q && { " + skipExcludedScript(excludes) + "; }"
	}
	for _, k := range []string{"user.name", "user.email"} {
		if v := hostGitConfig(ctx, repo, k); v != "" {
			script += fmt.Sprintf(" && git config %s %s", k, shellQuote(v))
		}
	}
	if _, err := lima.Exec(ctx, name, script); err != nil {
		return fmt.Errorf("set up git in the VM: %w", err)
	}
	what := "an empty repository"
	if snap.Head != "" {
		what = "commit " + snap.Head[:12]
	}
	on := snap.Branch
	if on == "" {
		on = "detached HEAD"
	}
	fmt.Printf("Added .git as a fresh clone would have it: %s on %s, no history, hooks or credentials\n", what, on)
	return nil
}

// hostGitConfig reads one value of the host's effective git config.
func hostGitConfig(ctx context.Context, dir, key string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", key).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if strings.ContainsAny(v, "\n\r") {
		return ""
	}
	return v
}

// skipExcludedScript marks tracked files that exclude kept out of the copy
// as skip-worktree, so git in the VM treats them as unchanged rather than
// deleted. Only files missing from the work tree and matching an exclude
// pattern are marked; any other missing file is a real deletion.
func skipExcludedScript(excludes []string) string {
	var specs []string
	for _, e := range excludes {
		e = strings.Trim(e, "/")
		if e == "" || e == ".git" {
			continue
		}
		for _, form := range []string{"**/%s", "**/%s/**"} {
			specs = append(specs, shellQuote(":(glob)"+fmt.Sprintf(form, e)))
		}
	}
	if len(specs) == 0 {
		return "true"
	}
	return "git ls-files -d -z -- " + strings.Join(specs, " ") + " | git update-index -z --skip-worktree --stdin"
}
