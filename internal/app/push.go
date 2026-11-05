package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jurajpiar/devkit/internal/gitx"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
	"github.com/spf13/cobra"
)

// maxBundle caps what push reads out of the VM.
const maxBundle = 512 << 20

var pushCmd = &cobra.Command{
	Use:   "push [branch]",
	Short: "Review commits made in the VM and push them with your own credentials",
	Long: `Push commits made inside the VM without giving the VM any credentials.

The VM writes a git bundle of the branch (default: the one checked out in
~/workspace). On your Mac, git checks every object in it, stores the branch
as refs/devkit/<project>/<branch>, outside your own branches and work tree,
and shows what would be pushed: commits, authors, changed files, and the
files among them that run in CI, your editor or your shell. After you
confirm, your Mac pushes it with your normal git credentials. No git hooks
run on the Mac; they ran in the VM. The push never forces; --force-with-lease
replaces the remote branch only if it is still where your Mac last saw it.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPush,
}

func init() {
	rootCmd.AddCommand(pushCmd)
	pushCmd.Flags().String("remote", "", "remote to push to (default: the branch's upstream remote, or origin)")
	pushCmd.Flags().String("to", "", "branch name on the remote (default: the same name)")
	pushCmd.Flags().BoolP("yes", "y", false, "push without asking after showing the review")
	pushCmd.Flags().Bool("force-with-lease", false, "replace the remote branch if it is still where your Mac last saw it")
}

func runPush(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if err := requireLima(); err != nil {
		return err
	}
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	if err := mustBeRunning(cmd, cfg); err != nil {
		return err
	}
	dir, _ := os.Getwd()
	// The host repository: the project itself when copied, devkit clone's
	// bare copy for source: git.
	cwd, bare := dir, false
	switch {
	case cfg.Source == project.SourceCopy:
		if !gitx.IsTopLevel(ctx, cwd) {
			return fmt.Errorf("%s is not the top of a git checkout", cwd)
		}
	case cfg.Source == project.SourceGit && isDir(bareRepo(dir)):
		cwd, bare = bareRepo(dir), true
	default:
		return fmt.Errorf("devkit push needs source: copy, or a project made by devkit clone")
	}
	name := cfg.VMName()
	ws := "$HOME/" + provision.WorkspaceDir

	branch := ""
	if len(args) == 1 {
		branch = args[0]
	} else {
		out, _ := lima.Exec(ctx, name, fmt.Sprintf(`git -C "%s" symbolic-ref --short -q HEAD`, ws))
		branch = strings.TrimSpace(out)
		if branch == "" {
			return fmt.Errorf("the VM's workspace is not on a branch; name one: devkit push <branch>")
		}
	}
	if !gitx.ValidBranch(branch) {
		return fmt.Errorf("refusing branch name %q from the VM", reviewable(branch))
	}
	to, _ := cmd.Flags().GetString("to")
	if to == "" {
		to = branch
	}
	if !gitx.ValidBranch(to) {
		return fmt.Errorf("invalid --to branch %q", to)
	}
	remote, _ := cmd.Flags().GetString("remote")
	if remote == "" {
		remote = gitx.UpstreamRemote(ctx, cwd, to)
	}
	if strings.HasPrefix(remote, "-") {
		return fmt.Errorf("invalid remote %q", remote)
	}

	// Leave out what the Mac already has, so the bundle holds only new work.
	bases := gitx.KnownCommits(ctx, cwd, remote, to)
	guest := "/tmp/devkit-push-" + randHex() + ".bundle"
	script := "(" + gitx.BundleScript(ws, branch, bases, guest) + "); echo devkit-exit=$?"
	out, err := lima.Exec(ctx, name, script)
	if err != nil {
		return fmt.Errorf("bundle in the VM: %w", err)
	}
	switch exitOf(out) {
	case "0":
	case fmt.Sprint(gitx.ExitNothingToPush):
		fmt.Printf("Nothing to push: %s in the VM has no commits your Mac lacks\n", branch)
		return nil
	case fmt.Sprint(gitx.ExitNoBranch):
		return fmt.Errorf("the VM has no branch %s", branch)
	default:
		return fmt.Errorf("could not bundle %s in the VM:\n%s", branch, reviewable(out))
	}
	defer func() { _, _ = lima.Exec(context.Background(), name, "rm -f "+shellQuote(guest)) }()

	tmp, err := os.MkdirTemp("", "devkit-push-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	local := filepath.Join(tmp, "vm.bundle")
	fh, err := os.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	readErr := lima.ReadGuestFile(ctx, name, guest, fh, maxBundle)
	if cerr := fh.Close(); readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		return readErr
	}

	ref := gitx.QuarantineRef(cfg.Name, branch)
	// From here on everything uses tip, the commit that was checked: ref
	// is shared, and another devkit push could move it.
	tip, err := gitx.ImportBundle(ctx, cwd, local, branch, ref)
	if err != nil {
		return err
	}
	// In a bare copy, refs/heads/<to> mirrors origin only; another remote
	// has no record there.
	tracksOrigin := bare && remote == "origin"
	dest, _ := gitx.RevParse(ctx, cwd, "refs/remotes/"+remote+"/"+to)
	if tracksOrigin {
		dest, _ = gitx.RevParse(ctx, cwd, "refs/heads/"+to)
	}
	base := gitx.ReviewBase(ctx, cwd, tip, remote, to)
	r, err := gitx.Review(ctx, cwd, tip, base, dest)
	if err != nil {
		return err
	}
	if len(r.Commits) == 0 && len(r.Dropped) == 0 {
		fmt.Printf("Nothing to push: %s adds no commits to %s/%s\n", branch, remote, to)
		return nil
	}
	printReview(ctx, cwd, r, ref, remote, to)

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes && !confirm(fmt.Sprintf("Push %d commit(s) to %s %s?", len(r.Commits), remote, to)) {
		return fmt.Errorf("not pushed; the commits stay at %s", ref)
	}
	lease, _ := cmd.Flags().GetBool("force-with-lease")
	expect := ""
	if lease && tracksOrigin {
		// No remote-tracking refs in a bare copy: lease on what it holds.
		expect = dest
	}
	if err := gitx.Push(ctx, cwd, remote, tip, to, lease, expect, os.Stdout); err != nil {
		return err
	}
	if tracksOrigin {
		// The bare copy stands in for origin: record what it now has, so
		// the next push and sync start from here.
		if err := gitx.SetBranch(ctx, cwd, to, tip); err != nil {
			return err
		}
	}
	if bare {
		fmt.Printf("Pushed %s to %s %s\n", branch, remote, to)
	} else {
		fmt.Printf("Pushed. On this Mac the commits are at %s; bring them into your checkout with: git merge --ff-only %s\n", ref, ref)
	}
	return nil
}

func printReview(ctx context.Context, cwd string, r *gitx.ReviewSummary, ref, remote, to string) {
	me := hostGitConfig(ctx, cwd, "user.email")
	fmt.Printf("\nCommits from the VM for %s %s (stored at %s):\n", remote, to, ref)
	for _, c := range r.Commits {
		fmt.Printf("  %s %s <%s>  %s\n", c.ID[:12], reviewable(c.Author), reviewable(c.Email), reviewable(c.Subject))
	}
	for _, c := range r.Commits {
		if me != "" && c.Email != me {
			fmt.Printf("\nNote: some commits name an author other than %s. Authorship in a commit is whatever the VM wrote.\n", me)
			break
		}
	}
	if len(r.Dropped) > 0 {
		fmt.Printf("\nThe remote %s has commits this push does not contain. With --force-with-lease they are removed; without it git refuses:\n", to)
		for _, c := range r.Dropped {
			fmt.Printf("  %s %s <%s>  %s\n", c.ID[:12], reviewable(c.Author), reviewable(c.Email), reviewable(c.Subject))
		}
	}
	fmt.Printf("\n%s\n", reviewable(r.Stat))
	if len(r.Sensitive) > 0 {
		fmt.Println("\nThese changed files run outside the VM, in CI, your editor or your shell. Read them before pushing:")
		for _, p := range r.Sensitive {
			fmt.Printf("  %s\n", reviewable(p))
		}
	}
	fmt.Printf("\nInspect in full with: git log -p %s\n\n", ref)
}

// reviewable makes text from the VM safe to show: no control characters,
// C0 or C1, and no bidirectional overrides that could make a file name or
// subject read differently from what it is. Line breaks are kept.
func reviewable(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case unicode.IsControl(r), r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
			return -1
		}
		return r
	}, s)
}

// exitOf reads the "devkit-exit=N" line the wrapped script ends with.
func exitOf(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	last := lines[len(lines)-1]
	if v, ok := strings.CutPrefix(last, "devkit-exit="); ok {
		return v
	}
	return ""
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
