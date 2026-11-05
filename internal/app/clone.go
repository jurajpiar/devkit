package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurajpiar/devkit/internal/detect"
	"github.com/jurajpiar/devkit/internal/gitx"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
)

// Seams for tests, which clone from local paths that devkit refuses.
var (
	normalizeCloneURL = gitx.NormalizeURL
	cloneRepo         = gitx.CloneBare
	fetchUpstream     = gitx.FetchBare
)

var cloneCmd = &cobra.Command{
	Use:   "clone <url> [dir]",
	Short: "Clone a repository for a new sandbox without checking it out on your Mac",
	Long: `Clone a repository into a new project directory and write its devkit.yaml.

Your Mac clones with your own git credentials, so private repositories work,
but bare: the project's files are never written out on the Mac. The VM gets a
fresh-clone .git on 'devkit up' and checks the files out itself. Languages are
detected from marker files read straight from git objects. 'devkit sync'
fetches new upstream commits on the Mac and fast-forwards the VM, and
'devkit push' pushes the VM's commits after you review them.

Accepts https://, ssh:// and git@host:org/repo URLs, and github.com/org/repo.
git:// is rewritten to https://. Also available as 'devkit <url>'.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runClone,
}

func init() {
	rootCmd.AddCommand(cloneCmd)
	addCloneFlags(cloneCmd)

	// "devkit <url>" is "devkit clone <url>", with the same flags (hidden
	// from the root's help); anything else is still an unknown command.
	addCloneFlags(rootCmd)
	for _, f := range []string{"branch", "name", "node", "toolchain", "network"} {
		_ = rootCmd.Flags().MarkHidden(f)
	}
	rootCmd.Args = cobra.ArbitraryArgs
	rootCmd.SuggestionsMinimumDistance = 2
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		if _, _, err := normalizeCloneURL(args[0]); err == nil && len(args) <= 2 {
			return runClone(cmd, args)
		}
		msg := fmt.Sprintf("unknown command %q for \"devkit\"", args[0])
		if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
			msg += "; did you mean " + strings.Join(s, ", ") + "?"
		}
		return fmt.Errorf("%s (run 'devkit --help')", msg)
	}
}

func addCloneFlags(c *cobra.Command) {
	c.Flags().String("branch", "", "branch to clone (default: the remote's default branch)")
	c.Flags().String("name", "", "project name (default: repository name)")
	c.Flags().String("node", "", "Node.js major version to install (default: detected, or 22)")
	c.Flags().String("toolchain", envOr("DEVKIT_TOOLCHAIN", project.ManagerMise), "toolchain manager: mise, nix or none")
	c.Flags().String("network", project.NetworkAllowlist, "network mode: allowlist, open or none")
}

// bareRepo is where devkit clone keeps the host's copy of a repository.
func bareRepo(dir string) string { return filepath.Join(dir, project.LockDir, "repo.git") }

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func runClone(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	url, note, err := normalizeCloneURL(args[0])
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Println("Note: " + note)
	}
	dir := repoName(url)
	if len(args) == 2 {
		dir = args[1]
	}
	if dir == "" || dir == "." || dir == ".." || strings.HasPrefix(dir, "-") {
		return fmt.Errorf("invalid directory %q", dir)
	}
	// Resolve first, then create the directory exclusively: cleanup on
	// failure may only ever remove a directory this run made. "x/.." or
	// "./" resolve to a directory that exists and are refused.
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("%s already exists", abs)
	}
	if err := os.Mkdir(abs, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", abs, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(abs)
		}
	}()
	if err := os.Mkdir(filepath.Join(abs, project.LockDir), 0o755); err != nil {
		return err
	}

	branch, _ := cmd.Flags().GetString("branch")
	fmt.Printf("Cloning %s on your Mac (bare: nothing is checked out here)\n", url)
	if err := cloneRepo(ctx, url, branch, bareRepo(abs), os.Stderr); err != nil {
		return err
	}
	head, err := gitx.HeadBranch(ctx, bareRepo(abs))
	if err != nil {
		return err
	}

	// Detection reads marker files from git objects into a private
	// temporary directory, under fixed names, instead of a checkout.
	markers, err := os.MkdirTemp("", "devkit-markers-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(markers)
	if err := gitx.ExtractFiles(ctx, bareRepo(abs), "HEAD", detect.MarkerFiles, markers); err != nil {
		return err
	}
	cfg := project.Default()
	cfg.Source = project.SourceGit
	cfg.Repo = url
	cfg.Branch = head
	if err := writeProjectConfig(cmd, cfg, abs, filepath.Join(abs, project.DefaultFile), detect.Scan(markers)); err != nil {
		return err
	}
	ok = true
	fmt.Printf("Next: cd %s && devkit up\n", dir)
	return nil
}

// syncUpstream fetches new commits of the configured branch on the Mac and
// hands them to the VM as a bundle, which the VM fetches into
// origin/<branch>; the VM never talks to the remote. The Mac fetches into a
// staging ref and moves its own branch only once the VM has the commits, so
// a failed hand-over is retried by the next sync.
func syncUpstream(ctx context.Context, cfg *project.Config, dir, ws string) error {
	repo := bareRepo(dir)
	b := cfg.Branch
	// Each sync stages under its own ref, so a concurrent one cannot change
	// what this one delivers and records.
	staging := "refs/devkit/upstream/" + b + "-" + randHex()
	defer func() { _ = gitx.DeleteRef(context.Background(), repo, staging) }()
	old, err := gitx.RevParse(ctx, repo, "refs/heads/"+b)
	if err != nil {
		return err
	}
	fmt.Printf("Fetching %s on your Mac\n", b)
	if err := fetchUpstream(ctx, repo, b, staging, os.Stderr); err != nil {
		return err
	}
	cur, err := gitx.RevParse(ctx, repo, staging)
	if err != nil {
		return err
	}
	if cur == old {
		fmt.Printf("Up to date with origin/%s\n", b)
		return nil
	}
	name := cfg.VMName()
	if gitx.IsAncestor(ctx, repo, cur, old) {
		// Upstream moved back: no new commits, only origin/<branch> moves.
		// The VM's own branch is left alone.
		script := fmt.Sprintf(`cd "%s" || exit 1
git cat-file -e %s^{commit} 2>/dev/null || { echo "origin/%s moved back to a commit this VM does not have"; exit 1; }
git update-ref refs/remotes/origin/%s %s && echo "origin/%s moved back upstream; your branches are unchanged"`, ws, cur, b, b, cur, b)
		if err := lima.ExecStream(ctx, name, script); err != nil {
			return err
		}
		return gitx.SetBranch(ctx, repo, b, cur)
	}
	tmp, err := os.MkdirTemp("", "devkit-sync-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	local := filepath.Join(tmp, "upstream.bundle")
	if err := gitx.BundleRange(ctx, repo, staging, old, local); err != nil {
		return err
	}
	guest := "/tmp/devkit-sync-" + randHex() + ".bundle"
	if err := lima.CopyTo(ctx, name, local, guest); err != nil {
		return err
	}
	if err := lima.ExecStream(ctx, name, upstreamScript(ws, guest, b, staging)); err != nil {
		return fmt.Errorf("the VM did not take the new commits; the next devkit sync retries: %w", err)
	}
	return gitx.SetBranch(ctx, repo, b, cur)
}

// upstreamScript is what the VM runs to take a sync bundle: fetch it into
// origin/<branch>, then fast-forward <branch> and nothing else. The bundle
// carries the commit under staging. ws is a
// devkit constant expanded in double quotes; b passed ValidBranch.
func upstreamScript(ws, guest, b, staging string) string {
	src := shellQuote("+" + staging + ":refs/remotes/origin/" + b)
	qb := shellQuote(b)
	return fmt.Sprintf(`cd "%s" || exit 1
git fetch -q %s %s; st=$?
rm -f %s
[ $st -eq 0 ] || { echo "could not apply the new commits"; exit 1; }
cur="$(git symbolic-ref --short -q HEAD)"
if [ "$cur" = %s ]; then
  if git merge --ff-only -q origin/%s 2>/dev/null; then echo "Fast-forwarded %s to origin/%s"
  else echo "Fetched origin/%s; %s has diverged or has local changes, merge or rebase it yourself"; fi
elif git fetch -q . refs/remotes/origin/%s:refs/heads/%s 2>/dev/null; then
  echo "Fast-forwarded %s to origin/%s; you are on $cur, which is unchanged"
else
  echo "Fetched origin/%s; %s has diverged, merge it yourself"
fi
`, ws, shellQuote(guest), src, shellQuote(guest), qb, b, b, b, b, b, b, b, b, b, b, b)
}
