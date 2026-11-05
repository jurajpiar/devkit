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
	cloneCmd.Flags().String("branch", "", "branch to clone (default: the remote's default branch)")
	cloneCmd.Flags().String("name", "", "project name (default: repository name)")
	cloneCmd.Flags().String("node", "", "Node.js major version to install (default: detected, or 22)")
	cloneCmd.Flags().String("toolchain", envOr("DEVKIT_TOOLCHAIN", project.ManagerMise), "toolchain manager: mise, nix or none")
	cloneCmd.Flags().String("network", project.NetworkAllowlist, "network mode: allowlist, open or none")

	// "devkit <url>" is "devkit clone <url>"; anything else is still an
	// unknown command.
	rootCmd.Args = cobra.ArbitraryArgs
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		if _, _, err := normalizeCloneURL(args[0]); err == nil && len(args) <= 2 {
			cloneCmd.SetContext(cmd.Context())
			return runClone(cloneCmd, args)
		}
		return fmt.Errorf("unknown command %q for \"devkit\"; run 'devkit --help'", args[0])
	}
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
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("%s already exists", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(abs, project.LockDir), 0o755); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(abs)
		}
	}()

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

// syncUpstream fetches new commits of the configured branch into the host's
// bare copy and hands them to the VM as a bundle, which the VM fetches into
// origin/<branch> and fast-forwards to when it can. The VM never talks to
// the remote.
func syncUpstream(ctx context.Context, cfg *project.Config, dir, ws string) error {
	repo := bareRepo(dir)
	ref := "refs/heads/" + cfg.Branch
	old, err := gitx.RevParse(ctx, repo, ref)
	if err != nil {
		return err
	}
	fmt.Printf("Fetching %s on your Mac\n", cfg.Branch)
	if err := fetchUpstream(ctx, repo, cfg.Branch, os.Stderr); err != nil {
		return err
	}
	cur, err := gitx.RevParse(ctx, repo, ref)
	if err != nil {
		return err
	}
	if cur == old {
		fmt.Printf("Up to date with origin/%s\n", cfg.Branch)
		return nil
	}
	tmp, err := os.MkdirTemp("", "devkit-sync-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	local := filepath.Join(tmp, "upstream.bundle")
	if err := gitx.BundleRange(ctx, repo, ref, old, local); err != nil {
		return err
	}
	name := cfg.VMName()
	guest := "/tmp/devkit-sync-" + randHex() + ".bundle"
	if err := lima.CopyTo(ctx, name, local, guest); err != nil {
		return err
	}
	b := cfg.Branch
	script := fmt.Sprintf(`cd "%s" || exit 1
git fetch -q %s +refs/heads/%s:refs/remotes/origin/%s; st=$?
rm -f %s
[ $st -eq 0 ] || { echo "could not apply the new commits; the VM's history may have diverged from origin/%s"; exit 1; }
if git merge --ff-only -q origin/%s 2>/dev/null; then echo "Fast-forwarded to origin/%s"
else echo "Fetched origin/%s; your branch has diverged or has local changes, merge or rebase it yourself"; fi`,
		ws, shellQuote(guest), b, b, shellQuote(guest), b, b, b, b)
	return lima.ExecStream(ctx, name, script)
}
