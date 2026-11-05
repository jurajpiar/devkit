package gitx

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

// Exit codes of BundleScript besides 0 (bundle written).
const (
	ExitNoBranch      = 3
	ExitNothingToPush = 4
)

// noHooks keeps git on the host from running the repository's hooks. A
// pre-push hook such as husky's runs the project's own scripts, which is
// exactly the code the VM exists to contain; it already ran inside.
var noHooks = []string{"-c", "core.hooksPath=" + os.DevNull}

var commitID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// ValidCommitID reports a full SHA-1 or SHA-256 object name.
func ValidCommitID(s string) bool { return commitID.MatchString(s) }

var branchChars = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

// ValidBranch accepts a plain branch name, stricter than git: the name
// travels from the VM, so anything git would treat as a revision expression,
// an option or a full ref name is refused.
func ValidBranch(name string) bool {
	if !branchChars.MatchString(name) || name == "HEAD" || strings.HasPrefix(name, "refs/") {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// QuarantineRef is where a branch from the VM is kept on the host: outside
// refs/heads, so no checkout, branch listing or push of the host's own
// branches includes it.
func QuarantineRef(project, branch string) string {
	return "refs/devkit/" + project + "/" + branch
}

// BundleScript is the shell the VM runs to write a bundle of branch to out,
// leaving out every commit the host is known to have: the snapshot's
// shallow boundary and the given host commits the VM also has. It exits
// ExitNoBranch or ExitNothingToPush instead of writing an empty bundle.
// branch must have passed ValidBranch; bases that are not commit ids are
// dropped.
func BundleScript(ws, branch string, bases []string, out string) string {
	var known []string
	for _, b := range bases {
		if ValidCommitID(b) {
			known = append(known, b)
		}
	}
	ref := shq("refs/heads/" + branch)
	return fmt.Sprintf(`set -e
cd %s
git rev-parse -q --verify %s >/dev/null || exit %d
neg=""
for c in $(cat .git/shallow 2>/dev/null) %s; do
  if git cat-file -e "$c^{commit}" 2>/dev/null; then neg="$neg ^$c"; fi
done
# shellcheck disable=SC2086
if [ -z "$(git rev-list -1 %s $neg)" ]; then exit %d; fi
# shellcheck disable=SC2086
git bundle create -q %s %s $neg
`, shq(ws), ref, ExitNoBranch, strings.Join(known, " "), ref, ExitNothingToPush, shq(out), ref)
}

// ImportBundle fetches branch from a bundle the VM wrote into ref, checking
// every new object first (fsck rejects, among others, trees with a .git or
// .. entry, the shape of past checkout exploits). The bundle must carry that
// one branch and nothing else. No hooks run.
func ImportBundle(ctx context.Context, repo, bundle, branch, ref string) error {
	if !ValidBranch(branch) {
		return fmt.Errorf("invalid branch name")
	}
	heads, err := run(ctx, repo, "bundle", "list-heads", bundle)
	if err != nil {
		return fmt.Errorf("not a readable git bundle: %w", err)
	}
	lines := strings.Split(heads, "\n")
	if len(lines) != 1 {
		return fmt.Errorf("the bundle carries %d refs; only refs/heads/%s is accepted", len(lines), branch)
	}
	f := strings.Fields(lines[0])
	if len(f) != 2 || !ValidCommitID(f[0]) || f[1] != "refs/heads/"+branch {
		return fmt.Errorf("the bundle does not carry refs/heads/%s", branch)
	}
	args := append(append([]string{}, noHooks...),
		"-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true",
		"fetch", "-q", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", "--no-auto-gc",
		bundle, "+refs/heads/"+branch+":"+ref)
	if _, err := run(ctx, repo, args...); err != nil {
		return fmt.Errorf("refused the VM's commits: %w", err)
	}
	return nil
}

// Push sends ref to branch to on remote with the host's own credentials and
// no hooks. It never forces; lease allows replacing the remote branch only
// if it is still where the host last saw it.
func Push(ctx context.Context, repo, remote, ref, to string, lease bool, out io.Writer) error {
	if strings.HasPrefix(remote, "-") || !ValidBranch(to) {
		return fmt.Errorf("invalid remote or branch")
	}
	args := append(append([]string{"-C", repo}, noHooks...), "push", "--no-verify")
	if lease {
		args = append(args, "--force-with-lease=refs/heads/"+to)
	}
	args = append(args, remote, ref+":refs/heads/"+to)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git push: %w", err)
	}
	return nil
}

// Commit is one commit under review. Every field comes from the VM.
type Commit struct {
	ID, Author, Email, Subject string
}

// ReviewSummary is what a push would add on top of base.
type ReviewSummary struct {
	Commits []Commit
	Stat    string
	// Sensitive lists changed files that run outside the VM: in CI, in the
	// editor, or in your shell on the host.
	Sensitive []string
}

// Review describes the commits in ref that base does not have. An empty
// base means everything in ref.
func Review(ctx context.Context, repo, ref, base string) (*ReviewSummary, error) {
	rng := ref
	from := base
	if base != "" {
		rng = base + ".." + ref
	} else {
		empty, err := run(ctx, repo, "hash-object", "-t", "tree", os.DevNull)
		if err != nil {
			return nil, err
		}
		from = empty
	}
	log, err := run(ctx, repo, "log", "--format=%H%x1f%an%x1f%ae%x1f%s%x1e", rng)
	if err != nil {
		return nil, err
	}
	r := &ReviewSummary{}
	for _, rec := range strings.Split(log, "\x1e") {
		f := strings.Split(strings.TrimSpace(rec), "\x1f")
		if len(f) == 4 {
			r.Commits = append(r.Commits, Commit{ID: f[0], Author: f[1], Email: f[2], Subject: f[3]})
		}
	}
	if r.Stat, err = run(ctx, repo, "diff", "--stat", from, ref); err != nil {
		return nil, err
	}
	names, err := run(ctx, repo, "diff", "--name-only", "-z", from, ref)
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(names, "\x00") {
		if p != "" && Sensitive(p) {
			r.Sensitive = append(r.Sensitive, p)
		}
	}
	return r, nil
}

var sensitiveDirs = []string{
	".github/", ".gitlab/", ".circleci/", ".buildkite/", ".husky/", ".githooks/",
	".vscode/", ".idea/", ".devcontainer/", ".devkit/", ".zed/", ".cursor/", ".claude/",
}

var sensitiveNames = map[string]bool{
	".gitlab-ci.yml": true, ".gitmodules": true, ".gitattributes": true, ".envrc": true,
	".pre-commit-config.yaml": true, "lefthook.yml": true, "lefthook.yaml": true, ".lefthook.yml": true,
	"devkit.yaml": true, "Makefile": true, "justfile": true, "Justfile": true,
	"package.json": true, ".npmrc": true, ".yarnrc.yml": true, "bunfig.toml": true,
	"mise.toml": true, ".mise.toml": true, ".tool-versions": true, "flake.nix": true,
	"Taskfile.yml": true, ".travis.yml": true, "azure-pipelines.yml": true, "Jenkinsfile": true,
}

// Sensitive reports a path whose content runs outside the VM once pushed or
// pulled: CI definitions, git and editor hooks, direnv, package scripts,
// task runners and toolchain configs.
func Sensitive(p string) bool {
	for _, d := range sensitiveDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return sensitiveNames[path.Base(p)]
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// IsTopLevel reports whether dir is the top of a git work tree.
func IsTopLevel(ctx context.Context, dir string) bool {
	top, err := run(ctx, dir, "rev-parse", "--show-toplevel")
	return err == nil && sameDir(top, dir)
}

// UpstreamRemote is the remote branch tracks, or origin.
func UpstreamRemote(ctx context.Context, repo, branch string) string {
	if r, _ := run(ctx, repo, "config", "--get", "branch."+branch+".remote"); r != "" && r != "." && !strings.HasPrefix(r, "-") {
		return r
	}
	return "origin"
}

// KnownCommits lists commits the host has that the VM's bundle can leave
// out: HEAD and the remote-tracking tip of to.
func KnownCommits(ctx context.Context, repo, remote, to string) []string {
	var out []string
	for _, rev := range []string{"HEAD", "refs/remotes/" + remote + "/" + to} {
		if c, err := run(ctx, repo, "rev-parse", "-q", "--verify", rev+"^{commit}"); err == nil && ValidCommitID(c) {
			out = append(out, c)
		}
	}
	return out
}

// ReviewBase is the commit a push of ref is reviewed against: where it
// meets the remote branch as last fetched, else where it meets HEAD, else
// nothing (review everything).
func ReviewBase(ctx context.Context, repo, ref, remote, to string) string {
	for _, rev := range []string{"refs/remotes/" + remote + "/" + to, "HEAD"} {
		if c, err := run(ctx, repo, "merge-base", ref, rev); err == nil && ValidCommitID(c) {
			return c
		}
	}
	return ""
}
