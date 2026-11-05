package gitx

import (
	"bufio"
	"bytes"
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
// ws is a shell word expanded inside double quotes, such as
// "$HOME/workspace", and must come from devkit, never from the VM. branch
// must have passed ValidBranch; bases that are not commit ids are dropped.
func BundleScript(ws, branch string, bases []string, out string) string {
	var known []string
	for _, b := range bases {
		if ValidCommitID(b) {
			known = append(known, b)
		}
	}
	ref := shq("refs/heads/" + branch)
	return fmt.Sprintf(`set -e
cd "%s"
git rev-parse -q --verify %s >/dev/null || exit %d
neg=""
for c in $(cat .git/shallow 2>/dev/null) %s; do
  if git cat-file -e "$c^{commit}" 2>/dev/null; then neg="$neg ^$c"; fi
done
# shellcheck disable=SC2086
if [ -z "$(git rev-list -1 %s $neg)" ]; then exit %d; fi
# shellcheck disable=SC2086
git bundle create -q %s %s $neg
`, ws, ref, ExitNoBranch, strings.Join(known, " "), ref, ExitNothingToPush, shq(out), ref)
}

// ImportBundle stores branch from a bundle the VM wrote as ref. It does not
// lean on git fetch, whose object checking for bundles depends on the git
// release and the repository's config: it reads the bundle's header itself,
// requires exactly refs/heads/<branch> and prerequisites the host already
// has, and feeds the pack to "git index-pack --strict", which checks every
// object (refusing, among others, trees with a .git or .. entry, the shape
// of past checkout exploits). Only then is ref set, after a connectivity
// check, and no hooks run.
func ImportBundle(ctx context.Context, repo, bundle, branch, ref string) (string, error) {
	if !ValidBranch(branch) {
		return "", fmt.Errorf("invalid branch name")
	}
	f, err := os.Open(bundle)
	if err != nil {
		return "", err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	h, err := readBundleHeader(r)
	if err != nil {
		return "", fmt.Errorf("not a usable git bundle: %w", err)
	}
	if len(h.refs) != 1 || h.refs[0][1] != "refs/heads/"+branch {
		return "", fmt.Errorf("the bundle must carry refs/heads/%s and nothing else", branch)
	}
	tip := h.refs[0][0]
	for _, p := range h.prereqs {
		if _, err := run(ctx, repo, "cat-file", "-e", p+"^{commit}"); err != nil {
			return "", fmt.Errorf("the bundle builds on %s, which this repository does not have", p[:12])
		}
	}
	pack := exec.CommandContext(ctx, "git", append(append([]string{"-C", repo}, noHooks...), "index-pack", "--strict", "--fix-thin", "--stdin")...)
	pack.Stdin = r
	var perr bytes.Buffer
	pack.Stderr = &perr
	if err := pack.Run(); err != nil {
		return "", fmt.Errorf("refused the VM's commits: %s", strings.TrimSpace(perr.String()))
	}
	walk := append([]string{"rev-list", "--objects", "--quiet", tip, "--not"}, h.prereqs...)
	if _, err := run(ctx, repo, append(walk, "--all")...); err != nil {
		return "", fmt.Errorf("the VM's commits are incomplete: %w", err)
	}
	if _, err := run(ctx, repo, append(append([]string{}, noHooks...), "update-ref", ref, tip)...); err != nil {
		return "", err
	}
	return tip, nil
}

type bundleHeader struct {
	prereqs []string
	refs    [][2]string
}

// readBundleHeader parses a v2 or v3 bundle header up to the blank line
// that precedes the pack. Capabilities other than the object format, such
// as a partial-clone filter, are refused.
func readBundleHeader(r *bufio.Reader) (*bundleHeader, error) {
	line := func() (string, error) {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("truncated header")
		}
		if len(l) > 4096 {
			return "", fmt.Errorf("header line too long")
		}
		return strings.TrimSuffix(l, "\n"), nil
	}
	sig, err := line()
	if err != nil {
		return nil, err
	}
	if sig != "# v2 git bundle" && sig != "# v3 git bundle" {
		return nil, fmt.Errorf("unknown signature")
	}
	h := &bundleHeader{}
	for n := 0; ; n++ {
		if n > 10000 {
			return nil, fmt.Errorf("header too long")
		}
		l, err := line()
		if err != nil {
			return nil, err
		}
		switch {
		case l == "":
			return h, nil
		case strings.HasPrefix(l, "@"):
			if l != "@object-format=sha1" && l != "@object-format=sha256" {
				return nil, fmt.Errorf("unsupported capability %q", l)
			}
		case strings.HasPrefix(l, "-"):
			id, _, _ := strings.Cut(l[1:], " ")
			if !ValidCommitID(id) {
				return nil, fmt.Errorf("bad prerequisite")
			}
			h.prereqs = append(h.prereqs, id)
		default:
			id, name, ok := strings.Cut(l, " ")
			if !ok || !ValidCommitID(id) {
				return nil, fmt.Errorf("bad ref line")
			}
			h.refs = append(h.refs, [2]string{id, name})
		}
	}
}

// Push sends ref (a commit id or ref) to branch to on remote with the host's own credentials and
// no hooks. It never forces; lease allows replacing the remote branch only
// if it is still at expect, or, with expect empty, where the remote-tracking
// ref says it is. A bare copy has no remote-tracking refs, so it passes the
// commit it last saw.
func Push(ctx context.Context, repo, remote, ref, to string, lease bool, expect string, out io.Writer) error {
	if strings.HasPrefix(remote, "-") || !ValidBranch(to) || (expect != "" && !ValidCommitID(expect)) {
		return fmt.Errorf("invalid remote, branch or lease")
	}
	args := append(append([]string{"-C", repo}, noHooks...), "push", "--no-verify")
	switch {
	case lease && expect != "":
		args = append(args, "--force-with-lease=refs/heads/"+to+":"+expect)
	case lease:
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

// ReviewSummary is what a push of tip would change on the remote.
type ReviewSummary struct {
	// Commits are those tip adds over base.
	Commits []Commit
	// Dropped are commits on the remote branch that tip does not contain:
	// a lease push removes them.
	Dropped []Commit
	Stat    string
	// Sensitive lists changed files that run outside the VM: in CI, in the
	// editor, or in your shell on the host.
	Sensitive []string
}

// Review describes pushing tip. Commits are those in tip but not base (all
// of tip when base is empty). dest is the remote branch's tip as last seen,
// or empty: when tip does not contain it, its commits are listed as
// dropped and the diff is taken against dest, so files a forced push
// removes are shown too.
func Review(ctx context.Context, repo, tip, base, dest string) (*ReviewSummary, error) {
	if !ValidCommitID(tip) || (base != "" && !ValidCommitID(base)) || (dest != "" && !ValidCommitID(dest)) {
		return nil, fmt.Errorf("invalid commit id")
	}
	r := &ReviewSummary{}
	var err error
	rng := []string{tip}
	if base != "" {
		rng = append(rng, "^"+base)
	}
	if r.Commits, err = commits(ctx, repo, rng...); err != nil {
		return nil, err
	}
	from := base
	if dest != "" {
		if _, err := run(ctx, repo, "merge-base", "--is-ancestor", dest, tip); err != nil {
			if r.Dropped, err = commits(ctx, repo, dest, "^"+tip); err != nil {
				return nil, err
			}
			from = dest
		}
	}
	if from == "" {
		if from, err = run(ctx, repo, "hash-object", "-t", "tree", os.DevNull); err != nil {
			return nil, err
		}
	}
	if r.Stat, err = run(ctx, repo, "diff", "--stat", from, tip); err != nil {
		return nil, err
	}
	names, err := run(ctx, repo, "diff", "--name-only", "-z", from, tip)
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

// commits lists the commits in a revision range. The ids come from
// rev-list and are authoritative; the text fields are read one per line,
// which is safe because neither commit headers nor subjects can hold a
// newline, and any record that does not line up with its id fails the
// whole review rather than dropping a commit from view.
func commits(ctx context.Context, repo string, rng ...string) ([]Commit, error) {
	ids, err := run(ctx, repo, append([]string{"rev-list"}, rng...)...)
	if err != nil {
		return nil, err
	}
	if ids == "" {
		return nil, nil
	}
	want := strings.Split(ids, "\n")
	text, err := run(ctx, repo, append([]string{"log", "--format=%H%n%an%n%ae%n%s"}, rng...)...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(text, "\n")
	if len(lines) != 4*len(want) {
		return nil, fmt.Errorf("could not read the commits' text; inspect them with git log")
	}
	out := make([]Commit, len(want))
	for i, id := range want {
		rec := lines[4*i : 4*i+4]
		if !ValidCommitID(id) || rec[0] != id {
			return nil, fmt.Errorf("could not read the commits' text; inspect them with git log")
		}
		out[i] = Commit{ID: id, Author: rec[1], Email: rec[2], Subject: rec[3]}
	}
	return out, nil
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
	for _, rev := range []string{"HEAD", "refs/remotes/" + remote + "/" + to, "refs/heads/" + to} {
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
	for _, rev := range []string{"refs/remotes/" + remote + "/" + to, "refs/heads/" + to, "HEAD"} {
		if c, err := run(ctx, repo, "merge-base", ref, rev); err == nil && ValidCommitID(c) {
			return c
		}
	}
	return ""
}

// SetBranch points refs/heads/branch at ref.
func SetBranch(ctx context.Context, repo, branch, ref string) error {
	if !ValidBranch(branch) {
		return fmt.Errorf("invalid branch %q", branch)
	}
	_, err := run(ctx, repo, append(append([]string{}, noHooks...), "update-ref", "refs/heads/"+branch, ref)...)
	return err
}
