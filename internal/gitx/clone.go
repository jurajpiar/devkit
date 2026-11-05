package gitx

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// allowFileProtocol lets tests clone from a local path. Never set outside
// tests: CloneBare accepts only network transports.
var allowFileProtocol bool

// maxMarker caps a marker file read out of git objects.
const maxMarker = 1 << 20

var (
	bareHostPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}/[A-Za-z0-9._~-][A-Za-z0-9._~/-]*$`)
	safeChars    = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// NormalizeURL turns what a user types into a URL devkit clone accepts:
// https, ssh, or git@host:path. "github.com/org/repo" gains https://, and
// git://, git's old unauthenticated protocol that GitHub no longer serves,
// becomes https:// with a note saying so. Anything else is refused: plain
// http, local paths, file://, and git's command-running transports.
func NormalizeURL(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	bad := func() (string, string, error) {
		return "", "", fmt.Errorf("not a repository URL devkit can clone: %q (use https://, ssh:// or git@host:org/repo)", raw)
	}
	if s == "" || !safeChars.MatchString(s) || strings.HasPrefix(s, "-") {
		return bad()
	}
	note := ""
	if rest, ok := strings.CutPrefix(s, "git://"); ok {
		s = "https://" + rest
		note = "git:// is git's unauthenticated protocol, which GitHub no longer serves; using " + s
	}
	if scpLike.MatchString(s) {
		return s, note, nil
	}
	if bareHostPath.MatchString(s) {
		return "https://" + s, note, nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "ssh") {
		return bad()
	}
	if h := u.Hostname(); h == "" || strings.HasPrefix(h, "-") {
		return bad()
	}
	if p := strings.Trim(u.Path, "/"); p == "" || strings.HasPrefix(p, "-") {
		return bad()
	}
	return s, note, nil
}

// CloneBare clones the tip of branch (default: the remote's default) from
// url into a bare repository at dst. Bare means the project's files are
// never written out on the host, which rules out the checkout-time class
// of git exploits; the VM does the checkout. Only https and ssh are allowed,
// for the clone and anything it is redirected to, and no hooks or
// templates apply. Prompts for credentials reach the terminal as usual.
func CloneBare(ctx context.Context, rawURL, branch, dst string, out io.Writer) error {
	if branch != "" && !ValidBranch(branch) {
		return fmt.Errorf("invalid branch %q", branch)
	}
	args := []string{
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
		"-c", "core.hooksPath=" + os.DevNull,
	}
	if allowFileProtocol {
		args = append(args, "-c", "protocol.file.allow=always")
	}
	args = append(args, "clone", "--bare", "--depth", "1", "--no-tags", "--template=")
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", rawURL, dst)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	return nil
}

// ExtractFiles writes the named top-level files of rev into dst, reading
// them from git objects. Only regular files up to 1 MiB are written, under
// the given names; symlinks, directories, nested paths and missing names
// are skipped. Callers pass a fixed list, never names from the repository.
func ExtractFiles(ctx context.Context, repo, rev string, names []string, dst string) error {
	for _, n := range names {
		if n == "" || n == "." || n == ".." || filepath.Base(n) != n || strings.ContainsAny(n, `/\`) {
			continue
		}
		entry, err := run(ctx, repo, "ls-tree", rev, "--", n)
		if err != nil || entry == "" {
			continue
		}
		meta, name, ok := strings.Cut(entry, "\t")
		f := strings.Fields(meta)
		if !ok || name != n || len(f) != 3 || f[1] != "blob" || (f[0] != "100644" && f[0] != "100755") || !ValidCommitID(f[2]) {
			continue
		}
		size, err := run(ctx, repo, "cat-file", "-s", f[2])
		if n, err2 := strconv.Atoi(size); err != nil || err2 != nil || n > maxMarker {
			continue
		}
		cmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "blob", f[2])
		body, err := cmd.Output()
		if err != nil {
			return err
		}
		fh, err := os.OpenFile(filepath.Join(dst, n), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, werr := fh.Write(body)
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	return nil
}

// HeadBranch is the branch HEAD names in repo, refused unless it is a plain
// branch name (it comes from the remote).
func HeadBranch(ctx context.Context, repo string) (string, error) {
	b, err := run(ctx, repo, "symbolic-ref", "--short", "HEAD")
	if err != nil || !ValidBranch(b) {
		return "", fmt.Errorf("the cloned repository's HEAD is not a usable branch")
	}
	return b, nil
}

// RevParse resolves rev to a commit id.
func RevParse(ctx context.Context, repo, rev string) (string, error) {
	c, err := run(ctx, repo, "rev-parse", "-q", "--verify", rev+"^{commit}")
	if err != nil || !ValidCommitID(c) {
		return "", fmt.Errorf("%s: no such commit", rev)
	}
	return c, nil
}

// FetchBare updates branch in a bare copy from its origin, with the same
// transport limits as CloneBare and no hooks.
func FetchBare(ctx context.Context, repo, branch string, out io.Writer) error {
	if !ValidBranch(branch) {
		return fmt.Errorf("invalid branch %q", branch)
	}
	args := []string{"-C", repo,
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
		"-c", "core.hooksPath=" + os.DevNull,
	}
	if allowFileProtocol {
		args = append(args, "-c", "protocol.file.allow=always")
	}
	args = append(args, "fetch", "-q", "--no-tags", "--no-write-fetch-head", "origin", "+refs/heads/"+branch+":refs/heads/"+branch)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git fetch: %w", err)
	}
	return nil
}

// BundleRange writes a bundle of ref without the commits reachable from
// exclude.
func BundleRange(ctx context.Context, repo, ref, exclude, out string) error {
	if !ValidCommitID(exclude) {
		return fmt.Errorf("invalid commit %q", exclude)
	}
	_, err := run(ctx, repo, "bundle", "create", "-q", out, ref, "^"+exclude)
	return err
}
