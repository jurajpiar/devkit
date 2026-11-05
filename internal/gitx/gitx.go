// Package gitx moves git state across the VM boundary without moving
// anything that does not belong there. Going in, the VM gets what a fresh
// clone would: the current commit and branch, no history, hooks, stash,
// tags, other branches or credentials. Coming out, commits travel as a
// bundle whose every object is checked before the host stores it, under a
// ref namespace that no checkout uses.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Snapshot is a fresh repository holding only the host's current commit.
type Snapshot struct {
	// Dir is a temporary directory whose only entry is .git.
	Dir string
	// Branch is the checked-out branch, empty when HEAD is detached.
	Branch string
	// Head is the commit, empty in a repository with no commits yet.
	Head string
}

// Close removes the snapshot's directory.
func (s *Snapshot) Close() error { return os.RemoveAll(s.Dir) }

// TakeSnapshot builds a Snapshot of the repository whose top level is src.
// It returns nil, nil when src is not the top level of a work tree: a plain
// directory, or a subdirectory whose .git would describe files that were
// never copied.
func TakeSnapshot(ctx context.Context, src string) (*Snapshot, error) {
	// A bare repository (devkit clone's host copy) is its own top level.
	topArg := "--show-toplevel"
	if bare, _ := run(ctx, src, "rev-parse", "--is-bare-repository"); bare == "true" {
		topArg = "--absolute-git-dir"
	}
	top, err := run(ctx, src, "rev-parse", topArg)
	if err != nil || !sameDir(top, src) {
		return nil, nil
	}
	branch, _ := run(ctx, top, "symbolic-ref", "--short", "-q", "HEAD")
	head, _ := run(ctx, top, "rev-parse", "-q", "--verify", "HEAD^{commit}")

	dir, err := os.MkdirTemp("", "devkit-git-")
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Dir: dir, Branch: branch, Head: head}
	fail := func(err error) (*Snapshot, error) {
		_ = s.Close()
		return nil, err
	}
	initBranch := branch
	if initBranch == "" {
		initBranch = "main"
	}
	// The snapshot must hash objects as the source does.
	format, err := run(ctx, top, "rev-parse", "--show-object-format")
	if err != nil || (format != "sha1" && format != "sha256") {
		return fail(fmt.Errorf("unknown object format %q", format))
	}
	// No template: no sample hooks, no info/exclude from the host's git.
	if _, err := run(ctx, dir, "-c", "init.templateDir=", "init", "-q", "--object-format="+format, "-b", initBranch); err != nil {
		return fail(err)
	}
	// The VM's filesystem is case-sensitive and not HFS+; the host's
	// defaults for these would make git misreport changes there.
	for _, k := range []string{"core.ignorecase", "core.precomposeunicode"} {
		_, _ = run(ctx, dir, "config", "--unset", k)
	}
	if head != "" {
		if _, err := run(ctx, dir, "fetch", "-q", "--depth", "1", "--no-tags", "--no-write-fetch-head", "file://"+top, head); err != nil {
			return fail(fmt.Errorf("snapshot %s: %w", head, err))
		}
		if branch != "" {
			_, err = run(ctx, dir, "update-ref", "refs/heads/"+branch, head)
		} else {
			_, err = run(ctx, dir, "update-ref", "--no-deref", "HEAD", head)
		}
		if err != nil {
			return fail(err)
		}
	}
	remote := "origin"
	if branch != "" {
		if r, _ := run(ctx, top, "config", "--get", "branch."+branch+".remote"); r != "" && r != "." {
			remote = r
		}
	}
	raw, _ := run(ctx, top, "config", "--get", "remote."+remote+".url")
	if u := SanitizeURL(raw); u != "" {
		for _, kv := range [][2]string{
			{"remote.origin.url", u},
			{"remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"},
		} {
			if _, err := run(ctx, dir, "config", kv[0], kv[1]); err != nil {
				return fail(err)
			}
		}
	}
	return s, nil
}

// scpLike is git's user@host:path form. Neither host nor path may start
// with "-", which ssh would read as an option.
var scpLike = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9][A-Za-z0-9.-]*:[A-Za-z0-9._~][A-Za-z0-9._~/-]*$`)

// SanitizeURL returns a remote URL with any password or token removed, or
// "" for anything that is not a network remote (local paths, file://, and
// git's command-running ext:: transport).
func SanitizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if scpLike.MatchString(raw) {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "https", "http":
		u.User = nil
	case "ssh":
		if u.User != nil {
			u.User = url.User(u.User.Username())
		}
	default:
		return ""
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String()
}

func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && filepath.Clean(ra) == filepath.Clean(rb)
}

// run runs git in dir and returns its trimmed standard output.
func run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}
