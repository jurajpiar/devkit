package gitx

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// A copied project reaches the VM as snapshots: the Mac records its
// directory, exactly as tar would send it, as one parentless commit in a
// private repository, and the VM applies the difference between the last
// snapshot it took and the new one with git's two-tree merge. A file only
// the VM changed is kept, one only the Mac changed is updated or deleted,
// and one both changed stops the whole sync with nothing applied.
//
// Neither side ever uses the project's own repository, and git on both runs
// with no configuration but its own, no hooks and, in the VM, attributes
// that switch off every conversion: the project's files are only data.

// CopySyncedRef names, in both private repositories, the snapshot the VM
// last applied.
const CopySyncedRef = "refs/devkit/synced"

// CopySyncRepoDir is the name of the Mac's private repository, in
// devkit's state directory for the VM (never in the project).
const CopySyncRepoDir = "sync.git"

// copyPending is where a snapshot waits until the VM has applied it.
const copyPending = "refs/devkit/pending/"

// copyManifestFile, inside the Mac's private repository, is the manifest of
// the snapshot at CopySyncedRef: what git cannot carry, needed to tell the
// VM which directories went away and which modes went back to git's.
const copyManifestFile = "devkit-synced.manifest"

// Exit codes of the VM's sync script besides 0.
const (
	ExitCopyConflict = 3
	ExitCopyRefused  = 4
)

//go:embed copysync.sh
var copySyncScript string

// CopySyncScript is the shell script the VM runs to apply a snapshot. It is
// exported so tests can run it as it is, against a temporary HOME.
func CopySyncScript() string { return copySyncScript }

var sha1ID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// copyEnv is the environment of every git command on either side of a copy
// sync: none of the user's configuration, none of the caller's GIT_
// variables, and a fixed identity, so nothing leaks into a snapshot and the
// same directory always gives the same commit.
func copyEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "LC_ALL=") {
			env = append(env, kv)
		}
	}
	return append(env,
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C",
		"GIT_AUTHOR_NAME=devkit", "GIT_AUTHOR_EMAIL=devkit@localhost", "GIT_AUTHOR_DATE=@0 +0000",
		"GIT_COMMITTER_NAME=devkit", "GIT_COMMITTER_EMAIL=devkit@localhost", "GIT_COMMITTER_DATE=@0 +0000",
	)
}

// CopyRepo is the Mac's private repository for a copied project.
type CopyRepo struct {
	Dir string
}

// OpenCopyRepo opens, creating if needed, the private repository at dir.
// dir must be outside the project, in devkit's own state for the VM:
// pruning there deletes objects, so a project must not be able to supply
// the repository or anything in it. dir and its parent may not be
// symlinks.
func OpenCopyRepo(ctx context.Context, dir string) (*CopyRepo, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{filepath.Dir(dir), dir} {
		if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing %s for devkit's sync snapshots: it is a symlink", p)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	r := &CopyRepo{Dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		// No template: no sample hooks or info/exclude from the Mac's git.
		init := exec.CommandContext(ctx, "git", "-c", "init.templateDir=", "init", "-q", "--bare", "--object-format=sha1", "--", dir)
		init.Env = copyEnv()
		if out, err := init.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("create %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
		}
	}
	// The config is devkit's alone, whatever an older devkit or a user
	// left there.
	if err := writeFileAtomic(filepath.Join(dir, "config"), []byte(copyRepoConfig)); err != nil {
		return nil, err
	}
	return r, nil
}

// ErrCopySyncRunning is LockCopyRepo's answer while another sync of the
// same project holds the lock.
var ErrCopySyncRunning = errors.New("another devkit sync of this project is running; try again once it has finished")

// LockCopyRepo takes the lock of the private repository at dir, without
// waiting, for the whole of a sync: two syncs at once would each prune the
// other's snapshot. The lock is a file beside the repository, released by
// the returned function or when the process ends.
func LockCopyRepo(dir string) (func(), error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if st, err := os.Lstat(filepath.Dir(dir)); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing %s for devkit's sync snapshots: it is a symlink", filepath.Dir(dir))
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(dir+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrCopySyncRunning
		}
		return nil, fmt.Errorf("lock %s: %w", dir+".lock", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// copyRepoConfig is the whole config of the Mac's private repository.
// Snapshots are packed by fast-import and pruned after every sync, so git
// must not start its own maintenance in the background.
const copyRepoConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = true
[gc]
	auto = 0
`

// git runs git on the private repository with copyEnv and no hooks.
func (r *CopyRepo) git(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	var out bytes.Buffer
	if err := r.gitTo(ctx, stdin, &out, args...); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func (r *CopyRepo) gitTo(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	cmd := r.command(ctx, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func (r *CopyRepo) command(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{"--git-dir=" + r.Dir, "-c", "core.hooksPath=" + os.DevNull}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = copyEnv()
	return cmd
}

// Skipped is an entry of the directory that a snapshot cannot carry.
type Skipped struct {
	Path string
	Why  string
}

// CopySnapshot is one snapshot of the directory, kept under a pending ref
// until Record or Discard.
type CopySnapshot struct {
	Commit   string
	Manifest *Manifest
	Skipped  []Skipped
	ref      string
}

// Manifest is what git cannot carry: the directories, empty ones included,
// with their modes, and the modes of files other than git's two. Modes are
// already what the VM applies: as a tar extraction under umask 022 would
// leave them, without setuid, setgid or sticky bits, and directories always
// writable by their owner so the next sync can write into them.
type Manifest struct {
	Dirs  map[string]uint32
	Modes map[string]uint32
	// exec records every regular file's git mode, to know what a file
	// whose odd mode went away goes back to. Not stored.
	exec map[string]bool
}

func newManifest() *Manifest {
	return &Manifest{Dirs: map[string]uint32{}, Modes: map[string]uint32{}, exec: map[string]bool{}}
}

// Snapshot reads a tar stream of the directory and writes it into the
// private repository as one commit, with git fast-import. Each file's bytes
// go to git as they are on disk: no attributes, filters or line-ending
// conversion apply. Entries git cannot hold are listed in Skipped.
func (r *CopyRepo) Snapshot(ctx context.Context, archive io.Reader) (*CopySnapshot, error) {
	snap := &CopySnapshot{Manifest: newManifest(), ref: copyPending + randomHex()}
	cmd := r.command(ctx, "fast-import", "--quiet", "--done", "--date-format=raw")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(stdin, 1<<16)
	werr := snap.write(w, archive)
	if werr == nil {
		werr = w.Flush()
	}
	_ = stdin.Close()
	if werr != nil {
		// Without "done", fast-import refuses the stream: no ref is made.
		_ = cmd.Wait()
		return nil, werr
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git fast-import: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	if snap.Commit, err = r.git(ctx, nil, "rev-parse", "--verify", "-q", snap.ref+"^{commit}"); err != nil {
		return nil, err
	}
	return snap, nil
}

// write turns the archive into a fast-import stream: one commit whose files
// are given inline, in the order tar sends them.
func (snap *CopySnapshot) write(w *bufio.Writer, archive io.Reader) error {
	msg := "devkit snapshot\n"
	fmt.Fprintf(w, "commit %s\nauthor devkit <devkit@localhost> 0 +0000\ncommitter devkit <devkit@localhost> 0 +0000\ndata %d\n%s", snap.ref, len(msg), msg)
	m := snap.Manifest
	tr := tar.NewReader(archive)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read the archive of the directory: %w", err)
		}
		p, ok := tarPath(h.Name)
		switch {
		case !ok:
			snap.Skipped = append(snap.Skipped, Skipped{h.Name, "not a plain relative path"})
			continue
		case p == "":
			continue
		case p == ".devkit" || strings.HasPrefix(p, ".devkit/"):
			// devkit's own state, the private repository included, even
			// when the project's exclude list leaves it out.
			continue
		case hasGitComponent(p):
			// git never writes a .git into a work tree; the project's
			// repository reaches the VM separately, as a fresh clone.
			snap.Skipped = append(snap.Skipped, Skipped{p, "a .git path; git cannot carry it"})
			continue
		}
		perm := uint32(h.Mode) & 0o777 &^ 0o022
		switch h.Typeflag {
		case tar.TypeDir:
			m.Dirs[p] = perm | 0o700
		case tar.TypeReg, tar.TypeLink:
			if h.Typeflag == tar.TypeLink && h.Size == 0 {
				// tar sends a second name of a file as a link to the
				// first; the VM gets a second copy, as extracting did.
				src, ok := tarPath(h.Linkname)
				if _, seen := m.exec[src]; !ok || !seen {
					snap.Skipped = append(snap.Skipped, Skipped{p, "a hard link to a file not sent"})
					continue
				}
				fmt.Fprintf(w, "C %s %s\n", fastImportPath(src), fastImportPath(p))
				m.exec[p] = m.exec[src]
				if mode, ok := m.Modes[src]; ok {
					m.Modes[p] = mode
				}
				continue
			}
			exec := h.Mode&0o100 != 0
			mode, def := "100644", uint32(0o644)
			if exec {
				mode, def = "100755", 0o755
			}
			fmt.Fprintf(w, "M %s inline %s\ndata %d\n", mode, fastImportPath(p), h.Size)
			if n, err := io.CopyN(w, tr, h.Size); err != nil {
				return fmt.Errorf("read %s from the archive after %d bytes: %w", p, n, err)
			}
			w.WriteByte('\n')
			m.exec[p] = exec
			if perm != def {
				m.Modes[p] = perm
			}
		case tar.TypeSymlink:
			fmt.Fprintf(w, "M 120000 inline %s\ndata %d\n%s\n", fastImportPath(p), len(h.Linkname), h.Linkname)
		case tar.TypeFifo:
			snap.Skipped = append(snap.Skipped, Skipped{p, "a named pipe"})
		case tar.TypeChar, tar.TypeBlock:
			snap.Skipped = append(snap.Skipped, Skipped{p, "a device file"})
		default:
			snap.Skipped = append(snap.Skipped, Skipped{p, fmt.Sprintf("an entry of tar type %q", h.Typeflag)})
		}
	}
	_, err := w.WriteString("\ndone\n")
	return err
}

// tarPath turns a name in tar's archive of "." into a path relative to the
// directory: "" for the directory itself, false for anything that is not a
// plain relative path.
func tarPath(name string) (string, bool) {
	p := strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")
	if p == "." || p == "" {
		return "", true
	}
	if strings.HasPrefix(p, "/") {
		return "", false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return p, true
}

func hasGitComponent(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if strings.EqualFold(part, ".git") {
			return true
		}
	}
	return false
}

// fastImportPath quotes a path for fast-import, always: C-style, with
// every byte outside printable ASCII in octal, so a name with spaces,
// quotes, a newline or bytes that are not UTF-8 arrives unchanged.
func fastImportPath(p string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Encode writes the manifest the VM applies after the merge, given the one
// the VM had (nil when unknown): directories that went away, deepest first,
// to be removed when empty; every directory, parents first, to be made and
// given its mode; and files whose mode is not git's, including files whose
// odd mode went away and go back to git's. Records end with NUL, as a path
// may hold any other byte; each is a kind, four octal digits and a space.
func (m *Manifest) Encode(prev *Manifest) []byte {
	var b bytes.Buffer
	rec := func(kind byte, mode uint32, p string) {
		fmt.Fprintf(&b, "%c%04o %s\x00", kind, mode, p)
	}
	if prev != nil {
		gone := []string{}
		for p := range prev.Dirs {
			if _, ok := m.Dirs[p]; !ok {
				gone = append(gone, p)
			}
		}
		// A directory sorts before everything inside it.
		sort.Sort(sort.Reverse(sort.StringSlice(gone)))
		for _, p := range gone {
			rec('r', 0, p)
		}
	}
	for _, p := range sortedKeys(m.Dirs) {
		rec('d', m.Dirs[p], p)
	}
	modes := map[string]uint32{}
	if prev != nil {
		for p := range prev.Modes {
			if exec, ok := m.exec[p]; ok {
				modes[p] = 0o644
				if exec {
					modes[p] = 0o755
				}
			}
		}
	}
	for p, mode := range m.Modes {
		modes[p] = mode
	}
	for _, p := range sortedKeys(modes) {
		rec('f', modes[p], p)
	}
	return b.Bytes()
}

// parseManifest reads what Encode(nil) wrote.
func parseManifest(data []byte) *Manifest {
	m := newManifest()
	for _, r := range bytes.Split(data, []byte{0}) {
		if len(r) < 7 || r[5] != ' ' {
			continue
		}
		var mode uint32
		if _, err := fmt.Sscanf(string(r[1:5]), "%o", &mode); err != nil {
			continue
		}
		switch p := string(r[6:]); r[0] {
		case 'd':
			m.Dirs[p] = mode
		case 'f':
			m.Modes[p] = mode
		}
	}
	return m
}

func sortedKeys(m map[string]uint32) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Base checks the VM's answer to "which snapshot do you have": the VM is
// untrusted, so it counts only as a full commit id of a snapshot this Mac
// holds, whole. Anything else returns "", and the VM is sent everything.
func (r *CopyRepo) Base(ctx context.Context, answer string) string {
	lines := strings.Split(strings.TrimSpace(answer), "\n")
	c := strings.TrimSpace(lines[len(lines)-1])
	if !sha1ID.MatchString(c) {
		return ""
	}
	if t, err := r.git(ctx, nil, "cat-file", "-t", c); err != nil || t != "commit" {
		return ""
	}
	// Every snapshot is a root commit by devkit.
	if parents, err := r.git(ctx, nil, "rev-list", "--parents", "-n", "1", c); err != nil || parents != c {
		return ""
	}
	if err := r.gitTo(ctx, nil, io.Discard, "rev-list", "--objects", c); err != nil {
		return ""
	}
	return c
}

// SyncedManifest is the manifest of base when base is the snapshot this
// Mac recorded as the VM's; otherwise nil.
func (r *CopyRepo) SyncedManifest(ctx context.Context, base string) *Manifest {
	if base == "" {
		return nil
	}
	if cur, err := r.git(ctx, nil, "rev-parse", "-q", "--verify", CopySyncedRef+"^{commit}"); err != nil || cur != base {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(r.Dir, copyManifestFile))
	if err != nil {
		return nil
	}
	return parseManifest(data)
}

// WritePack writes to w a pack of the objects of commit that base does not
// have, and returns how many there are. Snapshots share no history, so the
// objects are listed rather than left to revision ranges, which would
// exclude nothing. base "" sends everything. With nothing to send, nothing
// is written.
func (r *CopyRepo) WritePack(ctx context.Context, commit, base string, w io.Writer) (int, error) {
	have := map[string]bool{}
	if base != "" {
		var out bytes.Buffer
		if err := r.gitTo(ctx, nil, &out, "rev-list", "--objects", base); err != nil {
			return 0, err
		}
		for _, l := range strings.Split(out.String(), "\n") {
			if len(l) >= 40 {
				have[l[:40]] = true
			}
		}
	}
	var all bytes.Buffer
	if err := r.gitTo(ctx, nil, &all, "rev-list", "--objects", commit); err != nil {
		return 0, err
	}
	// Each line keeps its path: pack-objects uses it to find deltas.
	var want bytes.Buffer
	n := 0
	for _, l := range strings.Split(all.String(), "\n") {
		if len(l) >= 40 && !have[l[:40]] {
			want.WriteString(l)
			want.WriteByte('\n')
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := r.gitTo(ctx, &want, w, "pack-objects", "-q", "--stdout"); err != nil {
		return 0, err
	}
	return n, nil
}

// Record makes snap the VM's snapshot once the VM has applied it, and
// keeps nothing else: the previous snapshot and every pending one go, and
// so do their objects, so the repository holds about one compressed copy
// of the directory.
func (r *CopyRepo) Record(ctx context.Context, snap *CopySnapshot) error {
	if err := writeFileAtomic(filepath.Join(r.Dir, copyManifestFile), snap.Manifest.Encode(nil)); err != nil {
		return err
	}
	if _, err := r.git(ctx, nil, "update-ref", CopySyncedRef, snap.Commit); err != nil {
		return err
	}
	refs, _ := r.git(ctx, nil, "for-each-ref", "--format=%(refname)", copyPending)
	for _, ref := range strings.Fields(refs) {
		_, _ = r.git(ctx, nil, "update-ref", "-d", ref)
	}
	packs, _ := filepath.Glob(filepath.Join(r.Dir, "objects", "pack", "*.pack"))
	if len(packs) > 1 {
		if _, err := r.git(ctx, nil, "repack", "-a", "-d", "-q"); err != nil {
			return err
		}
	}
	_, err := r.git(ctx, nil, "prune", "--expire=now")
	return err
}

// Discard drops snap's pending ref; its objects go with the next Record.
// The record of what the VM has is unchanged.
func (r *CopyRepo) Discard(ctx context.Context, snap *CopySnapshot) {
	_, _ = r.git(ctx, nil, "update-ref", "-d", snap.ref)
}

// CopySyncedQuery is the command that prints the snapshot the VM last
// applied to ws, when the VM still has all of it and the workspace exists.
// ws is a shell word expanded inside double quotes, such as
// "$HOME/workspace", and must come from devkit.
func CopySyncedQuery(ws string) string {
	return fmt.Sprintf(`r="$HOME/.local/state/devkit/sync.git"
[ -d "%s" ] && [ -f "$r/HEAD" ] || exit 0
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
unset GIT_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
c=$(git --git-dir="$r" rev-parse -q --verify %s^{commit} 2>/dev/null) &&
  git --git-dir="$r" rev-list --objects "$c" >/dev/null 2>&1 && echo "$c"
exit 0`, ws, CopySyncedRef)
}

// CopySyncCommand is the command that runs the sync script in the VM. ws is
// as for CopySyncedQuery; pack is "" when the VM has every object already.
func CopySyncCommand(ws, pack, manifest, commit string, overwrite bool) string {
	o := "0"
	if overwrite {
		o = "1"
	}
	return fmt.Sprintf(`bash -c %s devkit-sync "%s" %s %s %s %s; echo devkit-exit=$?`,
		shq(copySyncScript), ws, shq(pack), shq(manifest), shq(commit), o)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CopyGuest is the VM, as a copy sync reaches it.
type CopyGuest interface {
	// Exec runs a bash command as the sandbox user and returns its
	// standard output, also when it fails.
	Exec(ctx context.Context, command string) (string, error)
	// Put copies a local file into the VM under a name of the guest's
	// choosing and returns its path there.
	Put(ctx context.Context, local, name string) (string, error)
}

// CopyResult is what the VM made of a snapshot. Paths are as git prints
// them, C-quoted where needed, and come from the VM: show them only
// through a sanitiser.
type CopyResult struct {
	// Synced is set when the VM applied the snapshot.
	Synced bool
	// Conflicts are the files changed in the VM that the snapshot also
	// changes; the VM applied nothing.
	Conflicts []string
	// Refused is git's account of what in the VM is in the way of the
	// snapshot, such as a directory where it has a file; the VM applied
	// nothing.
	Refused []string
	// Kept are the files that differ in the VM from the snapshot after
	// it was applied: the VM's own changes.
	Kept []string
	// Skipped are manifest entries the VM left alone.
	Skipped []string
}

// DeliverCopy hands snap to the VM: it asks which snapshot the VM has,
// sends the objects it lacks and the manifest, and has the VM apply them
// to ws. Only when the VM confirms is snap recorded as the VM's; otherwise
// the Mac's record stays as it was. A conflict or a refusal is a result,
// not an error.
func DeliverCopy(ctx context.Context, repo *CopyRepo, snap *CopySnapshot, guest CopyGuest, ws string, overwrite bool) (*CopyResult, error) {
	recorded := false
	defer func() {
		if !recorded {
			repo.Discard(context.Background(), snap)
		}
	}()
	answer, _ := guest.Exec(ctx, CopySyncedQuery(ws))
	base := repo.Base(ctx, answer)

	tmp, err := os.MkdirTemp("", "devkit-copysync-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	id := randomHex()
	packPath := filepath.Join(tmp, "sync.pack")
	f, err := os.OpenFile(packPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	n, err := repo.WritePack(ctx, snap.Commit, base, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(tmp, "sync.manifest")
	if err := os.WriteFile(manifestPath, snap.Manifest.Encode(repo.SyncedManifest(ctx, base)), 0o600); err != nil {
		return nil, err
	}
	guestPack := ""
	if n > 0 {
		if guestPack, err = guest.Put(ctx, packPath, "devkit-sync-"+id+".pack"); err != nil {
			return nil, fmt.Errorf("copy the snapshot into the VM: %w", err)
		}
	}
	guestManifest, err := guest.Put(ctx, manifestPath, "devkit-sync-"+id+".manifest")
	if err != nil {
		return nil, fmt.Errorf("copy the snapshot into the VM: %w", err)
	}
	out, execErr := guest.Exec(ctx, CopySyncCommand(ws, guestPack, guestManifest, snap.Commit, overwrite))
	res := &CopyResult{}
	var errs []string
	exit := ""
	for _, l := range strings.Split(out, "\n") {
		kind, rest, _ := strings.Cut(l, " ")
		switch kind {
		case "devkit-conflict":
			res.Conflicts = append(res.Conflicts, rest)
		case "devkit-kept":
			res.Kept = append(res.Kept, rest)
		case "devkit-skip":
			res.Skipped = append(res.Skipped, rest)
		case "devkit-refused":
			res.Refused = append(res.Refused, rest)
		case "devkit-error":
			errs = append(errs, rest)
		case "devkit-synced":
			res.Synced = rest == snap.Commit
		default:
			if v, ok := strings.CutPrefix(l, "devkit-exit="); ok {
				exit = v
			}
		}
	}
	switch {
	case exit == "0" && res.Synced:
		if err := repo.Record(ctx, snap); err != nil {
			return res, fmt.Errorf("the VM has the new snapshot, but this Mac could not record it (the next sync works it out): %w", err)
		}
		recorded = true
		return res, nil
	case exit == fmt.Sprint(ExitCopyConflict) && len(res.Conflicts) > 0,
		exit == fmt.Sprint(ExitCopyRefused) && len(res.Refused) > 0:
		res.Synced = false
		return res, nil
	case len(errs) > 0:
		return nil, fmt.Errorf("the VM could not apply the snapshot: %s", strings.Join(errs, "\n"))
	case execErr != nil:
		return nil, fmt.Errorf("sync in the VM: %w", execErr)
	default:
		return nil, fmt.Errorf("the VM did not confirm the sync (exit %q)", exit)
	}
}

// SnapshotOf runs tarCmd, which writes an archive of the directory to its
// standard output, and takes the snapshot from it. tar decides which files
// are in it, as it did when the archive itself went to the VM.
func (r *CopyRepo) SnapshotOf(ctx context.Context, tarCmd *exec.Cmd) (*CopySnapshot, error) {
	out, err := tarCmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errb bytes.Buffer
	tarCmd.Stderr = &errb
	if err := tarCmd.Start(); err != nil {
		return nil, fmt.Errorf("start tar: %w", err)
	}
	snap, err := r.Snapshot(ctx, out)
	if err != nil {
		// Unblock tar if the snapshot stopped reading early.
		_, _ = io.Copy(io.Discard, out)
	}
	if werr := tarCmd.Wait(); werr != nil {
		if snap != nil {
			r.Discard(context.Background(), snap)
		}
		return nil, fmt.Errorf("tar: %w: %s", werr, strings.TrimSpace(errb.String()))
	}
	return snap, err
}
