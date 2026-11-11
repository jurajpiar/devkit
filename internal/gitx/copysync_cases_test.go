package gitx

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jurajpiar/devkit/internal/lima"
)

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	must(t, os.Chmod(path, mode))
}

func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	must(t, err)
	return st.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// treePaths lists every path in commit's tree, as raw bytes.
func (f *copyFixture) treePaths(commit string) []string {
	f.t.Helper()
	out, err := f.repo.git(context.Background(), nil, "ls-tree", "-r", "-z", "--name-only", commit)
	must(f.t, err)
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths
}

// tarEntries reads tar's own archive of dir, as devkit asks for it, and
// returns what it holds: files and symlinks, and directories.
func tarEntries(t *testing.T, dir string, excludes []string) (files, dirs []string) {
	t.Helper()
	cmd := lima.TarCommand(context.Background(), dir, excludes)
	out, err := cmd.Output()
	must(t, err)
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		must(t, err)
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		switch {
		case name == "" || name == ".":
		case h.Typeflag == tar.TypeDir:
			dirs = append(dirs, name)
		case h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeLink || h.Typeflag == tar.TypeSymlink:
			files = append(files, name)
		}
	}
	sort.Strings(files)
	sort.Strings(dirs)
	return files, dirs
}

func TestCopySnapshotIsWhatTarSends(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	for _, p := range []string{
		"a.txt", "with space.txt", "-leading-dash", `quo"te'.txt`, "new\nline.txt", "src/deep/er/f.go",
		"lib/nested/f.txt", "run.sh", "key", "group", "world", "setuid", "private/inside",
		// Every default exclude, at the top and further down.
		"node_modules/x", ".next/x", "dist/x", "build/x", ".cache/x", "target/x", ".venv/x",
		"__pycache__/x.pyc", "vendor/x", ".DS_Store", "._foo", "debug.log", "devkit.yaml",
		"src/dist/y", "src/node_modules/z", "src/x.log", "src/._bar",
	} {
		put(t, m(p), "content of "+p+"\n")
	}
	gitT(t, f.mac, "init", "-q")
	gitT(t, m("lib/nested"), "init", "-q")
	chmod(t, m("run.sh"), 0o755)
	chmod(t, m("key"), 0o600)
	chmod(t, m("group"), 0o640)
	chmod(t, m("world"), 0o666)
	chmod(t, m("setuid"), 0o4755)
	chmod(t, m("private"), 0o700)
	must(t, os.MkdirAll(m("empty/inner"), 0o755))
	must(t, os.Symlink("a.txt", m("link")))
	must(t, os.Symlink("no/such/target", m("dangling")))
	must(t, os.Link(m("a.txt"), m("hard")))
	must(t, syscall.Mkfifo(m("pipe"), 0o644))
	if err := os.WriteFile(m("bad\xff\xfe.txt"), []byte("x"), 0o644); err != nil {
		t.Logf("this filesystem refuses a name that is not UTF-8 (%v); TestCopySnapshotOfHostileTarNames covers it", err)
	}

	snap := f.snapshot()
	files, dirs := tarEntries(t, f.mac, f.excludes)
	if got := f.treePaths(snap.Commit); strings.Join(got, "\x00") != strings.Join(files, "\x00") {
		t.Errorf("the snapshot's files differ from tar's:\n snapshot %q\n tar      %q", got, files)
	}
	gotDirs := sortedKeys(snap.Manifest.Dirs)
	if strings.Join(gotDirs, "\x00") != strings.Join(dirs, "\x00") {
		t.Errorf("the snapshot's directories differ from tar's:\n snapshot %q\n tar      %q", gotDirs, dirs)
	}
	for _, p := range files {
		if strings.HasPrefix(p, ".devkit") || strings.Contains(p, ".git/") || strings.Contains(p, "node_modules") {
			t.Errorf("excluded path in the snapshot: %q", p)
		}
	}
	if len(snap.Skipped) != 1 || snap.Skipped[0].Path != "pipe" {
		t.Errorf("the named pipe must be reported, and only it: %+v", snap.Skipped)
	}
	ls := func(p string) string {
		out, err := f.repo.git(context.Background(), nil, "ls-tree", snap.Commit, "--", p)
		must(t, err)
		return out
	}
	blob := func(p string) string {
		out, err := f.repo.git(context.Background(), nil, "cat-file", "blob", snap.Commit+":"+p)
		must(t, err)
		return out
	}
	for p, mode := range map[string]string{"run.sh": "100755", "setuid": "100755", "a.txt": "100644", "hard": "100644", "link": "120000", "dangling": "120000"} {
		if !strings.HasPrefix(ls(p), mode+" ") {
			t.Errorf("%s: %s, want mode %s", p, ls(p), mode)
		}
	}
	if blob("hard") != strings.TrimSpace("content of a.txt") || blob("link") != "a.txt" || blob("dangling") != "no/such/target" {
		t.Errorf("hard link or symlink content wrong: %q %q %q", blob("hard"), blob("link"), blob("dangling"))
	}
	wantModes := map[string]uint32{"key": 0o600, "group": 0o640}
	if fmt.Sprint(snap.Manifest.Modes) != fmt.Sprint(wantModes) {
		t.Errorf("odd modes = %v, want %v (0666 and setuid fall to git's own)", snap.Manifest.Modes, wantModes)
	}
	if snap.Manifest.Dirs["private"] != 0o700 || snap.Manifest.Dirs["empty/inner"] != 0o755 {
		t.Errorf("directory modes: %v", snap.Manifest.Dirs)
	}

	// And in the VM: the same files, a second copy for the hard link, the
	// modes, empty directories, no setuid, no pipe.
	res := f.mustSync()
	if len(res.Kept) != 0 || len(res.Skipped) != 0 {
		t.Errorf("a first sync keeps or skips nothing: %+v", res)
	}
	content := func(p string) string {
		if target, err := os.Readlink(p); err == nil {
			return "symlink to " + target
		}
		return read(t, p)
	}
	for _, p := range files {
		if a, b := content(m(p)), content(f.vm.ws(p)); a != b {
			t.Errorf("%q differs in the VM: %q vs %q", p, b, a)
		}
	}
	for p, want := range map[string]os.FileMode{"key": 0o600, "group": 0o640, "world": 0o644, "setuid": 0o755, "run.sh": 0o755, "private": os.ModeDir | 0o700, "empty/inner": os.ModeDir | 0o755} {
		st, err := os.Lstat(f.vm.ws(p))
		must(t, err)
		if got := st.Mode() & (os.ModeDir | os.ModePerm | os.ModeSetuid); got != want {
			t.Errorf("%s in the VM: %v, want %v", p, got, want)
		}
	}
	if target, err := os.Readlink(f.vm.ws("dangling")); err != nil || target != "no/such/target" {
		t.Errorf("dangling symlink: %q %v", target, err)
	}
	if exists(f.vm.ws("pipe")) || exists(f.vm.ws("lib/nested/.git")) || exists(f.vm.ws(".git")) {
		t.Error("no pipe, and no .git of either repository, arrives")
	}
}

// Names a filesystem may refuse, straight from a tar stream.
func TestCopySnapshotOfHostileTarNames(t *testing.T) {
	f := newCopyFixture(t)
	names := []string{"bad\xff\xfe.txt", "new\nline", "tab\there", `"q"`, `back\slash`, "-dash", "sp ace", "ü-nfc", "\x01ctl"}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	must(t, tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX}))
	for _, n := range names {
		must(t, tw.WriteHeader(&tar.Header{Name: "./" + n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(n)), Format: tar.FormatPAX}))
		_, err := tw.Write([]byte(n))
		must(t, err)
	}
	must(t, tw.WriteHeader(&tar.Header{Name: "./link\xff", Typeflag: tar.TypeSymlink, Linkname: "bad\xff\xfe.txt", Format: tar.FormatPAX}))
	must(t, tw.WriteHeader(&tar.Header{Name: "./hard\nlink", Typeflag: tar.TypeLink, Linkname: "./new\nline", Format: tar.FormatPAX}))
	must(t, tw.Close())

	archive := append([]byte(nil), b.Bytes()...)
	snap, err := f.repo.Snapshot(context.Background(), &b)
	must(t, err)
	want := append(append([]string{}, names...), "link\xff", "hard\nlink")
	sort.Strings(want)
	if got := f.treePaths(snap.Commit); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("paths changed on the way in:\n got  %q\n want %q", got, want)
	}
	for _, n := range names {
		out, err := f.repo.git(context.Background(), nil, "cat-file", "blob", snap.Commit+":"+n)
		if err != nil || out != strings.TrimSpace(n) {
			t.Errorf("%q: %q %v", n, out, err)
		}
	}
	// And through the VM's script, where these are C-quoted. A Mac's
	// filesystem takes only UTF-8 names, so the stand-in VM gets those.
	if err := os.WriteFile(filepath.Join(t.TempDir(), "bad\xff"), nil, 0o644); err != nil {
		f.repo.Discard(context.Background(), snap)
		b.Reset()
		tw = tar.NewWriter(&b)
		for _, n := range names {
			if utf8.ValidString(n) {
				must(t, tw.WriteHeader(&tar.Header{Name: "./" + n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(n)), Format: tar.FormatPAX}))
				_, err := tw.Write([]byte(n))
				must(t, err)
			}
		}
		must(t, tw.WriteHeader(&tar.Header{Name: "./hard\nlink", Typeflag: tar.TypeLink, Linkname: "./new\nline", Format: tar.FormatPAX}))
		must(t, tw.Close())
		archive = append([]byte(nil), b.Bytes()...)
		snap, err = f.repo.Snapshot(context.Background(), &b)
		must(t, err)
	}
	res, err := DeliverCopy(context.Background(), f.repo, snap, f.vm, `$HOME/workspace`, false)
	if err != nil || !res.Synced {
		t.Fatalf("%+v %v", res, err)
	}
	for _, n := range f.treePaths(snap.Commit) {
		want := n
		if n == "hard\nlink" {
			want = "new\nline"
		}
		if got := read(t, f.vm.ws(n)); got != want && !strings.HasPrefix(n, "link") {
			t.Errorf("%q in the VM holds %q", n, got)
		}
	}
	// Nothing is reported as changed: the quoted names match each other.
	if len(res.Kept) != 0 {
		t.Errorf("kept: %q", res.Kept)
	}
	put(t, f.vm.ws("new\nline"), "changed in the VM\n")
	snap, err = f.repo.Snapshot(context.Background(), bytes.NewReader(archive))
	must(t, err)
	res, err = DeliverCopy(context.Background(), f.repo, snap, f.vm, `$HOME/workspace`, false)
	if err != nil || !res.Synced {
		t.Fatalf("%+v %v", res, err)
	}
	if strings.Join(res.Kept, ",") != `"new\nline"` {
		t.Errorf("kept = %q, want the C-quoted name", res.Kept)
	}
}

// hostileGitConfig is a global git config that, if any git command of the
// sync read it, would run a filter or a hook that leaves mark behind.
func hostileGitConfig(t *testing.T, mark string) (config, home string) {
	t.Helper()
	home = t.TempDir()
	hooks := filepath.Join(home, "hooks")
	must(t, os.MkdirAll(hooks, 0o755))
	script := "#!/bin/sh\necho \"hook $0 $PWD\" >> " + shq(mark) + "\n"
	for _, h := range []string{"reference-transaction", "post-checkout", "post-index-change", "pre-auto-gc"} {
		must(t, os.WriteFile(filepath.Join(hooks, h), []byte(script), 0o755))
	}
	cfg := fmt.Sprintf(`[filter "evil"]
	clean = sh -c 'echo clean >> %[1]s; tr a-z A-Z'
	smudge = sh -c 'echo smudge >> %[1]s; tr a-z A-Z'
	required = true
[core]
	hooksPath = %[2]s
	autocrlf = true
	attributesFile = %[3]s
`, shq(mark), hooks, filepath.Join(home, "attributes"))
	must(t, os.WriteFile(filepath.Join(home, "attributes"), []byte("* filter=evil text\n"), 0o644))
	config = filepath.Join(home, ".gitconfig")
	must(t, os.WriteFile(config, []byte(cfg), 0o644))
	return config, home
}

func TestCopySyncCarriesBytesUnconverted(t *testing.T) {
	f := newCopyFixture(t)
	mark := filepath.Join(t.TempDir(), "ran")
	config, home := hostileGitConfig(t, mark)
	// On both sides, git would find this config in HOME and in
	// GIT_CONFIG_GLOBAL.
	t.Setenv("GIT_CONFIG_GLOBAL", config)
	t.Setenv("HOME", home)
	must(t, os.WriteFile(filepath.Join(f.vm.home, ".gitconfig"), []byte(read(t, config)), 0o644))
	f.vm.extraEnv = []string{"GIT_CONFIG_GLOBAL=" + config}

	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m(".gitattributes"), "* text eol=lf\n*.txt filter=evil ident\n")
	put(t, m("win.txt"), "crlf line\r\nsecond\r\n")
	put(t, m("lower.txt"), "lowercase $Id$\n")
	put(t, m("mixed.bin"), "a\r\nb\nc\r")
	f.mustSync()
	put(t, m("lower.txt"), "lowercase, changed $Id$\n")
	res := f.mustSync()

	for _, p := range []string{"win.txt", "lower.txt", "mixed.bin", ".gitattributes"} {
		blob, err := f.repo.git(context.Background(), nil, "cat-file", "blob", f.syncedCommit()+":"+p)
		must(t, err)
		if blob != strings.TrimSpace(read(t, m(p))) {
			t.Errorf("%s: the snapshot holds %q", p, blob)
		}
		if got := read(t, f.vm.ws(p)); got != read(t, m(p)) {
			t.Errorf("%s in the VM is %q, want %q", p, got, read(t, m(p)))
		}
	}
	if len(res.Kept) != 0 {
		t.Errorf("unconverted files must not look changed in the VM: %q", res.Kept)
	}
	if exists(mark) {
		t.Errorf("a filter or hook from the global git config ran: %s", read(t, mark))
	}
}

func (f *copyFixture) syncedCommit() string {
	f.t.Helper()
	c, err := f.repo.git(context.Background(), nil, "rev-parse", "--verify", CopySyncedRef)
	must(f.t, err)
	return c
}

func (f *copyFixture) vmSynced() string {
	f.t.Helper()
	out, _ := f.vm.Exec(context.Background(), CopySyncedQuery(`$HOME/workspace`))
	return strings.TrimSpace(out)
}

func TestCopySyncModesAndDirectories(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m("key"), "k\n")
	put(t, m("a.txt"), "a\n")
	put(t, m("gen/keep"), "x\n")
	chmod(t, m("key"), 0o600)
	must(t, os.MkdirAll(m("empty/inner"), 0o755))
	must(t, os.MkdirAll(m("gone/deeper/still"), 0o755))
	must(t, os.MkdirAll(m("busy"), 0o755))
	f.mustSync()
	if permOf(t, f.vm.ws("key")) != 0o600 || !exists(f.vm.ws("empty/inner")) || !exists(f.vm.ws("gone/deeper/still")) {
		t.Fatal("first sync: modes or empty directories missing")
	}
	put(t, f.vm.ws("busy/vm-made"), "the VM's\n")

	chmod(t, m("key"), 0o644)
	chmod(t, m("a.txt"), 0o755)
	chmod(t, m("gen"), 0o750)
	must(t, os.RemoveAll(m("gone")))
	must(t, os.RemoveAll(m("busy")))
	f.mustSync()
	if got := permOf(t, f.vm.ws("key")); got != 0o644 {
		t.Errorf("a file whose odd mode went away is %v, want 0644", got)
	}
	if got := permOf(t, f.vm.ws("a.txt")); got != 0o755 {
		t.Errorf("a file made executable is %v", got)
	}
	if got := permOf(t, f.vm.ws("gen")); got != 0o750 {
		t.Errorf("a directory's mode is %v", got)
	}
	if exists(f.vm.ws("gone")) {
		t.Error("empty directories removed on the Mac should go")
	}
	if read(t, f.vm.ws("busy/vm-made")) != "the VM's\n" {
		t.Error("a directory removed on the Mac that holds the VM's files stays")
	}
	if !exists(f.vm.ws("empty/inner")) {
		t.Error("an empty directory still on the Mac went")
	}
}

func TestCopySyncManifestStaysInTheWorkspace(t *testing.T) {
	f := newCopyFixture(t)
	put(t, filepath.Join(f.mac, "a.txt"), "a\n")
	f.mustSync()
	outside := t.TempDir()
	put(t, filepath.Join(outside, "file"), "outside\n")
	must(t, os.Symlink(outside, f.vm.ws("out")))
	must(t, os.Symlink(filepath.Join(outside, "file"), f.vm.ws("outfile")))
	must(t, os.MkdirAll(filepath.Join(outside, "victim"), 0o755))

	var mf bytes.Buffer
	for _, r := range []string{
		"d0700 ../escape", "d0700 " + outside + "/abs", "d0700 out/sub", "f0600 outfile", "f0600 out/file",
		"r0000 out/victim", "d0700 .git/x", "d0700 a//b", "d0700 ./x", "d0700 sub/../../escape2", "dxyz1 p",
		"f0600 a.txt\nnot-a-record",
	} {
		mf.WriteString(r + "\x00")
	}
	manifest := filepath.Join(f.vm.tmp, "evil.manifest")
	must(t, os.WriteFile(manifest, mf.Bytes(), 0o600))
	out, err := f.vm.Exec(context.Background(), CopySyncCommand(`$HOME/workspace`, "", manifest, f.syncedCommit(), false))
	if err != nil || !strings.Contains(out, "devkit-synced ") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The last record names a file that does not exist and is ignored.
	if n := strings.Count(out, "devkit-skip "); n != 11 {
		t.Errorf("every record should be skipped (%d were):\n%s", n, out)
	}
	if exists(filepath.Join(filepath.Dir(f.vm.ws("")), "escape")) || exists(filepath.Join(f.vm.home, "escape2")) || exists(filepath.Join(outside, "abs")) || exists(filepath.Join(outside, "sub")) {
		t.Error("a directory was made outside the workspace")
	}
	if permOf(t, filepath.Join(outside, "file")) != 0o644 || !exists(filepath.Join(outside, "victim")) {
		t.Error("something outside the workspace was changed")
	}
	if permOf(t, f.vm.ws("a.txt")) != 0o644 {
		t.Error("a record with a newline in it named another file")
	}
}

// A workspace filled by the old tar sync, met for the first time: what
// matches is adopted without being written, what differs is a conflict,
// and what the snapshot does not name is left alone.
func TestCopySyncAdoptsAFilledWorkspace(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m("a.txt"), "a\n")
	put(t, m("b.txt"), "b\n")
	put(t, m("src/c.txt"), "c\n")
	tarCmd := lima.TarCommand(context.Background(), f.mac, f.excludes)
	must(t, os.MkdirAll(f.vm.ws(""), 0o755))
	x := exec.Command("tar", "-C", f.vm.ws(""), "-xf", "-")
	var err error
	x.Stdin, err = tarCmd.StdoutPipe()
	must(t, err)
	must(t, tarCmd.Start())
	must(t, x.Run())
	must(t, tarCmd.Wait())
	put(t, f.vm.ws("b.txt"), "b, changed in the VM since the tar\n")
	put(t, f.vm.ws("extra.txt"), "only in the VM\n")
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	must(t, os.Chtimes(f.vm.ws("a.txt"), old, old))

	res := f.sync(false)
	if res.Synced || strings.Join(res.Conflicts, ",") != "b.txt" {
		t.Fatalf("want a refusal naming b.txt only, got %+v", res)
	}
	if f.vmSynced() != "" {
		t.Error("a refused first sync must not record a snapshot")
	}
	res = f.sync(true)
	if !res.Synced {
		t.Fatalf("%+v", res)
	}
	f.wantVM("b.txt", "b\n")
	f.wantVM("extra.txt", "only in the VM\n")
	if st, err := os.Stat(f.vm.ws("a.txt")); err != nil || !st.ModTime().Equal(old) {
		t.Errorf("a file that already matched was rewritten: %v %v", st.ModTime(), err)
	}
}

func TestCopySyncSendsOnlyNewObjects(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	for i := 0; i < 20; i++ {
		put(t, m(fmt.Sprintf("src/x/f%d", i)), fmt.Sprintf("file %d\n", i))
	}
	put(t, m("top.txt"), "top\n")
	f.mustSync()
	all, err := f.repo.git(context.Background(), nil, "rev-list", "--objects", f.syncedCommit())
	must(t, err)
	if n := len(strings.Split(all, "\n")); f.vm.packObjects[0] != n {
		t.Fatalf("first pack: %d objects, want all %d", f.vm.packObjects[0], n)
	}
	put(t, m("top.txt"), "top, changed\n")
	f.mustSync()
	put(t, m("src/x/f3"), "changed\n")
	f.mustSync()
	// A blob, the trees above it and the commit.
	if got := f.vm.packObjects[1:]; fmt.Sprint(got) != "[3 5]" {
		t.Errorf("incremental packs hold %v objects, want [3 5]", got)
	}
	f.mustSync()
	if len(f.vm.packObjects) != 3 {
		t.Errorf("nothing changed, yet a pack was sent: %v", f.vm.packObjects)
	}
}

func TestCopySyncDistrustsTheVMsAnswer(t *testing.T) {
	f := newCopyFixture(t)
	put(t, filepath.Join(f.mac, "a.txt"), "a\n")
	put(t, filepath.Join(f.mac, "b/c.txt"), "c\n")
	f.mustSync()
	ctx := context.Background()
	c := f.syncedCommit()
	tree, _ := f.repo.git(ctx, nil, "rev-parse", c+"^{tree}")
	blob, _ := f.repo.git(ctx, nil, "rev-parse", c+":a.txt")
	child, err := f.repo.git(ctx, strings.NewReader("x"), "commit-tree", tree, "-p", c)
	must(t, err)
	if f.repo.Base(ctx, c+"\n") != c {
		t.Fatal("the real snapshot should be accepted")
	}
	for _, answer := range []string{
		"", "garbage", "Error: " + c, strings.ToUpper(c), c[:39], c + "0",
		"0123456789abcdef0123456789abcdef01234567", tree, blob, child,
	} {
		if got := f.repo.Base(ctx, answer); got != "" {
			t.Errorf("answer %q accepted as %q", answer, got)
		}
		a := answer
		f.vm.answer = &a
		put(t, filepath.Join(f.mac, "a.txt"), "a "+answer+"\n")
		f.mustSync()
		total, _ := f.repo.git(ctx, nil, "rev-list", "--objects", f.syncedCommit())
		if got, want := f.vm.packObjects[len(f.vm.packObjects)-1], len(strings.Split(total, "\n")); got != want {
			t.Errorf("answer %q: sent %d objects, want everything (%d)", answer, got, want)
		}
	}
}

func TestCopySyncKeepsOneSnapshot(t *testing.T) {
	f := newCopyFixture(t)
	for i := 0; i < 4; i++ {
		put(t, filepath.Join(f.mac, "a.txt"), fmt.Sprintf("version %d\n", i))
		put(t, filepath.Join(f.mac, fmt.Sprintf("d%d/f", i)), "f\n")
		f.mustSync()
	}
	for side, dir := range map[string]string{"Mac": f.repo.Dir, "VM": f.vm.vmRepo()} {
		refs := gitT(t, dir, "for-each-ref", "--format=%(refname)")
		if refs != CopySyncedRef {
			t.Errorf("%s: refs %q, want only %s", side, refs, CopySyncedRef)
		}
		reachable := len(strings.Split(gitT(t, dir, "rev-list", "--objects", CopySyncedRef), "\n"))
		stored := 0
		for _, l := range strings.Split(gitT(t, dir, "count-objects", "-v"), "\n") {
			var n int
			if _, err := fmt.Sscanf(l, "count: %d", &n); err == nil {
				stored += n
			}
			if _, err := fmt.Sscanf(l, "in-pack: %d", &n); err == nil {
				stored += n
			}
		}
		if stored != reachable {
			t.Errorf("%s: %d objects stored, %d reachable from the one snapshot", side, stored, reachable)
		}
	}
}

func TestCopySyncFailureKeepsTheRecord(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m("a.txt"), "a\n")
	f.mustSync()
	first := f.syncedCommit()
	ctx := context.Background()
	put(t, m("a.txt"), "a, changed\n")

	f.vm.failPut = true
	if _, err := DeliverCopy(ctx, f.repo, f.snapshot(), f.vm, `$HOME/workspace`, false); err == nil {
		t.Fatal("a failed copy should fail the sync")
	}
	f.vm.failPut = false
	f.vm.failScript = true
	if _, err := DeliverCopy(ctx, f.repo, f.snapshot(), f.vm, `$HOME/workspace`, false); err == nil {
		t.Fatal("a VM that does not answer should fail the sync")
	}
	f.vm.failScript = false
	put(t, f.vm.ws("a.txt"), "the VM's\n")
	if res := f.sync(false); res.Synced {
		t.Fatal("a conflict should not apply")
	}
	if f.syncedCommit() != first || f.vmSynced() != first {
		t.Fatalf("a failed or refused sync moved the record: Mac %s, VM %s, want %s", f.syncedCommit(), f.vmSynced(), first)
	}
	if refs := gitT(t, f.repo.Dir, "for-each-ref", "--format=%(refname)"); refs != CopySyncedRef {
		t.Errorf("pending snapshots were left behind: %q", refs)
	}
	must(t, os.Remove(f.vm.ws("a.txt")))
	f.mustSync()
	f.wantVM("a.txt", "a, changed\n")
	if n := f.vm.packObjects[len(f.vm.packObjects)-1]; n != 3 {
		t.Errorf("the sync after the failures should still send only what changed, sent %d objects", n)
	}
}

// With an exclude list that leaves out .git, git still cannot carry it:
// the paths are reported, and the workspace's own repository is left to
// the fresh-clone logic.
func TestCopySyncReportsWhatGitCannotCarry(t *testing.T) {
	f := newCopyFixture(t)
	f.excludes = []string{"node_modules"}
	put(t, filepath.Join(f.mac, "a.txt"), "a\n")
	gitT(t, f.mac, "init", "-q")
	snap := f.snapshot()
	var skipped []string
	for _, s := range snap.Skipped {
		skipped = append(skipped, s.Path)
	}
	if len(skipped) == 0 || !strings.HasPrefix(skipped[0], ".git") {
		t.Errorf("the .git paths should be reported: %q", skipped)
	}
	for _, p := range f.treePaths(snap.Commit) {
		if strings.HasPrefix(p, ".git/") || strings.HasPrefix(p, ".devkit/") {
			t.Errorf("%s is in the snapshot", p)
		}
	}
	f.repo.Discard(context.Background(), snap)
}

// A file whose time changed in the VM, but not its content, is not a VM
// change: the Mac's next version of it arrives.
func TestCopySyncIgnoresATimestampAlone(t *testing.T) {
	f := newCopyFixture(t)
	put(t, filepath.Join(f.mac, "a.txt"), "a\n")
	f.mustSync()
	later := time.Now().Add(time.Hour)
	must(t, os.Chtimes(f.vm.ws("a.txt"), later, later))
	put(t, filepath.Join(f.mac, "a.txt"), "a, the Mac's\n")
	res := f.mustSync()
	f.wantVM("a.txt", "a, the Mac's\n")
	if len(res.Kept) != 0 {
		t.Errorf("kept: %q", res.Kept)
	}
}

// listTree records every entry under dir, with its mode, size and, for a
// symlink, its target, to tell whether anything there changed.
func listTree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	must(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		target, _ := os.Readlink(p)
		fmt.Fprintf(&b, "%s %v %d %s\n", strings.TrimPrefix(p, dir), info.Mode(), info.Size(), target)
		return nil
	}))
	return b.String()
}

// A project can ship a .devkit/sync.git of its own, with objects that are
// another repository's. Syncing it must neither use nor touch it: pruning
// "unreachable" objects there would delete the other repository's history.
func TestCopySyncIgnoresARepositoryInTheProject(t *testing.T) {
	victim := t.TempDir()
	gitT(t, victim, "init", "-q", "-b", "main")
	put(t, filepath.Join(victim, "precious.txt"), "precious\n")
	gitT(t, victim, "add", ".")
	gitT(t, victim, "-c", "user.name=v", "-c", "user.email=v@v", "-c", "commit.gpgsign=false", "commit", "-qm", "precious")
	head := gitT(t, victim, "rev-parse", "HEAD")

	mac := t.TempDir()
	planted := filepath.Join(mac, ".devkit", "sync.git")
	must(t, os.MkdirAll(filepath.Join(planted, "refs", "heads"), 0o755))
	put(t, filepath.Join(planted, "HEAD"), "ref: refs/heads/main\n")
	must(t, os.Symlink(filepath.Join(victim, ".git", "objects"), filepath.Join(planted, "objects")))
	before := listTree(t, filepath.Join(mac, ".devkit"))

	f := newCopyFixtureAt(t, mac)
	put(t, filepath.Join(mac, "a.txt"), "a\n")
	f.mustSync()
	put(t, filepath.Join(mac, "a.txt"), "a, changed\n")
	f.mustSync()

	if out, err := exec.Command("git", "-C", victim, "fsck", "--no-progress").CombinedOutput(); err != nil {
		t.Errorf("the other repository is damaged: %v\n%s", err, out)
	}
	if got := gitT(t, victim, "cat-file", "-t", head); got != "commit" {
		t.Errorf("the other repository's commit is gone: %s", got)
	}
	if after := listTree(t, filepath.Join(mac, ".devkit")); after != before {
		t.Errorf("the planted directory changed:\n before %s\n after  %s", before, after)
	}
}

// A sync interrupted while git held the VM's index must not block every
// later one; a lock that is not stale is still respected.
func TestCopySyncRecoversFromAStaleLock(t *testing.T) {
	f := newCopyFixture(t)
	put(t, filepath.Join(f.mac, "a.txt"), "a\n")
	f.mustSync()
	lock := filepath.Join(f.vm.vmRepo(), "index.lock")
	put(t, lock, "")
	put(t, filepath.Join(f.mac, "a.txt"), "a, changed\n")
	if _, err := DeliverCopy(context.Background(), f.repo, f.snapshot(), f.vm, `$HOME/workspace`, false); err == nil {
		t.Error("a sync must not take a lock that may be another sync's")
	}
	old := time.Now().Add(-time.Hour)
	must(t, os.Chtimes(lock, old, old))
	f.mustSync()
	f.wantVM("a.txt", "a, changed\n")
}

func TestCopyRepoRefusesASymlink(t *testing.T) {
	real := t.TempDir()
	for _, link := range []string{"state", filepath.Join("ok", "sync.git")} {
		base := t.TempDir()
		must(t, os.MkdirAll(filepath.Dir(filepath.Join(base, link)), 0o755))
		must(t, os.Symlink(real, filepath.Join(base, link)))
		dir := filepath.Join(base, "state", "sync.git")
		if link != "state" {
			dir = filepath.Join(base, "ok", "sync.git")
		}
		if _, err := OpenCopyRepo(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("%s as a symlink: got %v", link, err)
		}
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Errorf("something was written through the symlink: %v", entries)
	}
}

// workspaceState records every entry of the VM's workspace: mode, time,
// content or symlink target. The VM's own .git is left out of nothing.
func workspaceState(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	must(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		extra := ""
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			extra, _ = os.Readlink(p)
		case info.Mode().IsRegular():
			extra = read(t, p)
		}
		fmt.Fprintf(&b, "%s %v %d %q\n", strings.TrimPrefix(p, dir), info.Mode(), info.ModTime().UnixNano(), extra)
		return nil
	}))
	return b.String()
}

// Something in the VM in the way of the Mac's changes (a directory where
// the Mac adds a file, a file where it adds a directory) stops the sync
// as a refusal, with nothing changed, also under --overwrite, which does
// not resolve it. Moving it out of the way lets the sync through.
func TestCopySyncRefusesWhatIsInTheWay(t *testing.T) {
	for _, c := range []struct {
		name      string
		inTheWay  func(f *copyFixture)
		macAdds   string
		overwrite bool
	}{
		{"a directory where the Mac adds a file", func(f *copyFixture) { put(t, f.vm.ws("clash/inner"), "vm\n") }, "clash", false},
		{"a directory where the Mac adds a file, --overwrite", func(f *copyFixture) { put(t, f.vm.ws("clash/inner"), "vm\n") }, "clash", true},
		{"a file where the Mac adds a directory", func(f *copyFixture) { put(t, f.vm.ws("clash"), "vm\n") }, "clash/inner", false},
		{"a file where the Mac adds a directory, --overwrite", func(f *copyFixture) { put(t, f.vm.ws("clash"), "vm\n") }, "clash/inner", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCopyFixture(t)
			m := func(rel string) string { return filepath.Join(f.mac, rel) }
			put(t, m("a.txt"), "a\n")
			put(t, m("both.txt"), "both\n")
			f.mustSync()
			c.inTheWay(f)
			// A conflict too, which --overwrite would resolve: it must
			// not be reset when the sync is refused.
			put(t, f.vm.ws("both.txt"), "both, the VM's\n")
			put(t, m("both.txt"), "both, the Mac's\n")
			put(t, m(c.macAdds), "the Mac's\n")
			put(t, m("late.txt"), "late\n")
			before := workspaceState(t, f.vm.ws(""))
			index := read(t, filepath.Join(f.vm.vmRepo(), "index"))

			res := f.sync(c.overwrite)
			if res.Synced || len(res.Refused) == 0 || !strings.Contains(strings.Join(res.Refused, "\n"), "clash") {
				t.Fatalf("want a refusal naming clash, got %+v", res)
			}
			if strings.Join(res.Conflicts, ",") != "both.txt" {
				t.Errorf("the refusal should also list the conflict: %+v", res)
			}
			if after := workspaceState(t, f.vm.ws("")); after != before {
				t.Errorf("a refused sync changed the workspace:\n before %s\n after  %s", before, after)
			}
			if read(t, filepath.Join(f.vm.vmRepo(), "index")) != index {
				t.Error("a refused sync changed the VM's index")
			}
			if f.vmSynced() != f.syncedCommit() {
				t.Error("a refused sync moved a record")
			}

			must(t, os.Rename(f.vm.ws("clash"), f.vm.ws("clash.mine")))
			if res := f.sync(true); !res.Synced {
				t.Fatalf("with nothing in the way the sync should apply: %+v", res)
			}
			f.wantVM(c.macAdds, "the Mac's\n")
			f.wantVM("late.txt", "late\n")
			f.wantVM("both.txt", "both, the Mac's\n")
		})
	}
}

// Under --overwrite, a file the VM changed that the Mac turned into a
// directory is reset, then replaced: the rehearsal must not refuse it.
func TestCopySyncOverwriteOfAFileTheMacMadeADirectory(t *testing.T) {
	f := newCopyFixture(t)
	m := func(rel string) string { return filepath.Join(f.mac, rel) }
	put(t, m("x"), "x\n")
	f.mustSync()
	put(t, f.vm.ws("x"), "x, the VM's\n")
	must(t, os.Remove(m("x")))
	put(t, m("x/y"), "y\n")
	res := f.sync(false)
	if res.Synced || strings.Join(res.Conflicts, ",") != "x" {
		t.Fatalf("want a conflict on x, got %+v", res)
	}
	if res := f.sync(true); !res.Synced {
		t.Fatalf("--overwrite should apply: %+v", res)
	}
	f.wantVM("x/y", "y\n")
}
