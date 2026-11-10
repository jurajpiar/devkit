package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The image scan runs in the VM's python3; these tests run the same code
// with the host's, against fixture trees, so the logic is checked without a
// VM. The driver below is test-only: it forces the fallback reading on
// request and prints what the audit would.
const imageScanDriver = `
import json, sys
mode = sys.argv[2]
if mode == "fallback":
    _yaml = None
elif mode == "yaml" and _yaml is None:
    print(json.dumps({"no_yaml": True}))
    sys.exit(0)
deep = "--deep" in sys.argv
res = image_scan(sys.argv[1], deep)
res["lines"] = image_report(res, deep)
print(json.dumps(res))
`

type scanResult struct {
	NoYAML      bool       `json:"no_yaml"`
	Files       int        `json:"files"`
	Items       [][]string `json:"items"`
	Unread      [][]string `json:"unread"`
	Approximate bool       `json:"approximate"`
	Truncated   bool       `json:"truncated"`
	Lines       []string   `json:"lines"`
}

// allPinned is what a careless reader of the report would conclude: every
// reference pinned and nothing left unread.
func (r scanResult) allPinned() bool {
	if len(r.Unread) > 0 {
		return false
	}
	for _, it := range r.Items {
		if it[2] != "pinned" {
			return false
		}
	}
	return true
}

func python3(t *testing.T) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	return py
}

var yamlPython = sync.OnceValue(func() string {
	for _, c := range []string{"python3", "/usr/bin/python3", "python3.12", "python3.13"} {
		py, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		// -E, not -I: PyYAML is often in the user site, which -I hides.
		if exec.Command(py, "-E", "-c", "import yaml").Run() == nil {
			return py
		}
	}
	return ""
})

// runImageScan runs the scan over root. mode is "fallback" (no YAML parser,
// forced) or "yaml" (skipped when PyYAML is not importable).
func runImageScan(t *testing.T, root, mode string, deep bool) scanResult {
	t.Helper()
	harness := filepath.Join(t.TempDir(), "scan.py")
	if err := os.WriteFile(harness, []byte(ImageScanScript+imageScanDriver), 0o600); err != nil {
		t.Fatal(err)
	}
	// The harness sits in a directory of its own, so -E is isolation
	// enough; -I would hide a PyYAML in the user site.
	py := python3(t)
	if mode == "yaml" {
		if py = yamlPython(); py == "" {
			t.Skip("no python3 here can import PyYAML")
		}
	}
	args := []string{"-E", harness, root, mode}
	if deep {
		args = append(args, "--deep")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, py, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("image scan failed: %v\n%s", err, stderr.String())
	}
	var r scanResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("image scan output is not JSON: %v\n%s", err, out)
	}
	if r.NoYAML {
		t.Skip("PyYAML is not importable in the host's python3")
	}
	return r
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var (
	dg  = "sha256:" + strings.Repeat("ab", 32)
	dg2 = "sha256:" + strings.Repeat("0f", 32)
)

type img struct{ file, ref, status string }

func items(r scanResult) []img {
	var out []img
	for _, it := range r.Items {
		out = append(out, img{it[0], it[1], it[2]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].ref < out[j].ref
	})
	return out
}

func sorted(in []img) []img {
	out := append([]img(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].ref < out[j].ref
	})
	return out
}

func equalImgs(a, b []img) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The invalidation corpus from the hardening plan: each case is an input a
// careless reader gets wrong. Unless allPinned says otherwise, the result
// must not read as "all pinned".
func TestImageScanCorpus(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []img
		// fallback, when set, is the expected result without a YAML parser.
		fallback []img
		// yamlOnly cases need a parser to come out right (includes).
		yamlOnly  bool
		allPinned bool
		deep      bool
	}{
		{name: "tag", files: map[string]string{"compose.yaml": "services:\n  web:\n    image: nginx:1.27\n"},
			want: []img{{"compose.yaml", "nginx:1.27", "unpinned"}}},
		{name: "bare name is implicit latest", files: map[string]string{"compose.yml": "services:\n  cache:\n    image: redis\n"},
			want: []img{{"compose.yml", "redis", "unpinned"}}},
		{name: "tag and digest is pinned", allPinned: true,
			files: map[string]string{"docker-compose.yml": "services:\n  web:\n    image: \"nginx:1.27@" + dg + "\"\n  db:\n    image: postgres@" + dg2 + "\n"},
			want:  []img{{"docker-compose.yml", "nginx:1.27@" + dg, "pinned"}, {"docker-compose.yml", "postgres@" + dg2, "pinned"}}},
		{name: "variable unset", files: map[string]string{"compose.yaml": "services:\n  node:\n    image: ${RSKJ_IMAGE}\n"},
			want: []img{{"compose.yaml", "${RSKJ_IMAGE}", "unresolved"}}},
		{name: "variable with defaults", files: map[string]string{"compose.yaml": "services:\n  a:\n    image: ${A:-redis:7}\n  b:\n    image: ${B-alpine}\n  c:\n    image: \"${C:-busybox@" + dg + "}\"\n"},
			want: []img{{"compose.yaml", "${A:-redis:7} (= redis:7)", "unpinned"}, {"compose.yaml", "${B-alpine} (= alpine)", "unpinned"}, {"compose.yaml", "${C:-busybox@" + dg + "} (= busybox@" + dg + ")", "pinned"}}},
		{name: "variable set in .env", files: map[string]string{
			"compose.yaml": "services:\n  a:\n    image: ${A}\n  b:\n    image: $B\n  c:\n    image: ${C:-ignored:1}\n",
			".env":         "# images\nA=redis:7\nexport B='busybox@" + dg + "'\nC=\"node:22\" \n"},
			want: []img{{"compose.yaml", "${A} (= redis:7)", "unpinned"}, {"compose.yaml", "$B (= busybox@" + dg + ")", "pinned"}, {"compose.yaml", "${C:-ignored:1} (= node:22)", "unpinned"}}},
		{name: "required variable", files: map[string]string{"compose.yaml": "services:\n  rskj:\n    image: ${RSKJ_IMAGE:?set RSKJ_IMAGE}\n"},
			want: []img{{"compose.yaml", "${RSKJ_IMAGE:?set RSKJ_IMAGE}", "unresolved"}}},
		{name: ".env value that interpolates is not guessed", files: map[string]string{
			"compose.yaml": "services:\n  a:\n    image: ${A}\n", ".env": "A=${REGISTRY}/app:1\n"},
			want: []img{{"compose.yaml", "${A}", "unresolved"}}},
		{name: "Dockerfile FROM with a tag", files: map[string]string{"Dockerfile": "FROM node:22-slim\nRUN true\n"},
			want: []img{{"Dockerfile", "node:22-slim", "unpinned"}}},
		{name: "ARG with and without default", files: map[string]string{
			"Dockerfile.ci":  "ARG BASE=alpine:3.20\nFROM ${BASE}\n",
			"app.Dockerfile": "ARG BASE\nFROM $BASE\n",
			"Containerfile":  "ARG V=3.12\nFROM python:${V}@" + dg + "\n"},
			want: []img{{"Containerfile", "python:${V}@" + dg + " (= python:3.12@" + dg + ")", "pinned"}, {"Dockerfile.ci", "${BASE} (= alpine:3.20)", "unpinned"}, {"app.Dockerfile", "$BASE", "unresolved"}}},
		{name: "ARG after the first FROM does not reach FROM", files: map[string]string{"Dockerfile": "FROM alpine@" + dg + " AS a\nARG BASE=debian:12\nFROM $BASE\n"},
			want: []img{{"Dockerfile", "alpine@" + dg, "pinned"}, {"Dockerfile", "$BASE", "unresolved"}}},
		{name: "previous stage, scratch and --platform", allPinned: true, files: map[string]string{"Dockerfile": "# syntax=docker/dockerfile:1\n" +
			"FROM --platform=$BUILDPLATFORM golang@" + dg + " AS Build\n" +
			"FROM build AS test\nFROM scratch\nCOPY --from=build /out /out\nCOPY --from=0 /x /x\n"},
			want: []img{{"Dockerfile", "golang@" + dg, "pinned"}}},
		{name: "COPY --from an image", files: map[string]string{"Dockerfile": "FROM scratch\nCOPY --from=nginx:1.27 /etc/nginx /etc/nginx\n"},
			want: []img{{"Dockerfile", "nginx:1.27", "unpinned"}}},
		{name: "continuations, comments and heredocs", files: map[string]string{"Dockerfile": "FROM \\\n  # a comment inside the continuation\n  --platform=linux/amd64 \\\n  debian:12 \\\n  AS base\n# FROM evil:latest\nRUN <<EOF\nFROM fake:1\nEOF\nRUN echo \\\n  FROM other:1\n"},
			want: []img{{"Dockerfile", "debian:12", "unpinned"}}},
		{name: "escape directive", files: map[string]string{"Dockerfile": "# escape=\x60\nFROM \x60\n  mcr.microsoft.com/windows/servercore:ltsc2022\n"},
			want: []img{{"Dockerfile", "mcr.microsoft.com/windows/servercore:ltsc2022", "unpinned"}}},
		{name: "several compose files", files: map[string]string{
			"compose.yaml":                    "services:\n  a:\n    image: a@" + dg + "\n",
			"compose.override.yml":            "services:\n  a:\n    image: a:dev\n",
			"deploy/docker-compose.prod.yaml": "services:\n  a:\n    image: registry.example/a:1.0\n",
			"notcompose.yml":                  "services:\n  a:\n    image: ignored:1\n"},
			want: []img{{"compose.override.yml", "a:dev", "unpinned"}, {"compose.yaml", "a@" + dg, "pinned"}, {"deploy/docker-compose.prod.yaml", "registry.example/a:1.0", "unpinned"}}},
		{name: "anchors and merge keys", files: map[string]string{"compose.yaml": "x-img: &img redis:7\nx-base: &base\n  image: postgres:16\n  restart: always\nservices:\n  cache:\n    image: *img\n  db:\n    <<: *base\n  pinned:\n    image: &p busybox@" + dg + "\n"},
			want: []img{{"compose.yaml", "busybox@" + dg, "pinned"}, {"compose.yaml", "postgres:16", "unpinned"}, {"compose.yaml", "redis:7", "unpinned"}},
			// Without a parser the alias cannot be followed and the anchor's
			// own image: line is read wherever it sits.
			fallback: []img{{"compose.yaml", "*img", "unresolved"}, {"compose.yaml", "busybox@" + dg, "pinned"}, {"compose.yaml", "postgres:16", "unpinned"}}},
		{name: "digest of the wrong length", files: map[string]string{"compose.yaml": "services:\n  a:\n    image: a@sha256:abc123\n  b:\n    image: b@sha256:" + strings.Repeat("a", 63) + "\n  c:\n    image: c@sha256:" + strings.Repeat("a", 65) + "\n  d:\n    image: d@sha256:" + strings.Repeat("A", 64) + "\n"},
			want: []img{{"compose.yaml", "a@sha256:abc123", "unpinned"}, {"compose.yaml", "b@sha256:" + strings.Repeat("a", 63), "unpinned"}, {"compose.yaml", "c@sha256:" + strings.Repeat("a", 65), "unpinned"}, {"compose.yaml", "d@sha256:" + strings.Repeat("A", 64), "unpinned"}}},
		{name: "reference in a comment is not a use", allPinned: true, files: map[string]string{"compose.yaml": "# image: evil:latest\nservices:\n  a:\n    # image: evil:2\n    image: a@" + dg + " # was a:1\n"},
			want: []img{{"compose.yaml", "a@" + dg, "pinned"}}},
		{name: "build without image contributes its Dockerfile", files: map[string]string{"compose.yaml": "services:\n  app:\n    build: .\n", "Dockerfile": "FROM python:3.12\n"},
			want: []img{{"Dockerfile", "python:3.12", "unpinned"}}},
		{name: "include and extends", yamlOnly: true, files: map[string]string{
			"compose.yaml":      "include:\n  - deploy/extra.yaml\n  - path: ../outside.yaml\nservices:\n  web:\n    extends:\n      file: common/base.yaml\n      service: web\n",
			"deploy/extra.yaml": "services:\n  worker:\n    image: worker:1\n",
			"common/base.yaml":  "services:\n  web:\n    image: web@" + dg + "\n",
			"../outside.yaml":   "services:\n  x:\n    image: never:1\n"},
			want: []img{{"common/base.yaml", "web@" + dg, "pinned"}, {"deploy/extra.yaml", "worker:1", "unpinned"}}},
		{name: "dependency trees are pruned in the shallow scan", files: map[string]string{
			"node_modules/pkg/Dockerfile": "FROM node:22\n", "vendor/x/compose.yml": "services:\n  a:\n    image: a:1\n",
			"build/Dockerfile": "FROM golang:1.23\n", "Dockerfile.dockerignore": "FROM nothing:1\n"},
			want: []img{{"build/Dockerfile", "golang:1.23", "unpinned"}}},
		{name: "deep scan reads dependency trees", deep: true, files: map[string]string{"node_modules/pkg/Dockerfile": "FROM node:22\n"},
			want: []img{{"node_modules/pkg/Dockerfile", "node:22", "unpinned"}}},
	}
	for _, c := range cases {
		for _, mode := range []string{"fallback", "yaml"} {
			if mode == "fallback" && c.yamlOnly {
				continue
			}
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				// Fixtures with ".." are written beside the root, to prove
				// an include cannot leave the workspace.
				parent := writeTree(t, nil)
				files := map[string]string{}
				for k, v := range c.files {
					files[filepath.Join("ws", k)] = v
				}
				for k, v := range files {
					p := filepath.Join(parent, k)
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				r := runImageScan(t, filepath.Join(parent, "ws"), mode, c.deep)
				want := c.want
				if mode == "fallback" && c.fallback != nil {
					want = c.fallback
				}
				if got := items(r); !equalImgs(got, sorted(want)) {
					t.Errorf("references:\n got %v\nwant %v", got, sorted(want))
				}
				if r.allPinned() != c.allPinned {
					t.Errorf("all pinned = %v, want %v\n%s", r.allPinned(), c.allPinned, strings.Join(r.Lines, "\n"))
				}
				if r.Approximate != (mode == "fallback" && hasCompose(c.files)) {
					t.Errorf("approximate = %v in %s mode", r.Approximate, mode)
				}
			})
		}
	}
}

func hasCompose(files map[string]string) bool {
	for k := range files {
		// Pruned trees are not read in the shallow scan.
		if strings.HasPrefix(k, "node_modules/") || strings.HasPrefix(k, "vendor/") {
			continue
		}
		b := filepath.Base(k)
		if strings.HasPrefix(b, "compose.") || strings.HasPrefix(b, "docker-compose.") {
			return true
		}
	}
	return false
}

func TestImageScanReport(t *testing.T) {
	root := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  a:\n    image: a@" + dg + "\n  b:\n    image: b:1\n  c:\n    image: ${C:?}\n",
	})
	r := runImageScan(t, root, "fallback", false)
	if len(r.Lines) == 0 || !strings.HasPrefix(r.Lines[0], "  container images: 3 references in 1 file, 1 pinned by digest, 1 unpinned, 1 unresolved") {
		t.Fatalf("summary line:\n%s", strings.Join(r.Lines, "\n"))
	}
	if !strings.Contains(r.Lines[0], "approximate") {
		t.Errorf("a reading without a YAML parser must say it is approximate: %q", r.Lines[0])
	}
	text := strings.Join(r.Lines, "\n")
	for _, want := range []string{"    - compose.yaml: b:1  (unpinned)", "    - compose.yaml: ${C:?}  (unresolved)"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "a@"+dg) {
		t.Errorf("pinned references are counted, not listed:\n%s", text)
	}

	empty := runImageScan(t, writeTree(t, map[string]string{"main.go": "package main\n"}), "fallback", false)
	if len(empty.Lines) != 1 || empty.Lines[0] != "  container images: no compose files or Dockerfiles" {
		t.Errorf("a project without images gets one quiet line: %q", empty.Lines)
	}
}

func TestImageScanCapsTheList(t *testing.T) {
	var b strings.Builder
	b.WriteString("services:\n")
	for i := 0; i < 30; i++ {
		b.WriteString("  s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ":\n    image: img:1\n")
	}
	root := writeTree(t, map[string]string{"compose.yaml": b.String()})
	r := runImageScan(t, root, "fallback", false)
	listed := 0
	for _, l := range r.Lines {
		if strings.HasPrefix(l, "    - ") {
			listed++
		}
	}
	if listed != 12 || !strings.Contains(strings.Join(r.Lines, "\n"), "    ... 18 more; devkit audit --deep lists up to 200") {
		t.Errorf("shallow list should stop at 12 with a count of the rest:\n%s", strings.Join(r.Lines, "\n"))
	}
}

// File names and references come from the project: no control character
// may reach the terminal, whichever reading is used.
func TestImageScanSanitises(t *testing.T) {
	esc := "\x1b]0;pwned\x07\x1b[2J"
	root := writeTree(t, map[string]string{
		"compose." + esc + ".yml": "services:\n  a:\n    image: \"evil" + esc + ":1\"\n",
		"x" + esc + "/Dockerfile": "FROM bad\u202e" + esc + ":1\n",
	})
	for _, mode := range []string{"fallback", "yaml"} {
		t.Run(mode, func(t *testing.T) {
			r := runImageScan(t, root, mode, false)
			if r.allPinned() || r.Files != 2 {
				t.Fatalf("both files should be read and reported:\n%q", r.Lines)
			}
			for _, l := range r.Lines {
				for _, c := range l {
					if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == '\u202e' {
						t.Fatalf("control or format character %U reaches the terminal: %q", c, l)
					}
				}
			}
		})
	}
}

// A file named like a compose file or Dockerfile can be anything: huge,
// binary or a FIFO. None may hang or crash the audit, and none may read as
// clean.
func TestImageScanHostileFiles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"compose.yaml":                    "services:\n  a:\n    image: a@" + dg + "\n",
		"big/compose.yml":                 "services:\n  a:\n    image: a:1\n" + strings.Repeat("# padding\n", 600_000),
		"bin/compose.yaml":                "\x00\x01\x02\xff\xfeimage: x\x00",
		"bin2/Dockerfile":                 "FROM \xff\xfe\x00",
		"deep/a/b/c/d/e/f/g/h/Dockerfile": "FROM ok@" + dg + "\n",
	})
	if err := syscall.Mkfifo(filepath.Join(root, "docker-compose.yml"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"fallback", "yaml"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now()
			r := runImageScan(t, root, mode, false)
			if time.Since(start) > 20*time.Second {
				t.Errorf("scan took %s", time.Since(start))
			}
			unread := map[string]string{}
			for _, u := range r.Unread {
				unread[u[0]] = u[1]
			}
			for _, f := range []string{"big/compose.yml", "bin/compose.yaml", "bin2/Dockerfile", "docker-compose.yml"} {
				if _, ok := unread[f]; !ok {
					t.Errorf("%s should be reported as not read, got %v", f, r.Unread)
				}
			}
			if r.allPinned() {
				t.Errorf("unread files must not leave the report reading as all pinned")
			}
			text := strings.Join(r.Lines, "\n")
			if !strings.Contains(text, "4 files not read") || !strings.Contains(text, "big/compose.yml: not read (over 256 KB)") {
				t.Errorf("report should name unread files:\n%s", text)
			}
		})
	}
}

// The scan is part of the audit script, reports without counting findings,
// and the whole script is valid Python.
func TestAuditScriptCarriesImageScan(t *testing.T) {
	if !strings.Contains(AuditScript, ImageScanScript) {
		t.Fatal("the audit script does not include the image scan")
	}
	if !strings.Contains(AuditScript, "for line in image_report(image_scan(WORKSPACE, DEEP), DEEP):\n    say(line)") {
		t.Error("the audit should print the image report through say, in both modes")
	}
	if strings.Contains(ImageScanScript, "flag(") || strings.Contains(ImageScanScript, "stale") {
		t.Error("unpinned images are a report: they must not count towards the exit status")
	}
	if strings.Contains(ImageScanScript, "PYEOF") || strings.Contains(ImageScanScript, "`") {
		t.Error("the image scan would break the audit script's heredoc or Go literal")
	}
	script := filepath.Join(t.TempDir(), "audit.py")
	if err := os.WriteFile(script, []byte(AuditScript), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(python3(t), "-I", "-c", "import ast, sys; ast.parse(open(sys.argv[1]).read())", script).CombinedOutput(); err != nil {
		t.Fatalf("audit script does not parse: %v\n%s", err, out)
	}
}
