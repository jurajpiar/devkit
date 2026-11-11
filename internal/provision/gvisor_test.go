package provision

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/egressproxy"
	"github.com/jurajpiar/devkit/internal/project"
)

// tools.container_runtime: runc, the default, renders the Docker script
// pinned here. gVisor left it as it was before gVisor existed; the API
// filter and the runtime guard changed it (daemon.json registers the guard
// as the default runtime), so these are the filter branch's render, and
// Docker VMs provisioned before it are reported stale once.
func TestDockerRuncScriptIsPinned(t *testing.T) {
	want := map[string]string{
		"allowlist-mise":      "aa94ef7e539c1b93",
		"allowlist-mise-host": "e15c335d9b978647",
		"allowlist-nix":       "0060ef11597fa950",
		"allowlist-nix-host":  "67f3b1ef8d89626e",
		"allowlist-none":      "e121ca218cedf002",
		"allowlist-none-host": "798e226c1925e5e7",
		"none-mise":           "dab91333ed8ab533",
		"none-nix":            "273426011895180f",
		"none-none":           "cf819b9a263ac4bc",
		"open-mise":           "8c90dd291d226c64",
		"open-mise-host":      "b4e497d0249cb514",
		"open-nix":            "19f42045ec5e1c20",
		"open-nix-host":       "a96e0e8bad8d90d2",
		"open-none":           "48e0488fde5e5da3",
		"open-none-host":      "affbe336b22647fa",
	}
	var got []string
	dockerVariants(t, func(t *testing.T, p Params, s string) {
		sum := sha256.Sum256([]byte(s))
		h := hex.EncodeToString(sum[:])[:16]
		name := strings.TrimPrefix(t.Name(), "TestDockerRuncScriptIsPinned/")
		got = append(got, fmt.Sprintf("%q: %q,", name, h))
		if w := want[name]; w != h {
			t.Errorf("docker script with runc changed (hash %s, want %s)", h, w)
		}
	})
	if t.Failed() {
		sort.Strings(got)
		t.Logf("current hashes:\n%s", strings.Join(got, "\n"))
	}
}

var gvisorRuntimes = []project.ContainerRuntime{project.RuntimeGvisor, project.RuntimeGvisorHostnet}

const (
	gvisorMarker   = "# ---- gVisor: pinned release, verified by SHA-512 ----"
	gvisorFetch    = `"${CURL[@]}" -o "$tmp/gvisor.tar.zstd"`
	gvisorCheck    = `sha512sum -c --quiet -`
	gvisorUnpack   = `tar --zstd -xf "$tmp/gvisor.tar.zstd" -C "$tmp/x" --no-same-owner`
	gvisorInstall  = `install -m 755 -o root -g root "$tmp/x/runsc" "$tmp/x/containerd-shim-runsc-v1" /usr/local/bin/`
	gvisorSwap     = `mv -T "$new" /usr/local/bin/gvisor-bin`
	gvisorStamp    = `echo "$want" > "$GVISOR_STAMP"`
	daemonJSONOpen = "cat > /etc/devkit/docker/daemon.json <<'EOF'\n"
)

// gvisorVariants is dockerVariants for each gVisor runtime.
func gvisorVariants(t *testing.T, check func(t *testing.T, p Params, s string)) {
	for _, rt := range gvisorRuntimes {
		for _, mode := range []string{project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone} {
			for _, host := range []bool{false, true} {
				if host && mode == project.NetworkNone {
					continue
				}
				name := string(rt) + "-" + mode
				if host {
					name += "-host"
				}
				t.Run(name, func(t *testing.T) {
					set := func(c *project.Config) {
						c.Tools.Containers = project.ContainersDocker
						c.Tools.ContainerRuntime = rt
						c.Network.Mode = mode
					}
					p := params(set)
					if host {
						p = hostParams(set)
					}
					s, err := System(p)
					if err != nil {
						t.Fatal(err)
					}
					check(t, p, s)
				})
			}
		}
	}
}

// daemonJSON parses the daemon's settings out of a rendered script.
func daemonJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	body, err := heredocBody(s, daemonJSONOpen)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("daemon.json is not JSON: %v\n%s", err, body)
	}
	return out
}

// gVisor is fetched and installed only when a gVisor runtime is configured;
// runc, the default, downloads nothing and registers no runtime.
func TestGvisorStepsOnlyInGvisorModes(t *testing.T) {
	steps := []string{gvisorMarker, gvisorFetch, gvisorCheck, gvisorUnpack, gvisorInstall, gvisorSwap, gvisorStamp,
		"storage.googleapis.com", "runsc", "zstd"}
	for name, p := range map[string]Params{
		"off":         params(nil),
		"containerd":  params(func(c *project.Config) { c.Tools.Containers = project.ContainersContainerd }),
		"docker":      dockerParams(nil),
		"docker-runc": dockerParams(func(c *project.Config) { c.Tools.ContainerRuntime = project.RuntimeRunc }),
	} {
		s, err := System(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range steps {
			if strings.Contains(s, st) {
				t.Errorf("%s: %q belongs to the gVisor modes only", name, st)
			}
		}
	}
	gvisorVariants(t, func(t *testing.T, p Params, s string) {
		for _, st := range steps {
			if !strings.Contains(s, st) {
				t.Errorf("%q is missing", st)
			}
		}
		if !strings.Contains(s, "WANT_PKGS=\"") || !strings.Contains(s[strings.Index(s, "WANT_PKGS=\""):], " zstd\"") {
			t.Error("zstd should be among the packages, to unpack the archive")
		}
	})
}

// The archive is verified before anything in it is unpacked, installed with
// the packages it needs in place and before the firewall (root's download
// needs the network), and in place before the daemon starts. The stamp is
// written last, so an install that fails part way is redone.
func TestGvisorOrdering(t *testing.T) {
	gvisorVariants(t, func(t *testing.T, p Params, s string) {
		pkgs := index(t, s, "$APT install -y --no-install-recommends $WANT_PKGS")
		curlDef := strings.LastIndex(s, "CURL=(curl")
		fetch := index(t, s, gvisorFetch)
		check := index(t, s, gvisorCheck)
		unpack := index(t, s, gvisorUnpack)
		swap := index(t, s, gvisorSwap)
		install := index(t, s, gvisorInstall)
		stamp := index(t, s, gvisorStamp)
		daemonJSON := index(t, s, daemonJSONOpen)
		fw := index(t, s, "\n/usr/local/sbin/devkit-firewall\n")
		start := index(t, s, dockerStart)
		if !(pkgs < fetch && curlDef < fetch && fetch < check && check < unpack && unpack < swap && swap < install && install < stamp && stamp < daemonJSON && daemonJSON < fw && fw < start) {
			t.Errorf("order: packages=%d curl=%d fetch=%d check=%d unpack=%d swap=%d install=%d stamp=%d daemon.json=%d firewall=%d start=%d",
				pkgs, curlDef, fetch, check, unpack, swap, install, stamp, daemonJSON, fw, start)
		}
		// A mismatch aborts provisioning, before tar is reached.
		block := s[check:unpack]
		if !strings.Contains(block, "warn \"refused gVisor") || !strings.Contains(block, "exit 1") {
			t.Errorf("a checksum mismatch must warn and abort:\n%s", block)
		}
		// Neither the download nor the install is excused.
		inst := s[index(t, s, gvisorMarker):index(t, s, daemonJSONOpen)]
		for _, line := range strings.Split(inst, "\n") {
			if strings.Contains(line, "|| true") && !strings.Contains(line, "GVISOR_STAMP\" 2>/dev/null || true") {
				t.Errorf("a gVisor step is excused: %q", line)
			}
		}
		// The download is skipped only when the recorded checksum is the
		// pinned one and the files are there.
		for _, want := range []string{
			`if [ "$(cat "$GVISOR_STAMP" 2>/dev/null || true)" != "$want" ] || [ ! -x /usr/local/bin/runsc ]`,
			`GVISOR_STAMP=/etc/devkit/gvisor.sha512`,
			`aarch64) want="` + GvisorArm64SHA512 + `" ;;`,
			`x86_64)  want="` + GvisorAmd64SHA512 + `" ;;`,
			`"https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${GVISOR_ARCH}/gvisor.tar.zstd"`,
			`GVISOR_RELEASE="` + GvisorRelease + `"`,
			`chown -R root:root "$new"`,
			`chmod -R go-w "$new"`,
		} {
			if !strings.Contains(inst, want) {
				t.Errorf("the gVisor install should contain %q", want)
			}
		}
	})
}

// The checksum line, run as the script runs it: the pinned form passes the
// right file and refuses any other.
func TestGvisorChecksumLine(t *testing.T) {
	if _, err := exec.LookPath("sha512sum"); err != nil {
		t.Skip("sha512sum not installed")
	}
	s, err := System(dockerParams(func(c *project.Config) { c.Tools.ContainerRuntime = project.RuntimeGvisor }))
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^  if ! (printf .*sha512sum -c --quiet - >/dev/null 2>&1); then$`).FindStringSubmatch(s)
	if line == nil {
		t.Fatal("checksum line not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gvisor.tar.zstd"), []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512([]byte("archive"))
	for want, ok := range map[string]bool{hex.EncodeToString(sum[:]): true, GvisorArm64SHA512: false} {
		cmd := exec.Command("bash", "-c", line[1])
		cmd.Env = append(os.Environ(), "want="+want, "tmp="+dir)
		if err := cmd.Run(); (err == nil) != ok {
			t.Errorf("want %.16s...: passed=%v, should be %v", want, err == nil, ok)
		}
	}
}

// daemon.json keeps devkit's two defaults in every mode; gVisor modes
// register both gVisor runtimes and make the configured one the default.
func TestGvisorDaemonJSON(t *testing.T) {
	// With runc the runtime guard is the default, under its own name.
	base := map[string]any{"no-new-privileges": true, "ip": "127.0.0.1",
		"runtimes":        map[string]any{"devkit-runc": map[string]any{"path": "/usr/local/bin/devkit-runc-guard"}},
		"default-runtime": "devkit-runc"}
	if got := daemonJSON(t, mustSystem(t, dockerParams(nil))); !reflect.DeepEqual(got, base) {
		t.Errorf("runc: %v", got)
	}
	runtimes := map[string]any{
		"runsc":         map[string]any{"path": "/usr/local/bin/runsc", "runtimeArgs": []any{"--ignore-cgroups"}},
		"runsc-hostnet": map[string]any{"path": "/usr/local/bin/runsc", "runtimeArgs": []any{"--ignore-cgroups", "--network=host"}},
	}
	gvisorVariants(t, func(t *testing.T, p Params, s string) {
		want := map[string]any{"no-new-privileges": true, "ip": "127.0.0.1", "runtimes": runtimes,
			"default-runtime": map[project.ContainerRuntime]string{project.RuntimeGvisor: "runsc", project.RuntimeGvisorHostnet: "runsc-hostnet"}[p.Config.Tools.ContainerRuntime]}
		if got := daemonJSON(t, s); !reflect.DeepEqual(got, want) {
			t.Errorf("daemon.json:\n got %v\nwant %v", got, want)
		}
	})
	// Each runtime renders its own script, so a change of runtime changes
	// the VM's configuration and devkit up restarts it, starting the daemon
	// afresh with the new settings.
	seen := map[string]project.ContainerRuntime{}
	for _, rt := range []project.ContainerRuntime{project.RuntimeRunc, project.RuntimeGvisor, project.RuntimeGvisorHostnet} {
		fp, err := Fingerprint(dockerParams(func(c *project.Config) { c.Tools.ContainerRuntime = rt }))
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[fp]; dup {
			t.Errorf("%s and %s render the same script", rt, other)
		}
		seen[fp] = rt
	}
}

func mustSystem(t *testing.T, p Params) string {
	t.Helper()
	s, err := System(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Under network.enforce: host root's download goes through the proxy on the
// Mac, which must allow gVisor's bucket then, and only then.
func TestGvisorRootHosts(t *testing.T) {
	urlRe := regexp.MustCompile(`https?://([a-z0-9.-]+)/`)
	gvisorVariants(t, func(t *testing.T, p Params, s string) {
		f := egressproxy.NewFilter(RootHosts(p.Config))
		if !f.IsAllowed("storage.googleapis.com:443") {
			t.Errorf("RootHosts should allow gVisor's bucket: %v", RootHosts(p.Config))
		}
		block := s[index(t, s, gvisorMarker):index(t, s, daemonJSONOpen)]
		for _, m := range urlRe.FindAllStringSubmatch(block, -1) {
			if !f.IsAllowed(m[1] + ":443") {
				t.Errorf("root fetches from %s, which RootHosts does not allow", m[1])
			}
		}
	})
	for name, c := range map[string]*project.Config{
		"default":     params(nil).Config,
		"docker-runc": dockerParams(nil).Config,
	} {
		for _, h := range RootHosts(c) {
			if h == "storage.googleapis.com" {
				t.Errorf("%s: gVisor's bucket is for gVisor modes only", name)
			}
		}
	}
}

// The system and user scripts parse in every gVisor variant.
func TestGvisorScriptsParse(t *testing.T) {
	shellcheck, _ := exec.LookPath("shellcheck")
	dir := t.TempDir()
	gvisorVariants(t, func(t *testing.T, p Params, s string) {
		u, err := User(p)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.ReplaceAll(t.Name(), "/", "-")
		for kind, body := range map[string]string{"system": s, "user": u} {
			path := filepath.Join(dir, name+"-"+kind+".sh")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
				t.Errorf("%s does not parse: %s", kind, out)
			}
			if shellcheck != "" {
				if out, err := exec.Command(shellcheck, "--severity=error", "--shell=bash", path).CombinedOutput(); err != nil {
					t.Errorf("shellcheck %s:\n%s", kind, out)
				}
			}
		}
	})
}
