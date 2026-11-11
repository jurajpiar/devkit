package lima

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
	"gopkg.in/yaml.v3"
)

func TestRenderIsValidYAML(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	c.Tools.Node = "22"
	out, err := Render(TemplateInput{Config: c, User: "alice", HostDir: "/Users/alice/demo", EgressSHA256: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n%s", err, out)
	}
	if doc["vmType"] != "vz" {
		t.Errorf("vmType = %v, want vz", doc["vmType"])
	}
	imgs := doc["images"].([]any)
	if len(imgs) != 2 || !strings.Contains(imgs[0].(map[string]any)["location"].(string), "minimal-cloudimg-arm64") {
		t.Errorf("expected pinned Ubuntu Minimal images, got %v", imgs)
	}
	if !strings.HasPrefix(imgs[0].(map[string]any)["digest"].(string), "sha256:") {
		t.Error("image digest must be pinned")
	}
	if m, ok := doc["mounts"].([]any); !ok || len(m) != 0 {
		t.Errorf("mounts should be empty by default, got %v", doc["mounts"])
	}
	ssh := doc["ssh"].(map[string]any)
	if ssh["localPort"] != 2222 {
		t.Errorf("ssh.localPort = %v", ssh["localPort"])
	}
	prov := doc["provision"].([]any)
	if len(prov) != 3 {
		t.Fatalf("expected 3 provision scripts, got %d", len(prov))
	}
	// The boot script must come first: it switches off what would otherwise
	// hold the system script back.
	var modes []any
	for _, p := range prov {
		modes = append(modes, p.(map[string]any)["mode"])
	}
	if !reflect.DeepEqual(modes, []any{"boot", "system", "user"}) {
		t.Errorf("provision modes = %v, want boot, system, user", modes)
	}
	sys := prov[1].(map[string]any)
	if sys["mode"] != "system" || !strings.Contains(sys["script"].(string), "MODE=\"allowlist\"") {
		t.Errorf("system provision script malformed: %v", sys)
	}
	containerd := doc["containerd"].(map[string]any)
	if containerd["user"] != false {
		t.Errorf("containers must be opt-in, got %v", containerd["user"])
	}
	// No host proxy may enter the guest: not from limactl's environment and
	// not from the macOS system settings, which only an empty env entry drops.
	if doc["propagateProxyEnv"] != false {
		t.Errorf("propagateProxyEnv = %v, want false", doc["propagateProxyEnv"])
	}
	env, _ := doc["env"].(map[string]any)
	for _, k := range proxyVars {
		if v, ok := env[k]; !ok || v != "" {
			t.Errorf("env.%s should be set to an empty string, got %v (present=%v)", k, v, ok)
		}
	}
	// Trust settings are pinned to devkit's values here, so a default.yaml
	// entry of the same name cannot land in Lima's block instead.
	for k, want := range map[string]string{"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt", "NODE_OPTIONS": "--use-openssl-ca", "PIP_CERT": "/etc/ssl/certs/ca-certificates.crt"} {
		if env[k] != want {
			t.Errorf("env.%s = %v, want %q", k, env[k], want)
		}
	}
	for _, k := range trustVars {
		if _, ok := env[k]; !ok {
			t.Errorf("env.%s should be reserved in the instance config", k)
		}
	}
}

func TestRenderHostEnforcement(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	c.Network.Enforce = project.EnforceHost
	out, err := Render(TemplateInput{Config: c, User: "alice", EgressSHA256: "deadbeef", HostProxy: "192.168.5.2:41234"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "-upstream 192.168.5.2:41234") {
		t.Error("the host proxy must reach the provisioning script")
	}
	if _, err := Render(TemplateInput{Config: c, User: "alice", EgressSHA256: "deadbeef"}); err == nil {
		t.Error("host enforcement without a host proxy must not render")
	}
}

func TestRenderMount(t *testing.T) {
	c := project.Default()
	c.Name = "demo"
	c.Source = project.SourceMount
	out, err := Render(TemplateInput{Config: c, User: "alice", HostDir: "/Users/alice/demo"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `location: "/Users/alice/demo"`) || !strings.Contains(out, "writable: false") {
		t.Errorf("mount not rendered read-only:\n%s", out)
	}
}

// bootScript returns the script of the rendered config's only boot entry.
func bootScript(t *testing.T) string {
	t.Helper()
	c := project.Default()
	c.Name = "demo"
	out, err := Render(TemplateInput{Config: c, User: "alice", EgressSHA256: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Provision []struct{ Mode, Script string }
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	var scripts []string
	for _, p := range doc.Provision {
		if p.Mode == "boot" {
			scripts = append(scripts, p.Script)
		}
	}
	if len(scripts) != 1 {
		t.Fatalf("want exactly one boot script, got %d", len(scripts))
	}
	return scripts[0]
}

// The boot script runs before provisioning on every boot, the first one
// included, so it is run here for real against a stand-in systemctl that
// records its arguments and prints a canned unit list.
func TestBootScriptMasksSnapdAndPollinate(t *testing.T) {
	script := bootScript(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "boot.sh")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("boot script does not parse: %s", out)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
echo "$*" >> "$CALLS"
if [ "$1" = list-unit-files ]; then cat "$LISTING"; fi
exit "$RC"
`
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	const listing = `snapd.apparmor.service                 enabled         enabled
snapd.seeded.service                   masked          enabled
snapd.service                          enabled         enabled
snapd.snap-repair.timer                enabled         enabled
snapd.socket                           enabled         enabled
snapd.mounts.target                    static          -
`
	cases := []struct {
		label, listing, rc string
		masked             []string
	}{
		{"units listed", listing, "0", []string{"snapd.apparmor.service", "snapd.seeded.service", "snapd.service", "snapd.snap-repair.timer", "snapd.socket", "snapd.mounts.target", "pollinate.service"}},
		{"no snapd", "", "0", []string{"pollinate.service"}},
		{"systemctl fails", listing, "1", []string{"snapd.apparmor.service", "snapd.seeded.service", "snapd.service", "snapd.snap-repair.timer", "snapd.socket", "snapd.mounts.target", "pollinate.service"}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			sub := t.TempDir()
			calls, list := filepath.Join(sub, "calls"), filepath.Join(sub, "listing")
			if err := os.WriteFile(list, []byte(c.listing), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", path)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "CALLS=" + calls, "LISTING=" + list, "RC=" + c.rc}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("the boot script must exit 0 whatever systemctl does: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(calls)
			// One call for every unit; when it fails, one per unit, so a
			// single bad name cannot leave the others running.
			want := "list-unit-files snapd.* --no-legend\n" + "mask --now --no-block " + strings.Join(c.masked, " ") + "\n"
			if c.rc != "0" {
				for _, u := range c.masked {
					want += "mask --now --no-block " + u + "\n"
				}
			}
			if string(got) != want {
				t.Errorf("systemctl calls:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
