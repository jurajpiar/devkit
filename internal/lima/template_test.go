package lima

import (
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
	if len(prov) != 2 {
		t.Fatalf("expected 2 provision scripts, got %d", len(prov))
	}
	sys := prov[0].(map[string]any)
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

// Lima's own rootless containerd is for containers: true only. With docker
// the daemon is devkit's, under an account of its own.
func TestContainerdOnlyForContainersTrue(t *testing.T) {
	for v, want := range map[project.Containers]bool{
		project.ContainersOff:        false,
		project.ContainersContainerd: true,
		project.ContainersDocker:     false,
	} {
		c := project.Default()
		c.Name = "demo"
		c.Tools.Containers = v
		out, err := Render(TemplateInput{Config: c, User: "alice", HostDir: "/Users/alice/demo", EgressSHA256: "deadbeef"})
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%q: rendered config is not valid YAML: %v", v, err)
		}
		if got := doc["containerd"].(map[string]any)["user"]; got != want {
			t.Errorf("containers %q: containerd.user = %v, want %v", v, got, want)
		}
	}
}
