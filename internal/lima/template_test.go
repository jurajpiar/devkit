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
