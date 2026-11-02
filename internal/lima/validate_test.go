package lima

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

// TestLimactlValidate asks the real limactl to validate the rendered config.
// Skipped when Lima is not installed.
func TestLimactlValidate(t *testing.T) {
	if CheckInstalled() != nil {
		t.Skip("limactl not installed")
	}
	c := project.Default()
	c.Name = "validate"
	c.Tools.Node = "22"
	out, err := Render(TemplateInput{Config: c, User: "alice", HostDir: t.TempDir(), EgressSHA256: "x"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lima.yaml")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Validate(context.Background(), path); err != nil {
		t.Fatalf("limactl rejected the config: %v\n%s", err, out)
	}
}
