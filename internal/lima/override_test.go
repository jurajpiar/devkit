package lima

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckOverrideFile(t *testing.T) {
	dir := t.TempDir()
	if err := CheckOverrideFile(filepath.Join(dir, "missing.yaml")); err != nil {
		t.Errorf("missing override should pass: %v", err)
	}
	cases := map[string]string{
		"cpus: 4\nenv:\n  FOO: bar\n  HTTP_PROXY: \"\"\n": "",
		"propagateProxyEnv: true\n":                       "propagateProxyEnv: true",
		"env:\n  https_proxy: http://corp:3128\n":         "env.https_proxy",
	}
	for content, want := range cases {
		p := filepath.Join(dir, "override.yaml")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		err := CheckOverrideFile(p)
		switch {
		case want == "" && err != nil:
			t.Errorf("%q should pass: %v", content, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%q should fail mentioning %s, got %v", content, want, err)
		}
	}
}
