// Package e2e creates a real sandbox VM and checks devkit's guarantees.
//
// Run with: DEVKIT_E2E=1 go test ./tests/e2e/ -v -timeout 30m
// The first run downloads an Ubuntu image and takes several minutes.
package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func repoRootDir(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func buildDevkitBinary(t *testing.T) string {
	t.Helper()
	root := repoRootDir(t)
	bin := filepath.Join(t.TempDir(), "devkit")
	cmd := exec.Command("make", "-s", "build")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make build: %v\n%s", err, out)
	}
	if err := os.Rename(filepath.Join(root, "devkit"), bin); err != nil {
		t.Fatal(err)
	}
	return bin
}

type sandbox struct {
	t      *testing.T
	devkit string
	dir    string
	name   string
}

func (s *sandbox) run(args ...string) (string, error) {
	cmd := exec.Command(s.devkit, args...)
	cmd.Dir = s.dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	s.t.Logf("$ devkit %s\n%s", strings.Join(args, " "), out.String())
	return out.String(), err
}

func (s *sandbox) mustRun(args ...string) string {
	out, err := s.run(args...)
	if err != nil {
		s.t.Fatalf("devkit %s failed: %v", strings.Join(args, " "), err)
	}
	return out
}

// shell runs a command in the VM and returns combined output and error.
func (s *sandbox) shell(cmd string) (string, error) {
	return s.run("shell", cmd)
}

func TestSandboxGuarantees(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}

	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2e-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}

	// A tiny Node project with one dependency.
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"e2e","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}`)
	writeFile(t, filepath.Join(dir, "secret.txt"), "copied-marker")

	s.mustRun("init", "--name", name)
	t.Cleanup(func() {
		_, _ = s.run("rm", "--force")
	})

	start := time.Now()
	s.mustRun("up")
	t.Logf("devkit up took %s", time.Since(start).Round(time.Second))

	t.Run("workspace copied and deps installed", func(t *testing.T) {
		out, err := s.shell("cat secret.txt && test -d node_modules/is-odd && node --version")
		if err != nil || !strings.Contains(out, "copied-marker") || !strings.Contains(out, "v22.") {
			t.Fatalf("workspace or node missing: %v\n%s", err, out)
		}
	})

	t.Run("no sudo", func(t *testing.T) {
		out, err := s.shell("sudo -n true 2>&1; echo exit=$?")
		if err != nil || !strings.Contains(out, "exit=1") {
			t.Fatalf("sudo should be unavailable: %v\n%s", err, out)
		}
	})

	t.Run("host unreachable", func(t *testing.T) {
		// Direct: the firewall must reject it. Via proxy: the allowlist must block it.
		out, _ := s.shell("curl -s -m 5 --noproxy '*' -o /dev/null -w '%{http_code}' http://host.lima.internal:2222/ ; echo exit=$?")
		if !strings.Contains(out, "exit=7") && !strings.Contains(out, "exit=28") {
			t.Fatalf("direct connection to host should be refused: %s", out)
		}
		out, _ = s.shell("curl -s -m 5 -o /dev/null -w '%{http_code}' http://host.lima.internal:2222/ ; echo exit=$?")
		if !strings.Contains(out, "403") {
			t.Fatalf("proxied connection to host should be blocked: %s", out)
		}
	})

	t.Run("allowlist blocks and logs", func(t *testing.T) {
		out, _ := s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' https://example.com/ ; echo exit=$?")
		if strings.Contains(out, "200") {
			t.Fatalf("example.com should be blocked: %s", out)
		}
		out, _ = s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/is-odd ; echo exit=$?")
		if !strings.Contains(out, "200") {
			t.Fatalf("registry.npmjs.org should be allowed: %s", out)
		}
		logs := s.mustRun("logs")
		if !strings.Contains(logs, "BLOCKED") || !strings.Contains(logs, "example.com") {
			t.Fatalf("audit log should record the block:\n%s", logs)
		}
	})

	t.Run("direct connections bypassing the proxy are rejected", func(t *testing.T) {
		out, _ := s.shell("curl -s -m 10 --noproxy '*' -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ ; echo exit=$?")
		if strings.Contains(out, "200") {
			t.Fatalf("firewall should reject traffic not from the proxy: %s", out)
		}
	})

	t.Run("air gap", func(t *testing.T) {
		s.mustRun("up", "--network", "none", "--no-sync", "--no-install")
		out, _ := s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ ; echo exit=$?")
		if strings.Contains(out, "200") {
			t.Fatalf("air-gapped VM reached the internet: %s", out)
		}
		out, _ = s.shell("getent hosts example.com; echo exit=$?")
		if strings.Contains(out, "exit=0") {
			t.Fatalf("DNS should fail when air-gapped: %s", out)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
