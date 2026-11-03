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

	t.Run("toolchain lockfile recorded and enforced", func(t *testing.T) {
		lock, err := os.ReadFile(filepath.Join(dir, ".devkit", "mise.lock"))
		if err != nil || !strings.Contains(string(lock), "[[tools.node]]") || !strings.Contains(string(lock), "checksum = \"sha256:") {
			t.Fatalf("first up should record node's checksum in .devkit/mise.lock: %v\n%s", err, lock)
		}
		out := s.mustRun("up", "--no-sync", "--no-install")
		if !strings.Contains(out, "pinned by .devkit/mise.lock") {
			t.Fatalf("second up should install from the lockfile:\n%s", out)
		}
		// The sandbox user cannot loosen the manager's settings: they are
		// root-owned, and plugin backends stay off.
		out, _ = s.shell("mise settings get disable_backends; mise settings get paranoid; ls -l /etc/mise/config.toml")
		if !strings.Contains(out, "asdf") || !strings.Contains(out, "true") || !strings.Contains(out, "root root") {
			t.Fatalf("mise settings should be pinned by root: %s", out)
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

	t.Run("open mode is still audited", func(t *testing.T) {
		s.mustRun("up", "--network", "open", "--no-sync", "--no-install")
		out, _ := s.shell("curl -s -m 10 -o /dev/null -w '%{http_code}' https://example.com/ ; echo exit=$?")
		if !strings.Contains(out, "200") {
			t.Fatalf("open mode should allow example.com via the proxy: %s", out)
		}
		out, _ = s.shell("curl -s -m 10 --noproxy '*' -o /dev/null -w '%{http_code}' https://example.com/ ; echo exit=$?")
		if strings.Contains(out, "200") {
			t.Fatalf("open mode must reject connections that bypass the proxy: %s", out)
		}
		// Port 53 is not a loophole: only the resolvers accept it.
		out, _ = s.shell("timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>&1; echo exit=$?")
		if strings.Contains(out, "exit=0") {
			t.Fatalf("direct TCP to port 53 on an arbitrary host should be rejected: %s", out)
		}
		if logs := s.mustRun("logs"); !strings.Contains(logs, "ALLOWED") || !strings.Contains(logs, "example.com") {
			t.Fatalf("audit log should record the allowed request:\n%s", logs)
		}
	})

	t.Run("allow_host opens the host", func(t *testing.T) {
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: false", "allow_host: true")
		s.mustRun("up", "--no-sync", "--no-install")
		out, _ := s.shell("timeout 5 bash -c 'exec 3<>/dev/tcp/host.lima.internal/2222' 2>&1; echo exit=$?")
		if !strings.Contains(out, "exit=0") {
			t.Fatalf("host should be reachable with allow_host: %s", out)
		}
		out, _ = s.shell("echo $NO_PROXY")
		if !strings.Contains(out, "host.lima.internal") {
			t.Fatalf("host should bypass the proxy with allow_host: %s", out)
		}
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: true", "allow_host: false")
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

// TestNixToolchain builds a second VM with manager: nix. It downloads Nix
// and a nodejs closure from cache.nixos.org, so it is gated separately.
func TestNixToolchain(t *testing.T) {
	if os.Getenv("DEVKIT_E2E_NIX") == "" {
		t.Skip("set DEVKIT_E2E_NIX=1 to run (creates a real VM and installs Nix)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2enix-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"e2e","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}`)
	writeFile(t, filepath.Join(dir, ".nvmrc"), "22\n")

	s.mustRun("init", "--name", name, "--toolchain", "nix")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	if flake, err := os.ReadFile(filepath.Join(dir, "flake.nix")); err != nil || !strings.Contains(string(flake), "nodejs_22") {
		t.Fatalf("init should write a flake with the detected node: %v\n%s", err, flake)
	}

	start := time.Now()
	s.mustRun("up")
	t.Logf("devkit up took %s", time.Since(start).Round(time.Second))

	if _, err := os.Stat(filepath.Join(dir, "flake.lock")); err != nil {
		t.Fatal("up should copy flake.lock back to the project")
	}
	out, err := s.shell("node --version && test -d node_modules/is-odd && echo deps-ok")
	if err != nil || !strings.Contains(out, "v22.") || !strings.Contains(out, "deps-ok") {
		t.Fatalf("node from the dev shell and deps expected: %v\n%s", err, out)
	}
	// Outside the dev shell there is no node: the toolchain lives in the store.
	out, _ = s.run("shell", "bash", "-c", "'command -v node || echo no-node'")
	if !strings.Contains(out, "node") {
		t.Fatalf("unexpected: %s", out)
	}
	logs := s.mustRun("logs")
	if !strings.Contains(logs, "cache.nixos.org") {
		t.Fatalf("nix downloads should go through the audited proxy:\n%s", logs)
	}
	out, _ = s.shell("sudo -n true 2>&1; echo exit=$?")
	if !strings.Contains(out, "exit=1") {
		t.Fatalf("sudo should be unavailable: %s", out)
	}
}

// setYAML replaces one line fragment in devkit.yaml in place.
func setYAML(t *testing.T, path, from, to string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), from) {
		t.Fatalf("%s does not contain %q", path, from)
	}
	writeFile(t, path, strings.Replace(string(data), from, to, 1))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
