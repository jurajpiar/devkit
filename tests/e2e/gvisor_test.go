package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDockerGvisor checks tools.container_runtime on a real VM: with gvisor,
// containers run under gVisor's runsc by default, from the pinned release,
// behind the same firewall and proxy, with the workspace and published
// ports working; with gvisor-hostnet, Compose service names work too and
// the egress controls still hold.
//
// It downloads gVisor from Google's release bucket inside the VM.
func TestDockerGvisor(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2egvisor-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "gvisor e2e\n")
	writeFile(t, filepath.Join(dir, "compose.yaml"), `services:
  web:
    image: busybox:1.36
    command: sh -c 'echo from-web > /i; httpd -f -h /'
  client:
    image: busybox:1.36
    command: wget -Y off -T 8 -qO- http://web/i
    depends_on: [web]
`)
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	cfg := filepath.Join(dir, "devkit.yaml")
	setYAML(t, cfg, "# sudo: false", "sudo: true")
	setYAML(t, cfg, "containers: false", "containers: docker\n  container_runtime: gvisor\n  # was: false")
	setYAML(t, cfg, "  allow:\n", "  allow:\n    - registry-1.docker.io\n    - auth.docker.io\n    - production.cloudflare.docker.com\n    - production.cloudfront.docker.com\n    - \"**.r2.cloudflarestorage.com\"\n    - example.com\n")
	s.mustRun("up", "--no-install")

	sh := func(cmd string) string { out, _ := s.shell(cmd + " 2>&1; echo exit=$?"); return out }
	ok := func(out string) bool { return strings.Contains(out, "exit=0") }
	hasLine := func(out, want string) bool {
		for _, l := range strings.Split(out, "\n") {
			if strings.TrimSpace(l) == want {
				return true
			}
		}
		return false
	}
	if out := sh("docker pull -q busybox:1.36"); !ok(out) {
		t.Fatalf("pull through the proxy: %s", out)
	}
	// Read again after each restart: a restart may boot a kernel that a
	// security update installed.
	vmKernel := func() string { return strings.TrimSpace(strings.Split(sh("uname -r"), "\n")[0]) }
	guestKernel := vmKernel()

	// underGvisor: a container started with no flags sees gVisor's kernel,
	// not the VM's.
	underGvisor := func(t *testing.T, want string) {
		t.Helper()
		if out := sh("docker info --format '{{.DefaultRuntime}}'"); !hasLine(out, want) {
			t.Errorf("default runtime should be %s: %s", want, out)
		}
		out := sh("docker run --rm busybox:1.36 sh -c 'uname -r; dmesg | head -n 5'")
		if !ok(out) || !strings.Contains(strings.ToLower(out), "gvisor") {
			t.Fatalf("a container started with no flags should see gVisor's kernel: %s", out)
		}
		if guestKernel == "" || hasLine(out, guestKernel) {
			t.Errorf("the container saw the VM's own kernel %q: %s", guestKernel, out)
		}
	}
	egressHolds := func(t *testing.T) {
		t.Helper()
		if out := sh("docker run --rm busybox:1.36 wget -Y off -T 6 -qO- http://1.1.1.1/"); ok(out) {
			t.Errorf("a container connected directly: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 nslookup -timeout=5 example.com"); ok(out) {
			t.Errorf("a container resolved a name itself: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 nc -w 5 192.168.5.2 22 </dev/null"); ok(out) {
			t.Errorf("a container reached the Mac: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 wget -T 10 -qO- http://example.com/"); !strings.Contains(out, "Example Domain") {
			t.Errorf("a container should reach an allowed host through the proxy: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 wget -T 10 -qO- http://neverssl.com/"); ok(out) || !strings.Contains(out, "403") {
			t.Errorf("a host not on the allowlist should be refused by the proxy: %s", out)
		}
		// With the capability, a container still configures gVisor's
		// network stack, not the VM's: nothing appears in the VM.
		out := sh("docker run --rm --cap-add NET_ADMIN busybox:1.36 ip link add dkgv0 type dummy; ip link show dkgv0")
		if ok(out) {
			t.Errorf("a container with NET_ADMIN created an interface in the VM: %s", out)
		}
	}

	t.Run("gvisor is installed from the pinned release and is the default", func(t *testing.T) {
		out := sh("runsc --version; stat -c '%U %a %n' /usr/local/bin/runsc")
		if !strings.Contains(out, "release-") || !strings.Contains(out, "root 755 /usr/local/bin/runsc") {
			t.Errorf("runsc should be root's, from a named release: %s", out)
		}
		if out := sh("test -w /usr/local/bin/runsc || test -w /usr/local/bin/gvisor-bin || test -w /etc/devkit/docker/daemon.json"); ok(out) {
			t.Errorf("the sandbox user can write gVisor's files or the daemon's settings: %s", out)
		}
		underGvisor(t, "runsc")
		// runc stays registered: choosing it is the user's to do until the
		// API is filtered. The check is that it is not what runs by default.
		if out := sh("docker run --rm --runtime=runc busybox:1.36 uname -r"); !hasLine(out, guestKernel) {
			t.Errorf("--runtime=runc should still run on the VM's kernel: %s", out)
		}
	})

	t.Run("egress and the kernel surface under gvisor", egressHolds)

	t.Run("workspace, published port and build under gvisor", func(t *testing.T) {
		out := sh(`cd ~/workspace && echo by-user > u-file && chmod 644 u-file && docker run --rm -v "$PWD:/w" busybox:1.36 sh -c 'echo edit >> /w/u-file && echo c > /w/c-file' && stat -c '%U' c-file && tail -n 1 u-file && rm -f u-file c-file`)
		me := strings.TrimSpace(strings.Split(sh("id -un"), "\n")[0])
		if !ok(out) || !hasLine(out, "edit") || !hasLine(out, me) {
			t.Errorf("container root should edit and create in the workspace as the sandbox user: %s", out)
		}
		out = sh(`docker rm -f e2e-web >/dev/null 2>&1; docker run -d --name e2e-web -p 18080:80 busybox:1.36 sh -c 'echo hi > /i; httpd -f -h /' >/dev/null && sleep 4 && wget -T 5 -qO- http://127.0.0.1:18080/i && ss -ltnH | awk '$4 ~ /:18080$/ {print "LISTEN " $4}'; rc=$?; docker rm -f e2e-web >/dev/null 2>&1; (exit $rc)`)
		if !hasLine(out, "hi") || !hasLine(out, "LISTEN 127.0.0.1:18080") || strings.Count(out, "LISTEN ") != 1 {
			t.Errorf("a published port should answer in the VM and listen on loopback only: %s", out)
		}
		out = sh(`b=$(mktemp -d) && printf 'FROM busybox:1.36\nRUN wget -T 10 -qO- http://example.com/ | grep -q "Example Domain"\n' > $b/Dockerfile && docker build -q -t e2e-gv-build $b`)
		if !ok(out) {
			t.Errorf("docker build should work with gVisor as the default runtime: %s", out)
		}
	})

	t.Run("a restart keeps gvisor the default", func(t *testing.T) {
		s.mustRun("down")
		s.mustRun("up", "--no-sync", "--no-install")
		guestKernel = vmKernel()
		underGvisor(t, "runsc")
	})

	t.Run("gvisor-hostnet: service names work and egress still holds", func(t *testing.T) {
		setYAML(t, cfg, "container_runtime: gvisor", "container_runtime: gvisor-hostnet")
		s.mustRun("up", "--no-sync", "--no-install")
		guestKernel = vmKernel()
		underGvisor(t, "runsc-hostnet")
		out := sh("cd ~/workspace && docker compose up -d web && sleep 2 && docker compose run --rm client; rc=$?; docker compose down >/dev/null 2>&1; (exit $rc)")
		if !hasLine(out, "from-web") {
			t.Errorf("one Compose service should reach another by name under gvisor-hostnet: %s", out)
		}
		egressHolds(t)
	})

	t.Run("back to runc", func(t *testing.T) {
		setYAML(t, cfg, "container_runtime: gvisor-hostnet", "container_runtime: runc")
		s.mustRun("up", "--no-sync", "--no-install")
		guestKernel = vmKernel()
		if out := sh("docker info --format '{{.DefaultRuntime}}'"); !hasLine(out, "runc") {
			t.Errorf("default runtime should be runc again: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 uname -r"); !hasLine(out, guestKernel) {
			t.Errorf("a container should run on the VM's kernel again: %s", out)
		}
	})
}
