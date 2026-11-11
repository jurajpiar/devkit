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
		// The capability that would let a container reconfigure a network
		// stack is refused by the filter under every runtime, so the
		// request never reaches gVisor.
		if out := sh("docker run --rm --cap-add NET_ADMIN busybox:1.36 true"); ok(out) || !strings.Contains(out, "devkit") {
			t.Errorf("--cap-add NET_ADMIN should be refused by the filter: %s", out)
		}
		// A bind source the filter cannot see through: a symlink in a
		// directory only the sandbox user may enter. Whichever layer
		// refuses it, it must not be mounted.
		out := sh(`cd ~/workspace && rm -rf priv && mkdir -m 700 priv && ln -s /etc priv/l && docker run --rm -v "$PWD/priv/l:/x" busybox:1.36 ls /x/passwd; rc=$?; rm -rf priv; (exit $rc)`)
		if ok(out) || !strings.Contains(out, "devkit") {
			t.Errorf("a bind source the filter cannot resolve should be refused under gVisor: %s", out)
		}
		// The swap the filter cannot see at all: a real directory when the
		// container is created, a symlink to the daemon's sockets when it
		// starts. Only a check of the mounts as made refuses this, and
		// gVisor's runtime has to be behind one as runc is. The container
		// also mounts the workspace and tries to leave a file there, so a
		// process that ran at all is seen.
		out = sh(`cd ~/workspace && rm -rf swap ran && docker rm -f gv-swap >/dev/null 2>&1; mkdir swap && docker create --name gv-swap -v "$PWD:/w" -v "$PWD/swap:/s" busybox:1.36 sh -c 'touch /w/ran; ls /s' >/dev/null && rmdir swap && ln -s /var/lib/devkit-docker/run swap && docker start -a gv-swap; rc=$?; ls ran 2>/dev/null && echo PROCESS-RAN; docker rm -f gv-swap >/dev/null 2>&1; rm -rf swap ran; (exit $rc)`)
		if ok(out) || strings.Contains(out, "PROCESS-RAN") || strings.Contains(out, "docker.sock") {
			t.Errorf("under gVisor a directory swapped for a symlink after the request was mounted, or the container's process ran: %s", out)
		}
		if !strings.Contains(out, "a mount comes from outside the workspace") {
			t.Errorf("the swapped mount should be refused by devkit's runtime guard under gVisor: %s", out)
		}
		// And an ordinary bind still works behind that check.
		if out := sh(`cd ~/workspace && docker run --rm -v "$PWD:/w" -v gv-vol:/v --tmpfs /t --init busybox:1.36 sh -c 'echo x > /w/gv-ok && cat /w/gv-ok' && rm -f gv-ok; docker volume rm gv-vol >/dev/null 2>&1`); !hasLine(out, "x") {
			t.Errorf("an ordinary workspace bind, volume, tmpfs and --init should work under gVisor: %s", out)
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
		// With the API filtered the runtime is a control, not a default:
		// asking for runc by name is refused by devkit.
		if out := sh("docker run --rm --runtime=runc busybox:1.36 uname -r"); ok(out) || !strings.Contains(out, "devkit") {
			t.Errorf("--runtime=runc should be refused by the filter under gvisor: %s", out)
		}
		if out := sh("docker run --rm --runtime=runsc-hostnet busybox:1.36 true"); ok(out) || !strings.Contains(out, "devkit") {
			t.Errorf("the other gVisor runtime should be refused too; only the configured one runs: %s", out)
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

	// A container with --restart always is started again by the daemon
	// itself when the daemon starts, with no call through the filter and so
	// no checkStart. Only the runtime guard in front of runsc sees that
	// start: a bind source swapped for a symlink out of the workspace while
	// the daemon was down must not come up mounted.
	t.Run("a restart-policy start after a daemon restart is checked by the guard", func(t *testing.T) {
		defer sh(`systemctl is-active --quiet devkit-dockerd.service || sudo systemctl start devkit-dockerd.service; cd ~/workspace && docker rm -f gv-restart >/dev/null 2>&1; rm -rf gvr`)
		out := sh(`cd ~/workspace && docker rm -f gv-restart >/dev/null 2>&1; rm -rf gvr && mkdir gvr && echo inside-marker > gvr/m && docker run -d --name gv-restart --restart always -v "$PWD/gvr:/s" busybox:1.36 sleep 2147483647 >/dev/null && sleep 2 && docker exec gv-restart cat /s/m && docker inspect -f 'started={{.State.StartedAt}}' gv-restart`)
		if !ok(out) || !hasLine(out, "inside-marker") {
			t.Fatalf("a container with a workspace bind and --restart always should run and see the bind under gVisor: %s", out)
		}
		before := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "started=") {
				before = strings.TrimSpace(l)
			}
		}
		// The swap, as root, while the daemon is down: the same outside
		// target as the swap above, which the Docker account can read.
		out = sh(`sudo systemctl stop devkit-dockerd.service && cd ~/workspace && rm -rf gvr && ln -s /var/lib/devkit-docker/run gvr && sudo systemctl start devkit-dockerd.service`)
		if !ok(out) {
			t.Fatalf("stopping the daemon, swapping the bind source and starting it again: %s", out)
		}
		// The daemon starts restart-policy containers before it answers; the
		// extra wait leaves room for one that is slower.
		out = sh(`for i in $(seq 1 30); do docker ps >/dev/null 2>&1 && break; sleep 2; done; sleep 10; docker ps --format '{{.Names}}' >/dev/null && echo DAEMON-UP`)
		if !hasLine(out, "DAEMON-UP") {
			t.Fatalf("the daemon should answer again after its restart, or this proves nothing: %s", out)
		}
		state := sh(`docker inspect -f 'running={{.State.Running}} restarting={{.State.Restarting}} restarts={{.RestartCount}} started={{.State.StartedAt}} error={{.State.Error}}' gv-restart`)
		t.Logf("the container after the daemon's restart: %s", state)
		t.Logf("the daemon's log of the refusal: %s", sh(`sudo journalctl -u devkit-dockerd.service --since '-5min' --no-pager -o cat | grep -iE 'refused|outside the workspace' | tail -n 5`))
		if out := sh(`docker exec gv-restart ls /s`); ok(out) && strings.Contains(out, "docker.sock") {
			t.Errorf("after a daemon restart, a container started by its restart policy has the swapped bind's outside target mounted: %s", out)
		}
		// Not started again at all would leave the old mount, and the claim
		// untested: the daemon must have tried the start the guard judges.
		if strings.Contains(state, "running=true") && before != "" && strings.Contains(state, before+" ") {
			t.Errorf("the container kept its old start (%s), so the daemon's own start was never tried: %s", before, state)
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
		// runc behind devkit's guard, which checks the mounts as made.
		if out := sh("docker info --format '{{.DefaultRuntime}}'"); !hasLine(out, "devkit-runc") {
			t.Errorf("default runtime should be the guarded runc again: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 uname -r"); !hasLine(out, guestKernel) {
			t.Errorf("a container should run on the VM's kernel again: %s", out)
		}
	})
}
