package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDocker checks tools.containers: docker on a real VM: rootless Docker
// runs under its own account, the sandbox user reaches it without any
// setup, containers are behind the same firewall and proxy as everything
// else, user namespaces stay closed to the sandbox user, the workspace is
// shared so that container root is the sandbox user on disk (and stays so
// after devkit sync), builds and Compose work, and a container that
// restarts with the VM gets nothing before the firewall.
func TestDocker(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2edocker-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "docker e2e\n")
	// A Compose file at the workspace root: its service names must end up
	// in the no_proxy that devkit hands to containers.
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
	// sudo is for the test's own inspection. Every check of what the
	// sandbox user can do runs without it.
	setYAML(t, cfg, "# sudo: false", "sudo: true")
	setYAML(t, cfg, "containers: false", "containers: docker")
	// Docker Hub is not allowed by default: an allowlist entry is the
	// owner's decision. These are the hosts a pull from it uses.
	setYAML(t, cfg, "  allow:\n", "  allow:\n    - registry-1.docker.io\n    - auth.docker.io\n    - production.cloudflare.docker.com\n    - production.cloudfront.docker.com\n    - \"**.r2.cloudflarestorage.com\"\n    - example.com\n")
	s.mustRun("up", "--no-install")

	const account = "devkit-docker"
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
	// CAP_NET_ADMIN in a namespace the caller owns, without any kernel
	// module (loading is locked). The token is printed with printf so that
	// it is not in the command line a failing tool may quote back.
	const inner = `sh -c 'ip link set lo up && ip addr add 10.99.99.1/32 dev lo && printf "NETADMIN-%s\n" OK'`
	usernsClosed := func(t *testing.T) {
		t.Helper()
		if out := sh("timeout 30 unshare -Urn " + inner); hasLine(out, "NETADMIN-OK") {
			t.Errorf("the sandbox user got CAP_NET_ADMIN in a user namespace: %s", out)
		}
		if out := sh("timeout 30 rootlesskit unshare -n " + inner); hasLine(out, "NETADMIN-OK") {
			t.Errorf("the sandbox user got CAP_NET_ADMIN through rootlesskit: %s", out)
		}
		// The paths Ubuntu's profiles exempt, read from the profiles.
		out := sh(`for p in rootlesskit runc slirp4netns; do for b in $(sed -n 's/^profile [^ ]* \(\/[^ ]*\) flags=(unconfined).*/\1/p' /etc/apparmor.d/$p 2>/dev/null); do [ -e "$b" ] || continue; if [ -x "$b" ]; then echo "EXECUTABLE $b"; else echo "closed $b"; fi; done; done`)
		if strings.Contains(out, "EXECUTABLE") || strings.Count(out, "closed /") < 3 {
			t.Errorf("the exempted programs must not be executable by the sandbox user (want 3 closed): %s", out)
		}
		// Every other stock exemption is disabled, so a package that ships
		// an exempted program opens nothing.
		out = sh(`n=0; for f in /etc/apparmor.d/*; do [ -f "$f" ] || continue; grep -q 'flags=(unconfined)' "$f" && grep -qE '^\s*userns,' "$f" || continue; case "$(basename "$f")" in rootlesskit|runc|slirp4netns) continue;; esac; n=$((n+1)); [ -e "/etc/apparmor.d/disable/$(basename "$f")" ] || echo "ENABLED $f"; done; echo "checked=$n"`)
		if strings.Contains(out, "ENABLED") || strings.Contains(out, "checked=0") {
			t.Errorf("stock user-namespace exemptions left enabled: %s", out)
		}
	}
	dockerWorks := func(t *testing.T) {
		t.Helper()
		if out := sh("docker run --rm busybox:1.36 echo ran-in-a-container"); !hasLine(out, "ran-in-a-container") {
			t.Errorf("a container should run: %s", out)
		}
	}

	t.Run("the daemon runs under its own account and the user reaches it", func(t *testing.T) {
		out := sh("docker info --format '{{.SecurityOptions}}'")
		if !ok(out) || !strings.Contains(out, "rootless") || !strings.Contains(out, "no-new-privileges") {
			t.Fatalf("docker info as the sandbox user, in a plain devkit shell: %s", out)
		}
		out = sh("ps -o user:32=,comm= -C dockerd -C rootlesskit -C slirp4netns | sort -u")
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] != account {
				t.Errorf("%s runs as %s, want %s", f[1], f[0], account)
			}
		}
		if !strings.Contains(out, "dockerd") || !strings.Contains(out, "slirp4netns") {
			t.Errorf("dockerd and slirp4netns should be running: %s", out)
		}
		if out := sh("systemctl is-active docker.service containerd.service"); hasLine(out, "active") {
			t.Errorf("the rootful daemon must not run: %s", out)
		}
		if out := sh("ls /var/lib/" + account + "/.local/share/docker"); ok(out) {
			t.Errorf("the sandbox user can read the account's image store: %s", out)
		}
		if out := sh("cat /proc/sys/kernel/modules_disabled"); !hasLine(out, "1") {
			t.Errorf("module loading should be locked with Docker on: %s", out)
		}
		if out := sh("docker pull -q busybox:1.36"); !ok(out) {
			t.Fatalf("pull through the proxy: %s", out)
		}
		dockerWorks(t)
	})

	t.Run("containers are behind the firewall and the proxy", func(t *testing.T) {
		// devkit hands containers the proxy variables, so "direct" has to
		// say so: wget -Y off ignores them.
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
			t.Errorf("a container should reach an allowed host through the proxy with no flags: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 wget -T 10 -qO- http://neverssl.com/"); ok(out) || !strings.Contains(out, "403") {
			t.Errorf("a host not on the allowlist should be refused by the proxy: %s", out)
		}
		if out := s.mustRun("logs", "-n", "200"); !strings.Contains(out, "example.com") {
			t.Errorf("container traffic should be in the audit log:\n%s", out)
		}
	})

	t.Run("user namespaces stay closed to the sandbox user", func(t *testing.T) {
		usernsClosed(t)
		// Not vacuous: the account, which may execute rootlesskit, does
		// get the capability.
		out := sh("sudo -u " + account + " env XDG_RUNTIME_DIR=/run/user/$(id -u " + account + ") timeout 30 rootlesskit unshare -n " + inner)
		if !hasLine(out, "NETADMIN-OK") {
			t.Fatalf("the control is broken: the account's rootlesskit must get CAP_NET_ADMIN, or every closed check is vacuous: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 unshare -U true"); ok(out) {
			t.Errorf("a container created a user namespace: %s", out)
		}
	})

	t.Run("container root is the sandbox user in the workspace", func(t *testing.T) {
		out := sh(`cd ~/workspace && echo by-user > u-file && chmod 644 u-file && mkdir -p u-dir && chmod 755 u-dir && docker run --rm -v "$PWD:/w" busybox:1.36 sh -c 'echo edit >> /w/u-file && echo c > /w/u-dir/c-file && chmod 600 /w/u-dir/c-file && stat -c %u /w/u-file' && stat -c '%U %a' u-dir/c-file && cat u-dir/c-file && rm -r u-dir u-file`)
		if !ok(out) || !hasLine(out, "0") {
			t.Errorf("container root should read, edit and create in the workspace, and see the user's files as its own: %s", out)
		}
		me := strings.TrimSpace(strings.Split(sh("id -un"), "\n")[0])
		if !hasLine(out, me+" 600") {
			t.Errorf("a file container root made should belong to %s on disk: %s", me, out)
		}
		// devkit sync extracts an archive as the sandbox user, with modes
		// from the Mac. What it brings must be as writable to container
		// root as what was there before.
		if err := os.MkdirAll(filepath.Join(dir, "src", "deep"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "src", "deep", "synced.txt"), "from the mac\n")
		s.mustRun("sync")
		out = sh(`cd ~/workspace && docker run --rm -v "$PWD:/w" busybox:1.36 sh -c 'echo x >> /w/src/deep/synced.txt && echo x > /w/src/deep/new && echo x >> /w/README.md' && tail -n 1 src/deep/synced.txt && rm src/deep/new`)
		if !ok(out) || !hasLine(out, "x") {
			t.Errorf("container root should write what devkit sync brought: %s", out)
		}
		if out := sh(`docker run --rm -v "$HOME/.ssh:/s" busybox:1.36 ls /s`); ok(out) {
			t.Errorf("a container read ~/.ssh, outside the workspace: %s", out)
		}
		if out := sh("sudo -u " + account + " ls $HOME/.ssh"); ok(out) {
			t.Errorf("the account read ~/.ssh: %s", out)
		}
	})

	t.Run("build, compose and published ports", func(t *testing.T) {
		out := sh(`b=$(mktemp -d) && printf 'FROM busybox:1.36\nRUN wget -T 10 -qO- http://example.com/ | grep -q "Example Domain"\n' > $b/Dockerfile && docker build -q -t e2e-build $b`)
		if !ok(out) {
			t.Errorf("docker build with a RUN step that fetches from an allowed host: %s", out)
		}
		out = sh(`b=$(mktemp -d) && printf 'FROM busybox:1.36\nRUN wget -Y off -T 6 -qO- http://1.1.1.1/\n' > $b/Dockerfile && docker build -q -t e2e-build2 $b`)
		if ok(out) {
			t.Errorf("a build step connected directly: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 sh -c 'echo \"np=$no_proxy\"'"); !regexp.MustCompile(`np=.*\bweb\b`).MatchString(out) || !regexp.MustCompile(`np=.*\bclient\b`).MatchString(out) {
			t.Errorf("no_proxy in containers should name the Compose services of the workspace: %s", out)
		}
		out = sh("cd ~/workspace && docker compose up -d web && docker compose run --rm client; rc=$?; docker compose down >/dev/null 2>&1; (exit $rc)")
		if !hasLine(out, "from-web") {
			t.Errorf("one Compose service should reach another by name: %s", out)
		}
		out = sh(`docker rm -f e2e-web >/dev/null 2>&1; docker run -d --name e2e-web -p 18080:80 busybox:1.36 sh -c 'echo hi > /i; httpd -f -h /' >/dev/null && sleep 3 && wget -T 5 -qO- http://127.0.0.1:18080/i && ss -ltnH | awk '$4 ~ /:18080$/ {print "LISTEN " $4}'; rc=$?; docker rm -f e2e-web >/dev/null 2>&1; (exit $rc)`)
		if !hasLine(out, "hi") || !hasLine(out, "LISTEN 127.0.0.1:18080") || strings.Count(out, "LISTEN ") != 1 {
			t.Errorf("a published port should answer in the VM and listen on loopback only: %s", out)
		}
		if out := sh("docker run --rm -u 1000 busybox:1.36 su root -c true"); ok(out) {
			t.Errorf("no-new-privileges should be the default: %s", out)
		}
	})

	t.Run("a container restarted with the VM gets nothing before the firewall", func(t *testing.T) {
		// Each second, two routes, one line each "<ts> <route> <ok|no>":
		// a direct connection, and the proxy to an allowed host.
		loop := `while :; do if wget -Y off -T 2 -qO- http://1.1.1.1/ >/dev/null 2>&1; then r=ok; else r=no; fi; echo "$(date +%s) direct $r" >> /w/boot-docker.log; if wget -T 3 -qO- http://example.com/ >/dev/null 2>&1; then r=ok; else r=no; fi; echo "$(date +%s) proxy $r" >> /w/boot-docker.log; sleep 1; done`
		if out := sh(`cd ~/workspace && : > boot-docker.log && docker run -d --name e2e-boot --restart always -v "$PWD:/w" busybox:1.36 sh -c ` + shq(loop)); !ok(out) {
			t.Fatalf("could not start the restart-always container: %s", out)
		}
		boot := sh("cat /proc/sys/kernel/random/boot_id")
		s.mustRun("down")
		s.mustRun("up", "--no-sync", "--no-install")
		if b := sh("cat /proc/sys/kernel/random/boot_id"); b == boot {
			t.Fatalf("the VM did not restart")
		}
		// Give the container time to come back and reach the proxy.
		var logOut string
		for i := 0; i < 30; i++ {
			logOut, _ = s.shell("cat ~/workspace/boot-docker.log; echo ---; cat /run/devkit/firewall-at 2>/dev/null; echo; date -u -d \"$(uptime -s)\" +%s")
			if regexp.MustCompile(`(?m)^\d+ proxy ok$`).MatchString(lastBoot(logOut)) {
				break
			}
			time.Sleep(3 * time.Second)
		}
		parts := strings.SplitN(logOut, "---", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected output: %s", logOut)
		}
		tail := strings.Fields(parts[1])
		if len(tail) < 2 {
			t.Fatalf("no firewall time or boot time: %q", parts[1])
		}
		fwAt, _ := strconv.ParseInt(tail[0], 10, 64)
		bootAt, _ := strconv.ParseInt(tail[len(tail)-1], 10, 64)
		line := regexp.MustCompile(`^(\d+) (direct|proxy) (ok|no)$`)
		var thisBoot, before, proxyOK int
		for _, l := range strings.Split(parts[0], "\n") {
			m := line.FindStringSubmatch(strings.TrimSpace(l))
			if m == nil {
				continue
			}
			ts, _ := strconv.ParseInt(m[1], 10, 64)
			if ts < bootAt {
				continue
			}
			thisBoot++
			pre := ts < fwAt
			if pre {
				before++
			}
			switch {
			case m[3] == "ok" && pre:
				t.Errorf("the container got out by %s before the firewall (at +%ds, firewall at +%ds)", m[2], ts-bootAt, fwAt-bootAt)
			case m[3] == "ok" && m[2] == "direct":
				t.Errorf("the container connected directly after the firewall (at +%ds)", ts-bootAt)
			case m[3] == "ok":
				proxyOK++
			}
		}
		t.Logf("%d attempts this boot, %d before the firewall, %d through the proxy after it", thisBoot, before, proxyOK)
		if proxyOK == 0 {
			t.Errorf("the container should have come back with the VM and reached an allowed host through the proxy:\n%s", logOut)
		}
		sh("docker rm -f e2e-boot; rm -f ~/workspace/boot-docker.log")
		usernsClosed(t)
		dockerWorks(t)
	})

	t.Run("turning containers off stops the daemon and closes namespaces outright", func(t *testing.T) {
		setYAML(t, cfg, "containers: docker", "containers: false")
		s.mustRun("up", "--no-sync", "--no-install")
		if out := sh("ps -o user:32=,comm= -C dockerd -C rootlesskit -C slirp4netns"); strings.Contains(out, "dockerd") || strings.Contains(out, "rootlesskit") {
			t.Errorf("the daemon should be gone: %s", out)
		}
		if out := sh("unshare -U true"); ok(out) {
			t.Errorf("with containers off the sandbox user should be refused a user namespace outright: %s", out)
		}
		if out := sh("timeout 30 rootlesskit unshare -n " + inner); hasLine(out, "NETADMIN-OK") {
			t.Errorf("rootlesskit got CAP_NET_ADMIN with containers off: %s", out)
		}
	})
}

// lastBoot returns the log lines of out (as read in TestDocker's restart
// check: log, "---", firewall time, boot time) stamped at or after the boot
// time, so a wait for the container's return does not match the last boot.
func lastBoot(out string) string {
	parts := strings.SplitN(out, "---", 2)
	if len(parts) != 2 {
		return ""
	}
	tail := strings.Fields(parts[1])
	if len(tail) == 0 {
		return ""
	}
	bootAt, _ := strconv.ParseInt(tail[len(tail)-1], 10, 64)
	var b strings.Builder
	for _, l := range strings.Split(parts[0], "\n") {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		if ts, err := strconv.ParseInt(f[0], 10, 64); err == nil && ts >= bootAt {
			b.WriteString(strings.TrimSpace(l) + "\n")
		}
	}
	return b.String()
}
