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

// TestDockerFilter attacks the two controls that stand between the sandbox
// user and the Docker daemon: the API filter, which is the only socket the
// user can reach and refuses whatever it does not know to be harmless, and
// the runtime guard, which refuses a container whose mounts come from
// outside the workspace whatever the request said. Ordinary work has to
// keep working through both.
func TestDockerFilter(t *testing.T) {
	if os.Getenv("DEVKIT_E2E") == "" {
		t.Skip("set DEVKIT_E2E=1 to run (creates a real VM)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not installed")
	}
	devkit := buildDevkitBinary(t)
	dir := t.TempDir()
	name := fmt.Sprintf("e2efilter-%d", time.Now().Unix()%100000)
	s := &sandbox{t: t, devkit: devkit, dir: dir, name: name}
	writeFile(t, filepath.Join(dir, "README.md"), "docker filter e2e\n")
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM busybox:1.36\nCOPY README.md /readme\nRUN wget -T 10 -qO- http://example.com/ | grep -q 'Example Domain'\n")
	writeFile(t, filepath.Join(dir, "compose.yaml"), `services:
  web:
    build: .
    command: sh -c 'cp /readme /i; httpd -f -h /'
    volumes:
      - ./:/src
      - data:/data
    ports:
      - "18081:80"
    healthcheck:
      test: ["CMD", "wget", "-Y", "off", "-qO-", "http://127.0.0.1/i"]
      interval: 2s
      retries: 10
  client:
    image: busybox:1.36
    command: wget -Y off -T 8 -qO- http://web/i
    depends_on:
      web:
        condition: service_healthy
volumes:
  data:
`)
	s.mustRun("init", "--name", name, "--toolchain", "none")
	t.Cleanup(func() { _, _ = s.run("rm", "--force") })
	cfg := filepath.Join(dir, "devkit.yaml")
	// No sudo: this is the sandbox user as devkit ships it.
	setYAML(t, cfg, "containers: false", "containers: docker")
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
	// api sends one raw request to the socket the user's docker client
	// uses and prints the status code on its own line, then the body.
	api := func(method, path, body string) string {
		c := `S="${DOCKER_HOST#unix://}"; curl -s -m 30 --path-as-is --unix-socket "$S" -o /tmp/api.out -w 'status=%{http_code}\n' -X ` + method
		if body != "" {
			c += ` -H 'Content-Type: application/json' --data-binary ` + shq(body)
		}
		c += ` ` + shq("http://docker"+path) + `; cat /tmp/api.out; echo`
		out, _ := s.shell(c)
		return out
	}
	const daemonSock = "/var/lib/devkit-docker/run/docker.sock"

	if out := sh("docker pull -q busybox:1.36"); !ok(out) {
		t.Fatalf("pull through the filter and the proxy: %s", out)
	}

	t.Run("ordinary work goes through", func(t *testing.T) {
		for _, c := range []struct{ what, cmd, want string }{
			{"run", "docker run --rm busybox:1.36 echo ran-ok", "ran-ok"},
			{"stdin attach", "echo piped-ok | docker run --rm -i busybox:1.36 cat", "piped-ok"},
			{"workspace bind", `cd ~/workspace && docker run --rm -v "$PWD:/w" busybox:1.36 sh -c 'echo x > /w/f-file && cat /w/f-file' && rm f-file && echo bind-ok`, "bind-ok"},
			{"--mount bind of a subdirectory, read-only", `cd ~/workspace && mkdir -p sub && docker run --rm --mount type=bind,src="$PWD/sub",dst=/d,readonly busybox:1.36 ls /d && echo mount-ok`, "mount-ok"},
			{"named volume, tmpfs, init, read-only, user, env, workdir, limits", "docker run --rm -v f-vol:/v --tmpfs /t --init --read-only -u 1000:1000 -e A=b -w /tmp -m 128m --cpus 1 --pids-limit 100 busybox:1.36 echo opts-ok; docker volume rm f-vol >/dev/null", "opts-ok"},
			{"a harmless capability", "docker run --rm --cap-add IPC_LOCK --cap-drop ALL busybox:1.36 echo cap-ok", "cap-ok"},
			{"detached, logs, exec, cp both ways, inspect, stats, stop, rm", `cd ~/workspace && docker run -d --name f-run --restart on-failure -p 18080:80 busybox:1.36 sh -c 'echo hi > /i; echo started; httpd -f -h /' >/dev/null && sleep 3 && docker logs f-run && docker exec f-run cat /i && docker exec -u 1000 -e X=y -w /tmp f-run true && docker cp README.md f-run:/copied && docker cp f-run:/i ./from-container && cat from-container && rm from-container && docker inspect -f '{{.State.Running}}' f-run && docker stats --no-stream f-run >/dev/null && docker top f-run >/dev/null && wget -T 5 -qO- http://127.0.0.1:18080/i >/dev/null && docker stop -t 1 f-run >/dev/null && docker rm f-run >/dev/null && echo lifecycle-ok`, "lifecycle-ok"},
			{"network create, connect, rm", "docker network create f-net >/dev/null && docker run --rm --network f-net --network-alias a busybox:1.36 true && docker network rm f-net >/dev/null && echo net-ok", "net-ok"},
			{"build", "cd ~/workspace && docker build -q -t f-img . >/dev/null && docker run --rm f-img cat /readme && docker image inspect f-img >/dev/null && docker tag f-img f-img:two && docker rmi f-img:two >/dev/null && echo build-ok", "build-ok"},
			{"compose up with build, healthcheck, bind, volume, port; run; down", "cd ~/workspace && docker compose up -d --build web >/dev/null 2>&1 && docker compose run --rm client && docker compose ps >/dev/null && docker compose logs web >/dev/null && docker compose down -v >/dev/null 2>&1 && echo compose-ok", "compose-ok"},
			{"listing and housekeeping", "docker ps -a >/dev/null && docker images >/dev/null && docker volume ls >/dev/null && docker network ls >/dev/null && docker system df >/dev/null && docker version >/dev/null && docker info >/dev/null && docker container prune -f >/dev/null && docker image prune -f >/dev/null && echo list-ok", "list-ok"},
		} {
			if out := sh(c.cmd); !hasLine(out, c.want) {
				t.Errorf("%s should work through the filter: %s", c.what, out)
			}
		}
	})

	// Every attempt below must be refused, and none may leave a container
	// behind. "refused" means the command failed and the daemon never
	// answered for it: the message is devkit's.
	refused := func(t *testing.T, what, cmd string) {
		t.Helper()
		out := sh(cmd)
		if ok(out) {
			t.Errorf("%s was not refused: %s", what, out)
		} else if !strings.Contains(out, "devkit") {
			t.Errorf("%s failed, but not by devkit's refusal (it must not reach the daemon): %s", what, out)
		}
	}
	const run = "docker run --rm --name byp "
	const img = " busybox:1.36 true"

	t.Run("the daemon's own socket is out of reach", func(t *testing.T) {
		if out := sh("docker -H unix://" + daemonSock + " info"); ok(out) {
			t.Errorf("the sandbox user reached the daemon's socket directly: %s", out)
		}
		if out := sh(`echo "$DOCKER_HOST"`); strings.Contains(out, daemonSock) || !strings.Contains(out, "unix://") {
			t.Errorf("DOCKER_HOST should name the filter's socket, not the daemon's: %s", out)
		}
		if out := sh(`S="${DOCKER_HOST#unix://}"; test -w "$(dirname "$S")" || test -O "$S"`); ok(out) {
			t.Errorf("the sandbox user owns the filter's socket or can replace it: %s", out)
		}
		if out := sh("ls /etc/devkit/docker/ && test -w /etc/devkit/docker"); ok(out) {
			t.Errorf("the sandbox user can write the filter's or daemon's settings: %s", out)
		}
	})

	t.Run("container options that widen the kernel surface are refused", func(t *testing.T) {
		for what, flags := range map[string]string{
			"--privileged":                        "--privileged",
			"--cap-add NET_ADMIN":                 "--cap-add NET_ADMIN",
			"--cap-add SYS_ADMIN":                 "--cap-add SYS_ADMIN",
			"--cap-add ALL":                       "--cap-add ALL",
			"--cap-add NET_RAW":                   "--cap-add NET_RAW",
			"seccomp unconfined":                  "--security-opt seccomp=unconfined",
			"apparmor unconfined":                 "--security-opt apparmor=unconfined",
			"no-new-privileges off":               "--security-opt no-new-privileges=false",
			"systempaths unconfined":              "--security-opt systempaths=unconfined",
			"--pid host":                          "--pid host",
			"--ipc host":                          "--ipc host",
			"--network host":                      "--network host",
			"--userns host":                       "--userns host",
			"--uts host":                          "--uts host",
			"--cgroupns host":                     "--cgroupns host",
			"--device":                            "--device /dev/null:/dev/x",
			"--device-cgroup-rule":                "--device-cgroup-rule 'c 1:3 rwm'",
			"--sysctl":                            "--sysctl net.ipv4.ip_forward=1",
			"--runtime runc (unguarded)":          "--runtime runc",
			"--runtime io.containerd.runc.v2":     "--runtime io.containerd.runc.v2",
			"--cgroup-parent":                     "--cgroup-parent /x",
			"--oom-score-adj":                     "--oom-score-adj -500",
			"a port published on every interface": "-p 0.0.0.0:18090:80",
			"--volume-driver":                     "--volume-driver other -v x:/x",
			"a log driver that sends logs away":   "--log-driver syslog --log-opt syslog-address=udp://1.1.1.1:514",
		} {
			refused(t, what, run+flags+img)
		}
	})

	t.Run("mounts from outside the workspace are refused", func(t *testing.T) {
		for what, flags := range map[string]string{
			"/etc":                         "-v /etc:/e",
			"the VM's root":                "-v /:/host",
			"the user's home":              `-v "$HOME:/h"`,
			"~/.ssh":                       `-v "$HOME/.ssh:/s"`,
			"the daemon's socket":          "-v " + daemonSock + ":/var/run/docker.sock",
			"the daemon's directory":       "-v /var/lib/devkit-docker:/d",
			"the filter's own socket":      `-v "${DOCKER_HOST#unix://}:/var/run/docker.sock"`,
			"/proc":                        "-v /proc:/hp",
			"a path that climbs out":       `-v "$HOME/workspace/../.ssh:/s"`,
			"shared propagation":           `-v "$HOME/workspace:/w:rshared"`,
			"--mount with propagation":     `--mount type=bind,src="$HOME/workspace",dst=/w,bind-propagation=shared`,
			"--mount of /etc":              "--mount type=bind,src=/etc,dst=/e",
			"a volume with driver options": "--mount type=volume,dst=/v,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/etc",
		} {
			refused(t, what, run+flags+img)
		}
		refused(t, "a local volume that binds a path", "docker volume create --driver local --opt type=none --opt o=bind --opt device=/etc byp-vol")
		refused(t, "a volume from another driver", "docker volume create --driver other byp-vol")

		// A symlink in the workspace to the daemon's sockets: the path is
		// inside the workspace as asked, and outside it as mounted. The
		// container also mounts the workspace and tries to leave a file
		// there, so a process that ran at all is seen.
		for what, target := range map[string]string{
			"the daemon's socket directory":   "/var/lib/devkit-docker/run",
			"the account's runtime directory": "/run/user/$(id -u devkit-docker)",
			"/etc":                            "/etc",
		} {
			out := sh(`cd ~/workspace && rm -rf lnk ran && ln -s ` + target + ` lnk && docker run --rm --name byp -v "$PWD:/w" -v "$PWD/lnk:/s" busybox:1.36 sh -c 'touch /w/ran; ls /s'; rc=$?; ls ran 2>/dev/null && echo PROCESS-RAN; rm -rf lnk ran; (exit $rc)`)
			if ok(out) || strings.Contains(out, "PROCESS-RAN") {
				t.Errorf("a workspace symlink to %s was mounted, or the container's process ran: %s", what, out)
			}
		}
		// The same with the swap made between the request and the mount:
		// the container is created while the path is a real directory, and
		// started after it has become a symlink. Only a check of the mounts
		// as made can refuse this.
		out := sh(`cd ~/workspace && rm -rf swap ran && mkdir swap && docker create --name byp-swap -v "$PWD:/w" -v "$PWD/swap:/s" busybox:1.36 sh -c 'touch /w/ran; ls /s' >/dev/null && rmdir swap && ln -s /var/lib/devkit-docker/run swap && docker start -a byp-swap; rc=$?; ls ran 2>/dev/null && echo PROCESS-RAN; docker rm -f byp-swap >/dev/null 2>&1; rm -rf swap ran; (exit $rc)`)
		if ok(out) || strings.Contains(out, "PROCESS-RAN") {
			t.Errorf("a directory swapped for a symlink after the request was mounted, or the container's process ran: %s", out)
		}
		if !strings.Contains(out, "devkit") {
			t.Errorf("the swapped mount should be refused by devkit's runtime guard, by name: %s", out)
		}

		// The same swap aimed at Docker's stored settings for another
		// container. Docker does mount three files from a container's own
		// directory into it (hosts, hostname, resolv.conf); nothing else
		// there, and nothing of another container's, may be mounted:
		// hostconfig.json is what Docker reads a container's privileges
		// from when it restarts.
		const data = "/var/lib/devkit-docker/.local/share/docker"
		out = sh(`cd ~/workspace && rm -f swapf && docker rm -f byp-t byp-b >/dev/null 2>&1; T=$(docker create --name byp-t busybox:1.36 true) && : > swapf && docker create --name byp-b -v "$PWD/swapf:/h" busybox:1.36 cat /h >/dev/null && rm swapf && ln -s ` + data + `/containers/$T/hostconfig.json swapf && docker start -a byp-b; rc=$?; docker rm -f byp-t byp-b >/dev/null 2>&1; rm -f swapf; (exit $rc)`)
		if ok(out) || strings.Contains(out, "NetworkMode") {
			t.Errorf("a container mounted another container's hostconfig.json: %s", out)
		}
		if !strings.Contains(out, "devkit") {
			t.Errorf("mounting another container's settings should be refused by devkit's guard, by name: %s", out)
		}

		// docker cp has the daemon mount a container's binds itself,
		// without the runtime, so the guard never sees them: a bind source
		// swapped for a symlink would be followed. With a bind mount on the
		// container, copying in or out is refused, swapped or not.
		out = sh(`cd ~/workspace && rm -rf swap && docker rm -f byp-cp >/dev/null 2>&1; mkdir swap && docker create --name byp-cp -v "$PWD/swap:/s" busybox:1.36 true >/dev/null && rmdir swap && ln -s ` + data + `/containers swap && docker cp byp-cp:/s - | tar -t; rc=$?; rm -rf swap; (exit $rc)`)
		if strings.Contains(out, "hostconfig.json") || strings.Contains(out, "config.v2.json") {
			t.Errorf("docker cp read Docker's own files through a swapped bind: %s", out)
		}
		if !strings.Contains(out, "devkit") {
			t.Errorf("docker cp out of a container with a bind mount should be refused by devkit: %s", out)
		}
		out = sh(`cd ~/workspace && docker cp README.md byp-cp:/s/planted; rc=$?; docker rm -f byp-cp >/dev/null 2>&1; (exit $rc)`)
		if ok(out) || !strings.Contains(out, "devkit") {
			t.Errorf("docker cp into a container with a bind mount should be refused by devkit: %s", out)
		}
	})

	t.Run("other doors are refused", func(t *testing.T) {
		if out := sh("docker run -d --name byp-exec busybox:1.36 sleep 300"); !ok(out) {
			t.Fatalf("could not start a container to exec into: %s", out)
		}
		refused(t, "exec --privileged", "docker exec --privileged byp-exec true")
		refused(t, "container update", "docker update --memory 64m --memory-swap 64m byp-exec")
		sh("docker rm -f byp-exec")
		refused(t, "plugin list", "docker plugin ls")
		refused(t, "plugin install", "docker plugin install --grant-all-permissions vieux/sshfs")
		refused(t, "swarm init", "docker swarm init")
		refused(t, "service list", "docker service ls")
		refused(t, "secret list", "docker secret ls")
		refused(t, "config list", "docker config ls")
		refused(t, "node list", "docker node ls")
		refused(t, "a macvlan network", "docker network create -d macvlan byp-net")
		refused(t, "a host-driver network", "docker network create -d host byp-net")
		refused(t, "a bridge that publishes on every interface", "docker network create -o com.docker.network.bridge.host_binding_ipv4=0.0.0.0 byp-net")
		// BuildKit's own doors. A build step asking for the insecure
		// entitlement must not get it, and a build on the "host" network is
		// still behind the firewall.
		out := sh(`b=$(mktemp -d) && printf '# syntax=docker/dockerfile:1-labs\nFROM busybox:1.36\nRUN --security=insecure true\n' > $b/Dockerfile && docker buildx build --allow security.insecure -q $b`)
		if ok(out) {
			t.Errorf("a build got the security.insecure entitlement: %s", out)
		}
		out = sh(`b=$(mktemp -d) && printf 'FROM busybox:1.36\nRUN wget -Y off -T 6 -qO- http://1.1.1.1/\n' > $b/Dockerfile && docker build --network host -q $b`)
		if ok(out) {
			t.Errorf("a build step on the host network connected directly: %s", out)
		}
	})

	t.Run("the raw API: paths, versions and parser tricks", func(t *testing.T) {
		status := func(out string) string {
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), "status=") {
					return strings.TrimPrefix(strings.TrimSpace(l), "status=")
				}
			}
			return ""
		}
		// Controls: the helper reaches the filter, and a plain create works.
		if out := api("GET", "/_ping", ""); status(out) != "200" {
			t.Fatalf("the raw API helper does not reach the filter: %s", out)
		}
		if out := api("POST", "/v1.44/containers/create?name=byp-plain", `{"Image":"busybox:1.36","Cmd":["true"]}`); status(out) != "201" {
			t.Fatalf("a plain create through the raw API should work, or every refusal below is vacuous: %s", out)
		}
		sh("docker rm -f byp-plain")

		const priv = `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Privileged":true}}`
		for _, path := range []string{
			"/containers/create?name=byp-raw",
			"/v1.44/containers/create?name=byp-raw",
			"/v1.52/containers/create?name=byp-raw",
			"/v9.99/containers/create?name=byp-raw",
			"//containers/create?name=byp-raw",
			"/containers/create/?name=byp-raw",
			"/v1.44//containers/create?name=byp-raw",
			"/v1.44/containers/../containers/create?name=byp-raw",
			"/v1.44/images/../containers/create?name=byp-raw",
			"/_ping/../containers/create?name=byp-raw",
			"/%63ontainers/create?name=byp-raw",
			"/containers%2Fcreate?name=byp-raw",
			"/v1.44/containers/%2e%2e/containers/create?name=byp-raw",
			"/CONTAINERS/create?name=byp-raw",
		} {
			out := api("POST", path, priv)
			if st := status(out); strings.HasPrefix(st, "2") || st == "" {
				t.Errorf("POST %s with Privileged was answered %q: %s", path, st, out)
			}
		}
		// Bodies the filter and the daemon could read differently. Each is
		// either refused, or creates a container that is not privileged.
		for what, body := range map[string]string{
			"duplicate key, true last":  `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Privileged":false,"Privileged":true}}`,
			"duplicate key, true first": `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Privileged":true,"Privileged":false}}`,
			"lower-case key":            `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"privileged":true}}`,
			"upper-case key":            `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"PRIVILEGED":true}}`,
			"duplicate HostConfig":      `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{},"HostConfig":{"Privileged":true}}`,
			"lower-case hostconfig":     `{"Image":"busybox:1.36","Cmd":["true"],"hostconfig":{"Privileged":true}}`,
			"escaped key":               `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Privile\u0067ed":true}}`,
			"capabilities, lower-case":  `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"capadd":["SYS_ADMIN"]}}`,
			"binds, lower-case":         `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"binds":["/etc:/e"]}}`,
			"trailing second document":  `{"Image":"busybox:1.36","Cmd":["true"]}{"HostConfig":{"Privileged":true}}`,
		} {
			sh("docker rm -f byp-raw")
			out := api("POST", "/v1.44/containers/create?name=byp-raw", body)
			if strings.HasPrefix(status(out), "2") {
				insp := sh(`docker inspect -f 'priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} binds={{.HostConfig.Binds}}' byp-raw`)
				if !strings.Contains(insp, "priv=false") || strings.Contains(insp, "SYS_ADMIN") || strings.Contains(insp, "/etc") {
					t.Errorf("%s: the daemon read what the filter did not: %s", what, insp)
				}
			}
		}
		sh("docker rm -f byp-raw")
		for what, body := range map[string]string{
			"a field the filter does not know":         `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Frobnicate":true}}`,
			"a top-level field it does not know":       `{"Image":"busybox:1.36","Cmd":["true"],"Frobnicate":true}`,
			"masked paths emptied":                     `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"MaskedPaths":[],"ReadonlyPaths":[]}}`,
			"devices":                                  `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/x","CgroupPermissions":"rwm"}]}}`,
			"device requests":                          `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"DeviceRequests":[{"Count":-1,"Capabilities":[["gpu"]]}]}}`,
			"a bind mount with create and propagation": `{"Image":"busybox:1.36","Cmd":["true"],"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/e"}]}}`,
			"not JSON":                                 `{"Image":`,
		} {
			out := api("POST", "/v1.44/containers/create?name=byp-raw", body)
			if st := status(out); strings.HasPrefix(st, "2") || st == "" {
				t.Errorf("%s was answered %q: %s", what, st, out)
			}
		}
		for _, c := range []struct{ method, path, body string }{
			{"GET", "/plugins", ""},
			{"GET", "/v1.44/plugins", ""},
			{"POST", "/swarm/init", `{}`},
			{"GET", "/secrets", ""},
			{"POST", "/v1.44/containers/byp-raw/update", `{"Memory":1}`},
			{"GET", "/no/such/endpoint", ""},
			{"POST", "/v1.44/exec/abc/start", `{"Privileged":true}`},
			{"PATCH", "/v1.44/containers/json", ""},
			{"CONNECT", "/", ""},
		} {
			out := api(c.method, c.path, c.body)
			if st := status(out); strings.HasPrefix(st, "2") || st == "" {
				t.Errorf("%s %s was answered %q: %s", c.method, c.path, st, out)
			}
		}
	})

	t.Run("enforced defaults", func(t *testing.T) {
		out := sh(`docker run -d --name byp-def -p 18082:80 busybox:1.36 sleep 60 >/dev/null && docker inspect -f 'nnp={{.HostConfig.SecurityOpt}} drop={{.HostConfig.CapDrop}} rt={{.HostConfig.Runtime}}' byp-def && ss -ltnH | awk '$4 ~ /:18082$/ {print "LISTEN " $4}'; docker exec byp-def sh -c 'grep CapEff /proc/self/status'; docker rm -f byp-def >/dev/null`)
		if !strings.Contains(out, "NET_RAW") {
			t.Errorf("NET_RAW should be dropped from every container: %s", out)
		}
		if !hasLine(out, "LISTEN 127.0.0.1:18082") || strings.Count(out, "LISTEN ") != 1 {
			t.Errorf("a published port should listen on loopback only: %s", out)
		}
		if out := sh("docker run --rm -u 1000 busybox:1.36 su root -c true"); ok(out) {
			t.Errorf("no-new-privileges should hold for every container: %s", out)
		}
		// The daemon's own default covers its default bridge only. A
		// network the user makes, which is every Compose project's, has its
		// own default, and that is every interface unless the filter sets
		// it. Published with no address, with -P, and through Compose.
		listeners := func(port string) string {
			return sh(`ss -ltnH | awk '$4 ~ /:` + port + `$/ {print "LISTEN " $4}'`)
		}
		loopbackOnly := func(t *testing.T, what, out, port string) {
			t.Helper()
			if !hasLine(out, "LISTEN 127.0.0.1:"+port) || strings.Count(out, "LISTEN ") != 1 {
				t.Errorf("%s: the published port should listen on 127.0.0.1 only: %s", what, out)
			}
		}
		if out := sh(`docker network create byp-pub >/dev/null && docker run -d --name byp-pub1 --network byp-pub -p 18083:80 busybox:1.36 sleep 60 >/dev/null && sleep 2`); !ok(out) {
			t.Fatalf("could not start a container on a user-defined network: %s", out)
		}
		loopbackOnly(t, "a user-defined network", listeners("18083"), "18083")
		out = sh(`docker run -d --name byp-pub2 --network byp-pub --expose 80 -P busybox:1.36 sleep 60 >/dev/null && sleep 2 && docker port byp-pub2 80; docker rm -f byp-pub1 byp-pub2 >/dev/null; docker network rm byp-pub >/dev/null`)
		for _, l := range strings.Split(out, "\n") {
			l = strings.TrimSpace(l)
			if strings.Contains(l, ":") && !strings.HasPrefix(l, "exit=") && !strings.HasPrefix(l, "127.0.0.1:") && !strings.HasPrefix(l, "[::1]:") {
				t.Errorf("-P on a user-defined network published beyond loopback: %s", out)
			}
		}
		if !strings.Contains(out, "127.0.0.1:") {
			t.Errorf("-P should have published on loopback: %s", out)
		}
		if out := sh("cd ~/workspace && docker compose up -d web >/dev/null 2>&1 && sleep 2"); !ok(out) {
			t.Fatalf("compose up: %s", out)
		}
		loopbackOnly(t, "a Compose project's network", listeners("18081"), "18081")
		sh("cd ~/workspace && docker compose down -v")
	})

	t.Run("nothing is left behind and the VM is as it was", func(t *testing.T) {
		if out := sh(`docker ps -aq --filter name=byp | wc -l`); !hasLine(out, "0") {
			t.Errorf("a refused attempt left a container: %s", sh("docker ps -a --filter name=byp"))
		}
		if out := sh("docker volume ls -q | grep -c byp; docker network ls -q --filter name=byp | wc -l"); !hasLine(out, "0") {
			t.Errorf("a refused attempt left a volume or network: %s", out)
		}
		if out := sh("docker run --rm busybox:1.36 echo still-ok"); !hasLine(out, "still-ok") {
			t.Errorf("Docker should still work after the attempts: %s", out)
		}
	})
}
