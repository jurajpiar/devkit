package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jurajpiar/devkit/internal/dockerfilter"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/runcguard"
)

const (
	filterWait          = "--init-groups curl -q -fsS -o /dev/null --unix-socket " + FilterSocket + " http://docker/info"
	filterSocketUnit    = "cat > /etc/systemd/system/" + FilterUnit + ".socket <<EOF\n"
	filterServiceUnit   = "cat > /etc/systemd/system/" + FilterUnit + ".service <<'EOF'\n"
	filterConfigOpen    = "cat > " + FilterConfig + " <<EOF\n"
	guardConfigOpen     = "cat > " + GuardConfig + " <<EOF\n"
	filterSocketRestart = "\nsystemctl restart " + FilterUnit + ".socket\n"
	installProxyOpen    = "cat > /usr/local/sbin/devkit-install-proxy <<'EOF'\n"
)

// dockerAndGvisorVariants is every Docker variant, with each runtime.
func dockerAndGvisorVariants(t *testing.T, check func(t *testing.T, p Params, s string)) {
	t.Run("runc", func(t *testing.T) { dockerVariants(t, check) })
	gvisorVariants(t, check)
}

// expandConfig fills in what root's shell would for a settings heredoc.
func expandConfig(body string) string {
	return strings.NewReplacer("$WS_REAL", "/home/alice/workspace", "$RUNC_REAL", "/usr/sbin/runc",
		"$DATA_ROOT", DockerHome+"/.local/share/docker", "$DOCKER_INIT", "/usr/bin/docker-init").Replace(body)
}

// The filter's and the guard's settings are JSON that the programs
// themselves accept, with the runtime the configuration allows.
func TestDockerFilterSettings(t *testing.T) {
	dockerAndGvisorVariants(t, func(t *testing.T, p Params, s string) {
		dir := t.TempDir()
		body, err := heredocBody(s, filterConfigOpen)
		if err != nil {
			t.Fatal(err)
		}
		fp := filepath.Join(dir, "filter.json")
		os.WriteFile(fp, []byte(expandConfig(body)), 0o644)
		fc, err := dockerfilter.LoadConfig(fp)
		if err != nil {
			t.Fatalf("filter.json does not load: %v\n%s", err, body)
		}
		want := []string{"devkit-runc"}
		if p.Config.Tools.ContainerRuntime.Gvisor() {
			want = []string{p.Config.Tools.ContainerRuntime.DockerName()}
		}
		// The runtime guard checks the mounts as made in front of runc and
		// of runsc alike.
		if !fc.RuntimeGuard {
			t.Errorf("filter.json runtime_guard is false under %s", p.Config.Tools.ContainerRuntime)
		}
		if fc.DaemonSocket != DockerSocket || fc.Workspace != "/home/alice/workspace" || !reflect.DeepEqual(fc.Runtimes, want) ||
			!reflect.DeepEqual(fc.Capabilities, []string{"IPC_LOCK", "NET_BIND_SERVICE"}) {
			t.Errorf("filter.json: %+v", fc)
		}
		body, err = heredocBody(s, guardConfigOpen)
		if err != nil {
			t.Fatal(err)
		}
		var gc runcguard.Config
		dec := json.NewDecoder(strings.NewReader(expandConfig(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&gc); err != nil {
			t.Fatalf("guard.json: %v\n%s", err, body)
		}
		wantGC := runcguard.Config{Runc: "/usr/sbin/runc", Workspace: "/home/alice/workspace", DataRoot: DockerHome + "/.local/share/docker", DockerInit: "/usr/bin/docker-init"}
		if p.Config.Tools.ContainerRuntime.Gvisor() {
			// The runsc guard's real runsc and, per runtime, exactly the
			// arguments daemon.json gives it.
			wantGC.Runsc = &runcguard.RunscConfig{Path: "/usr/local/bin/runsc", RuntimeArgs: map[string][]string{
				"runsc": {"--ignore-cgroups"}, "runsc-hostnet": {"--ignore-cgroups", "--network=host"}}}
		}
		if !reflect.DeepEqual(gc, wantGC) {
			t.Errorf("guard.json: %+v", gc)
		}
		// Every path written into them is checked first: a quote or a
		// control character would break the JSON.
		if !strings.Contains(s, `""|[!/]*|*[\"\\]*|*[[:cntrl:]]*) warn`) {
			t.Error("the paths in the settings must be checked before they are written")
		}
		for _, want := range []string{
			"chmod 644 " + FilterConfig + " " + GuardConfig,
			"ln -sfn " + EgressBinary + " " + FilterBinary,
			"ln -sfn " + EgressBinary + " " + GuardBinary,
			`WS_REAL="$(readlink -f "$DEVKIT_HOME")/workspace"`,
			`RUNC_REAL="$(awk '$1 == "profile" && $4 == "flags=(unconfined)" {print $3; exit}' /etc/apparmor.d/runc)"`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q", want)
			}
		}
		// The runsc guard's names are linked under gVisor only.
		runscLinks := `for l in /usr/local/bin/devkit-runsc-guard /usr/local/bin/devkit-runsc-hostnet-guard; do ln -sfn ` + EgressBinary + ` "$l"; done`
		if strings.Contains(s, runscLinks) != p.Config.Tools.ContainerRuntime.Gvisor() {
			t.Errorf("the runsc guard's links under %s: %v", p.Config.Tools.ContainerRuntime, !p.Config.Tools.ContainerRuntime.Gvisor())
		}
		// daemon.json: the guard is registered as the default with runc;
		// under gVisor runc's guard is not registered, and both gVisor
		// runtimes are the guard under its runsc names.
		d := daemonJSON(t, s)
		rts, _ := d["runtimes"].(map[string]any)
		_, guard := rts["devkit-runc"]
		if gv := p.Config.Tools.ContainerRuntime.Gvisor(); gv == guard || (!gv && d["default-runtime"] != "devkit-runc") {
			t.Errorf("daemon.json runtimes: %v", d)
		}
		for name, prog := range map[string]string{"runsc": "devkit-runsc-guard", "runsc-hostnet": "devkit-runsc-hostnet-guard"} {
			if r, ok := rts[name].(map[string]any); ok && r["path"] != "/usr/local/bin/"+prog {
				t.Errorf("daemon.json runtime %s: %v", name, r)
			}
		}
	})
}

// The units: a socket only root and the sandbox user's group reach, in a
// directory only root may change, and a service under the filter's own
// account with no privileges, no IP and no capabilities.
func TestDockerFilterUnits(t *testing.T) {
	dockerAndGvisorVariants(t, func(t *testing.T, p Params, s string) {
		sock, err := heredocBody(s, filterSocketUnit)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"ListenStream=" + FilterSocket, "SocketUser=root", "SocketGroup=$SANDBOX_GROUP", "SocketMode=0660", "DirectoryMode=0755", "WantedBy=sockets.target"} {
			if !strings.Contains(sock, want+"\n") {
				t.Errorf("the socket unit should have %q:\n%s", want, sock)
			}
		}
		svc, err := heredocBody(s, filterServiceUnit)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"ExecStart=" + FilterBinary + " -config " + FilterConfig,
			"User=" + FilterAccount, "Group=" + FilterAccount, "SupplementaryGroups=" + DockerAccount,
			"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes", "PrivateDevices=yes",
			"RestrictAddressFamilies=AF_UNIX", "CapabilityBoundingSet=", "MemoryDenyWriteExecute=yes", "LockPersonality=yes",
			"SystemCallFilter=@system-service", "IPAddressDeny=any",
		} {
			if !strings.Contains(svc, want+"\n") {
				t.Errorf("the service unit should have %q:\n%s", want, svc)
			}
		}
		if strings.Contains(svc, "[Install]") || strings.Contains(svc, "User=root") {
			t.Errorf("the service starts by its socket, never as root:\n%s", svc)
		}
		for _, want := range []string{
			`useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$FILTER_ACCOUNT"`,
			`usermod -a -G "$DOCKER_ACCOUNT" "$FILTER_ACCOUNT"`,
			`if grep -q "^user:$DEVKIT_USER:" <<< "$run_acl"; then setfacl -x "u:$DEVKIT_USER" "$DOCKER_HOME/run"; fi`,
			`if grep -q "^default:user:$DEVKIT_USER:" <<< "$run_acl"; then setfacl -x "d:u:$DEVKIT_USER" "$DOCKER_HOME/run"; fi`,
			"systemctl enable " + FilterUnit + ".socket >/dev/null 2>&1\n",
			"echo \"export DOCKER_HOST=unix://" + FilterSocket + "\" > /etc/profile.d/devkit-docker.sh",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q", want)
			}
		}
		if strings.Contains(s, "DOCKER_HOST=unix://"+DockerSocket) {
			t.Error("DOCKER_HOST must name the filter's socket, never the daemon's")
		}
		// In place before the firewall and the daemon; the filter is waited
		// for, as the sandbox user, once the daemon answers, and before the
		// module lock.
		cfg, unit, restart := index(t, s, filterConfigOpen), index(t, s, filterServiceUnit), index(t, s, filterSocketRestart)
		fw, start := index(t, s, "\n/usr/local/sbin/devkit-firewall\n"), index(t, s, dockerStart)
		wait, fwait := index(t, s, `timeout 10 docker --host "unix://`+DockerSocket+`" info`), index(t, s, filterWait)
		stamp := index(t, s, "> /etc/devkit/provision.id")
		if !(cfg < unit && unit < restart && restart < fw && fw < start && start < wait && wait < fwait && fwait < stamp) {
			t.Errorf("order: config=%d unit=%d restart=%d firewall=%d start=%d wait=%d filter=%d stamp=%d", cfg, unit, restart, fw, start, wait, fwait, stamp)
		}
		tail := s[wait:stamp]
		for _, want := range []string{
			`timeout 10 setpriv --reuid="$SANDBOX_UID" --regid="$SANDBOX_GID" ` + filterWait,
			`if [ "$(sha256sum ` + EgressBinary + ` 2>/dev/null | awk '{print $1}')" = "$(cat /etc/devkit/egress.sha256)" ]; then`,
			"if [ \"$filter_up\" != 1 ]; then\n    warn \"Docker's API filter did not answer",
		} {
			if !strings.Contains(tail, want) {
				t.Errorf("the filter wait should contain %q:\n%s", want, tail)
			}
		}
		// The binary's install restarts the filter; with no proxy in the
		// VM it does not start the proxy.
		inst, err := heredocBody(s, installProxyOpen)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(inst, "systemctl restart "+FilterUnit+".socket || true") {
			t.Errorf("the install should restart the filter:\n%s", inst)
		}
		if none := p.Config.Network.Mode == project.NetworkNone; none == strings.Contains(inst, "systemctl restart "+EgressService) {
			t.Errorf("mode %s: the proxy restart:\n%s", p.Config.Network.Mode, inst)
		}
	})
}

// Turning Docker off takes the filter out: its units, socket, links,
// settings and ACL; the accounts stay.
func TestDockerFilterOff(t *testing.T) {
	undo := []string{
		"systemctl stop " + FilterUnit + ".socket " + FilterUnit + ".service",
		"systemctl disable " + FilterUnit + ".socket >/dev/null 2>&1",
		"rm -f /etc/systemd/system/" + FilterUnit + ".socket /etc/systemd/system/" + FilterUnit + ".service",
		"rm -f " + FilterSocket + " " + FilterBinary + " " + GuardBinary + " " + FilterConfig + " " + GuardConfig,
		`setfacl -x "u:` + FilterAccount + `" "$DEVKIT_HOME"`,
	}
	for _, v := range []project.Containers{project.ContainersOff, project.ContainersContainerd} {
		s := mustSystem(t, params(func(c *project.Config) { c.Tools.Containers = v }))
		for _, u := range undo {
			if !strings.Contains(s, u) {
				t.Errorf("containers %q: missing %q", v, u)
			}
		}
		for _, st := range []string{filterSocketUnit, filterServiceUnit, filterConfigOpen, filterWait, "userdel"} {
			if strings.Contains(s, st) {
				t.Errorf("containers %q: %q belongs to docker mode", v, st)
			}
		}
		if inst, _ := heredocBody(s, installProxyOpen); strings.Contains(inst, FilterUnit) {
			t.Errorf("containers %q: the install must not touch the filter", v)
		}
	}
	s := mustSystem(t, dockerParams(nil))
	for _, u := range undo {
		if strings.Contains(s, u) {
			t.Errorf("docker mode must not undo itself: %q", u)
		}
	}
}
