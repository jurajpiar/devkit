package provision

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/jurajpiar/devkit/internal/dockerfilter"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/runcguard"
)

// tools.containers: docker. The daemon runs under an account of its own,
// with its socket in that account's home, which only the API filter's
// account may reach. The sandbox user reaches the filter's socket.
const (
	DockerAccount = "devkit-docker"
	DockerHome    = "/var/lib/" + DockerAccount
	DockerSocket  = DockerHome + "/run/docker.sock"
	// DockerConfigHelper writes the sandbox user's ~/.docker/config.json
	// proxy settings. Root installs it; the sandbox user runs it.
	DockerConfigHelper = "/usr/local/bin/devkit-docker-config"

	// FilterAccount runs the API filter: not root, so that a bug in its
	// parsing is not root's.
	FilterAccount = "devkit-dockerfilter"
	// FilterSocket is the filter's socket, the sandbox user's DOCKER_HOST.
	FilterSocket = "/run/devkit/docker.sock"
	FilterUnit   = "devkit-dockerfilter"
	// The filter and the runtime guard are the guest binary, run under
	// these names.
	FilterBinary = "/usr/local/bin/" + dockerfilter.ProgramName
	GuardBinary  = "/usr/local/bin/" + runcguard.ProgramName
	FilterConfig = dockerfilter.DefaultConfigPath
	GuardConfig  = runcguard.DefaultConfigPath
)

// filterRuntimes is the runtime a container may name, as JSON: the
// configured default only. runc by name is never one.
func filterRuntimes(c *project.Config) string {
	name := runcguard.RuntimeName
	if c != nil && c.Tools.ContainerRuntime.Gvisor() {
		name = c.Tools.ContainerRuntime.DockerName()
	}
	b, _ := json.Marshal([]string{name})
	return string(b)
}

// dockerProxy is the in-guest egress proxy as containers reach it: rootless
// Docker's slirp4netns maps the VM's loopback to 10.0.2.2.
func dockerProxy() string {
	_, port, _ := net.SplitHostPort(ProxyListen)
	return "http://10.0.2.2:" + port
}

// dockerConfigScript is the helper with this configuration's proxy filled
// in: none when the VM has no proxy (network.mode: none).
func dockerConfigScript(c *project.Config) string {
	proxy := dockerProxy()
	if c != nil && c.Network.Mode == project.NetworkNone {
		proxy = ""
	}
	return strings.NewReplacer(
		"@PROXY@", proxy,
		"@DEVKIT_PROXY@", dockerProxy(),
		"@WORKSPACE@", WorkspaceDir,
	).Replace(dockerConfigPy)
}

// dockerConfigPy sets proxies.default in ~/.docker/config.json and keeps
// every other setting. It reads the workspace's Compose files without a
// YAML library, which the image may not have, by a line scan of the
// top-level services: block.
const dockerConfigPy = `#!/usr/bin/env python3
# Written by devkit's provisioning. Sets the proxy that Docker's client hands
# to containers and builds, in ~/.docker/config.json, keeping every other
# setting. The workspace's Compose service names and container names are
# exempt from the proxy, so that one service reaches another by name. Those
# names come from the repository, which is untrusted: only plain names are
# used, and anything else is dropped.
import json, os, re, sys, tempfile

PROXY = "@PROXY@"
DEVKIT_PROXY = "@DEVKIT_PROXY@"
WORKSPACE = os.path.join(os.path.expanduser("~"), "@WORKSPACE@")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")
FILES = [b + e for b in ("compose", "docker-compose", "compose.override", "docker-compose.override") for e in (".yaml", ".yml")]
LIMIT = 1 << 20


def compose_files(root):
    dirs = [root]
    try:
        with os.scandir(root) as it:
            for e in sorted(it, key=lambda e: e.name):
                if e.name != ".git" and e.is_dir(follow_symlinks=False):
                    dirs.append(e.path)
    except OSError:
        pass
    for d in dirs:
        for f in FILES:
            p = os.path.join(d, f)
            if os.path.isfile(p):
                yield p


def names(text):
    """Service keys of the top-level services: block, and container_name values."""
    out, inside, indent = [], False, None
    for line in text.splitlines():
        body = line.strip()
        if not body or body.startswith("#"):
            continue
        if not line[0].isspace():
            inside = re.match(r"services\s*:\s*(#.*)?$", line) is not None
            indent = None
            continue
        if not inside:
            continue
        width = len(line) - len(line.lstrip())
        if indent is None:
            indent = width
        if width == indent:
            m = re.match(r"\s*(['\"]?)([^'\":#\s]+)\1\s*:(\s|$)", line)
        else:
            m = re.match(r"\s*container_name\s*:\s*(['\"]?)([^'\"#\s]+)\1\s*(#.*)?$", line)
        if m:
            out.append(m.group(2))
    return out


def service_names(root):
    found = set()
    for p in compose_files(root):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read(LIMIT)
        except OSError:
            continue
        found.update(n for n in names(text) if len(n) <= 253 and NAME.match(n))
    return sorted(found)


def main():
    path = os.path.join(os.path.expanduser("~"), ".docker", "config.json")
    cfg = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError) as e:
            print("devkit: not changing %s, which is not valid JSON: %s" % (path, e), file=sys.stderr)
            return 0
        if not isinstance(cfg, dict):
            print("devkit: not changing %s, which is not a JSON object" % path, file=sys.stderr)
            return 0
    proxies = cfg.get("proxies") if isinstance(cfg.get("proxies"), dict) else {}
    default = proxies.get("default") if isinstance(proxies.get("default"), dict) else {}
    if PROXY:
        no_proxy = ["localhost", "127.0.0.1", "::1"] + service_names(WORKSPACE)
        default.update(httpProxy=PROXY, httpsProxy=PROXY, noProxy=",".join(no_proxy))
        proxies["default"] = default
        cfg["proxies"] = proxies
    elif default.get("httpProxy") == DEVKIT_PROXY:
        # No proxy in this VM: take out the settings devkit wrote earlier.
        for k in ("httpProxy", "httpsProxy", "noProxy"):
            default.pop(k, None)
        if default:
            proxies["default"] = default
        else:
            proxies.pop("default", None)
        if proxies:
            cfg["proxies"] = proxies
        else:
            cfg.pop("proxies", None)
    else:
        return 0
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.json.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())`

// dockerDaemonJSON is the daemon's root-owned configuration. Published ports
// bind to the VM's loopback and no container process gains privileges
// through setuid programs. With runc, the runtime guard is registered and is
// the default; the API filter refuses any other runtime by name. With a
// gVisor runtime both gVisor runtimes are registered and the configured one
// is the default; the filter allows that one only. --ignore-cgroups is how
// runsc was proven under the rootless daemon; it also means memory and CPU
// limits set on a container are not enforced under gVisor.
func dockerDaemonJSON(c *project.Config) string {
	type runtime struct {
		Path        string   `json:"path"`
		RuntimeArgs []string `json:"runtimeArgs,omitempty"`
	}
	d := struct {
		NoNewPrivileges bool               `json:"no-new-privileges"`
		IP              string             `json:"ip"`
		Runtimes        map[string]runtime `json:"runtimes"`
		DefaultRuntime  string             `json:"default-runtime"`
	}{
		NoNewPrivileges: true,
		IP:              "127.0.0.1",
		Runtimes:        map[string]runtime{runcguard.RuntimeName: {Path: GuardBinary}},
		DefaultRuntime:  runcguard.RuntimeName,
	}
	if c != nil && c.Tools.ContainerRuntime.Gvisor() {
		d.Runtimes = map[string]runtime{
			"runsc":         {GvisorRunsc, []string{"--ignore-cgroups"}},
			"runsc-hostnet": {GvisorRunsc, []string{"--ignore-cgroups", "--network=host"}},
		}
		d.DefaultRuntime = c.Tools.ContainerRuntime.DockerName()
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		panic(err) // fixed types: cannot fail
	}
	return string(b)
}
