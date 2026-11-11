package provision

import (
	"net"
	"strings"

	"github.com/jurajpiar/devkit/internal/project"
)

// tools.containers: docker. The daemon runs under an account of its own, and
// the sandbox user reaches it through a socket in that account's home.
const (
	DockerAccount = "devkit-docker"
	DockerHome    = "/var/lib/" + DockerAccount
	DockerSocket  = DockerHome + "/run/docker.sock"
	// DockerConfigHelper writes the sandbox user's ~/.docker/config.json
	// proxy settings. Root installs it; the sandbox user runs it.
	DockerConfigHelper = "/usr/local/bin/devkit-docker-config"
)

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
