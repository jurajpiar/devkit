// Package provision renders the scripts Lima runs inside the sandbox VM.
//
// The system script runs as root on every boot. It is the only place the
// network policy is applied, which is what makes the policy trustworthy: the
// sandbox user has no sudo, so code running in the VM cannot loosen it.
package provision

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/jurajpiar/devkit/internal/project"
)

// Params feeds the templates.
type Params struct {
	Config *project.Config
	// User is the Linux account Lima creates (same name as the macOS user).
	User string
	// EgressSHA256 is the hash of the devkit-egressproxy binary the host will
	// drop into the VM. Root only installs a binary with exactly this hash.
	EgressSHA256 string
	// MountPath is the guest path of the host directory for source: mount.
	MountPath string
}

// System renders the root provisioning script.
func System(p Params) (string, error) {
	return render(systemTmpl, p)
}

// User renders the per-user provisioning script.
func User(p Params) (string, error) {
	return render(userTmpl, p)
}

func render(src string, p Params) (string, error) {
	t, err := template.New("script").Funcs(template.FuncMap{
		"join": strings.Join,
		"bool": func(b bool) string {
			if b {
				return "1"
			}
			return "0"
		},
	}).Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse provisioning template: %w", err)
	}
	data := templateData{
		Params:        p,
		EgressBinary:  EgressBinary,
		EgressLog:     EgressLog,
		DropDir:       DropDir,
		ProxyListen:   ProxyListen,
		WorkspaceDir:  WorkspaceDir,
		EgressService: EgressService,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render provisioning script: %w", err)
	}
	return buf.String(), nil
}

// Guest paths shared with the CLI.
const (
	EgressBinary  = "/usr/local/bin/devkit-egressproxy"
	EgressLog     = "/var/log/devkit/egress.log"
	DropDir       = "/var/lib/devkit/drop"
	ProxyListen   = "127.0.0.1:3128"
	WorkspaceDir  = "workspace" // relative to the user's home
	EgressService = "devkit-egress"
)

const systemTmpl = `#!/bin/bash
# devkit system provisioning. Runs as root on every boot. Idempotent.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
DEVKIT_USER="{{.User}}"
MODE="{{.Config.Network.Mode}}"

mkdir -p /etc/devkit /var/log/devkit /var/lib/devkit {{.DropDir}}
chmod 755 /var/log/devkit

# ---- policy files, regenerated from devkit.yaml on every boot ----
cat > /etc/devkit/network.conf <<EOF
MODE=$MODE
ALLOW_HOST={{bool .Config.Network.AllowHost}}
EOF
cat > /etc/devkit/egress.conf <<EOF
EXTRA_ARGS=-allowed={{if eq .Config.Network.Mode "open"}}*{{else}}{{join .Config.Network.Allow ","}}{{end}}
EOF
echo "{{.EgressSHA256}}" > /etc/devkit/egress.sha256
chmod 644 /etc/devkit/*.conf /etc/devkit/egress.sha256
chown "$DEVKIT_USER" {{.DropDir}}
chmod 700 {{.DropDir}}

# ---- base packages (first boot) ----
if [ ! -f /var/lib/devkit/.base ]; then
  apt-get update
  apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential iptables openssh-client unzip rsync python3
{{- if .Config.Tools.Node}}
  curl -fsSL "https://deb.nodesource.com/setup_{{.Config.Tools.Node}}.x" | bash -
  apt-get install -y nodejs
  corepack enable || true
{{- end}}
  touch /var/lib/devkit/.base
fi

# ---- extra packages (re-run only when the list changes) ----
WANT_PKGS="{{join .Config.Tools.Packages " "}}"
if [ -n "$WANT_PKGS" ] && [ "$(cat /var/lib/devkit/.packages 2>/dev/null || true)" != "$WANT_PKGS" ]; then
  apt-get update
  apt-get install -y --no-install-recommends $WANT_PKGS
  echo "$WANT_PKGS" > /var/lib/devkit/.packages
fi

# ---- proxy account and proxy environment ----
id devkit-proxy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin devkit-proxy
PROXY_URL="http://{{.ProxyListen}}"
if [ "$MODE" != "none" ]; then
  cat > /etc/profile.d/devkit-proxy.sh <<EOF
export HTTP_PROXY=$PROXY_URL HTTPS_PROXY=$PROXY_URL http_proxy=$PROXY_URL https_proxy=$PROXY_URL
export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1
EOF
  sed -i '/^\(HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy\|NO_PROXY\|no_proxy\)=/d' /etc/environment
  cat >> /etc/environment <<EOF
HTTP_PROXY=$PROXY_URL
HTTPS_PROXY=$PROXY_URL
http_proxy=$PROXY_URL
https_proxy=$PROXY_URL
NO_PROXY=localhost,127.0.0.1
no_proxy=localhost,127.0.0.1
EOF
  cat > /etc/apt/apt.conf.d/99devkit-proxy <<EOF
Acquire::http::Proxy "$PROXY_URL";
Acquire::https::Proxy "$PROXY_URL";
EOF
else
  rm -f /etc/profile.d/devkit-proxy.sh /etc/apt/apt.conf.d/99devkit-proxy
  sed -i '/^\(HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy\|NO_PROXY\|no_proxy\)=/d' /etc/environment
fi

# ---- sudo ----
# Lima's host agent confirms boot by running two commands with sudo over SSH.
# Those two are always allowed. Anything else requires sudo: true in devkit.yaml.
rm -f /etc/sudoers.d/90-cloud-init-users
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  [ "$f" = /etc/sudoers.d/devkit ] && continue
  if grep -q "^$DEVKIT_USER " "$f" 2>/dev/null; then rm -f "$f"; fi
done
gpasswd -d "$DEVKIT_USER" sudo >/dev/null 2>&1 || true
{{- if .Config.Sudo}}
cat > /etc/sudoers.d/devkit <<EOF
# devkit.yaml has sudo: true. Root can disable the egress firewall.
$DEVKIT_USER ALL=(ALL) NOPASSWD:ALL
EOF
{{- else}}
cat > /etc/sudoers.d/devkit <<EOF
# Only what Lima's host agent needs to confirm the VM booted. Nothing else.
Cmnd_Alias DEVKIT_LIMA = /usr/bin/cat /mnt/lima-cidata/param.env, /usr/bin/diff -q /run/lima-ssh-ready /mnt/lima-cidata/meta-data, /usr/bin/diff -q /run/lima-boot-done /mnt/lima-cidata/meta-data
$DEVKIT_USER ALL=(root) NOPASSWD: DEVKIT_LIMA
EOF
{{- end}}
chmod 440 /etc/sudoers.d/devkit
visudo -cf /etc/sudoers.d/devkit >/dev/null

# ---- firewall ----
cat > /usr/local/sbin/devkit-firewall <<'EOF'
#!/bin/bash
# Applies /etc/devkit/network.conf to the OUTPUT chain. Runs as root.
set -u
. /etc/devkit/network.conf
HOST_IP="$(getent hosts host.lima.internal | awk '{print $1}' | head -n1)"
: "${HOST_IP:=192.168.5.2}"
modprobe nf_conntrack 2>/dev/null || true
for t in iptables ip6tables; do
  $t -P OUTPUT ACCEPT 2>/dev/null || true
  $t -F OUTPUT 2>/dev/null || true
done
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Replies from the guest's sshd to the host (Lima's control channel). Needed
# because connections opened before conntrack loaded are not yet tracked.
# Only root can bind port 22, so sandboxed code cannot use this rule.
iptables -A OUTPUT -d "$HOST_IP" -p tcp --sport 22 -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
# The host is also the gateway and the DNS resolver. Keep DNS to the host
# unless air-gapped; reject everything else aimed at the host.
if [ "${ALLOW_HOST:-0}" != "1" ]; then
  if [ "${MODE:-allowlist}" != "none" ]; then
    iptables -A OUTPUT -d "$HOST_IP" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$HOST_IP" -p tcp --dport 53 -j ACCEPT
  fi
  iptables -A OUTPUT -d "$HOST_IP" -j REJECT
fi
case "${MODE:-allowlist}" in
  open) ;;
  allowlist)
    iptables -A OUTPUT -m owner --uid-owner devkit-proxy -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -j REJECT
    ip6tables -A OUTPUT -j REJECT 2>/dev/null || true ;;
  none)
    iptables -A OUTPUT -j REJECT
    ip6tables -A OUTPUT -j REJECT 2>/dev/null || true ;;
esac
EOF
chmod 755 /usr/local/sbin/devkit-firewall

# ---- egress proxy service ----
cat > /etc/systemd/system/{{.EgressService}}.service <<EOF
[Unit]
Description=devkit egress proxy (domain allowlist + audit log)
After=network-online.target
ConditionPathExists={{.EgressBinary}}

[Service]
EnvironmentFile=/etc/devkit/egress.conf
ExecStart={{.EgressBinary}} -listen {{.ProxyListen}} -audit \$EXTRA_ARGS
User=devkit-proxy
Restart=always
RestartSec=1
StandardOutput=append:{{.EgressLog}}
StandardError=append:{{.EgressLog}}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# Root installs the proxy binary only if its hash matches devkit.yaml's build.
cat > /usr/local/sbin/devkit-install-proxy <<'EOF'
#!/bin/bash
set -u
f={{.DropDir}}/egressproxy
[ -f "$f" ] || exit 0
want="$(cat /etc/devkit/egress.sha256)"
got="$(sha256sum "$f" | awk '{print $1}')"
if [ -n "$want" ] && [ "$got" = "$want" ]; then
  install -m 755 -o root -g root "$f" {{.EgressBinary}}
  systemctl restart {{.EgressService}} || true
  echo "devkit: installed egress proxy $got"
else
  echo "devkit: refused egress proxy with hash $got (expected $want)" >&2
fi
rm -f "$f"
EOF
chmod 755 /usr/local/sbin/devkit-install-proxy

cat > /etc/systemd/system/devkit-proxy-install.path <<EOF
[Unit]
Description=Install devkit egress proxy when dropped by the host

[Path]
PathExists={{.DropDir}}/egressproxy

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/devkit-proxy-install.service <<EOF
[Unit]
Description=Verify and install devkit egress proxy

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/devkit-install-proxy
EOF

systemctl daemon-reload
systemctl enable --now devkit-proxy-install.path >/dev/null 2>&1 || true
touch {{.EgressLog}}
chmod 644 {{.EgressLog}}
if [ "$MODE" != "none" ]; then
  systemctl enable {{.EgressService}} >/dev/null 2>&1 || true
  systemctl restart {{.EgressService}} >/dev/null 2>&1 || true
else
  systemctl disable --now {{.EgressService}} >/dev/null 2>&1 || true
fi

/usr/local/sbin/devkit-firewall
echo "devkit: provisioning done (network=$MODE)"
`

const userTmpl = `#!/bin/bash
# devkit user provisioning. Runs as the sandbox user on every boot.
set -euo pipefail
{{- if eq .Config.Source "mount"}}
if [ ! -e "$HOME/{{.WorkspaceDir}}" ]; then
  ln -s "{{.MountPath}}" "$HOME/{{.WorkspaceDir}}"
fi
{{- else}}
mkdir -p "$HOME/{{.WorkspaceDir}}"
{{- end}}
`

// templateData wraps Params with the constants so templates can reference them.
type templateData struct {
	Params
	EgressBinary, EgressLog, DropDir, ProxyListen, WorkspaceDir, EgressService string
}
