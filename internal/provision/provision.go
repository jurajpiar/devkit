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
		NodeSourceKey: nodeSourceKey,
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
# Quoted heredocs: values come from the template, never from shell expansion.
cat > /etc/devkit/network.conf <<'EOF'
MODE={{.Config.Network.Mode}}
ALLOW_HOST={{bool .Config.Network.AllowHost}}
EOF
cat > /etc/devkit/egress.conf <<'EOF'
EXTRA_ARGS=-allowed={{if eq .Config.Network.Mode "open"}}*{{else}}{{join .Config.Network.Allow ","}}{{end}}
EOF
echo "{{.EgressSHA256}}" > /etc/devkit/egress.sha256
chmod 644 /etc/devkit/*.conf /etc/devkit/egress.sha256
chown "$DEVKIT_USER" {{.DropDir}}
chmod 700 {{.DropDir}}

# Provisioning runs before the firewall is applied for this boot and before
# the egress proxy is up, so apt talks to the mirrors directly here. Package
# signatures are still verified by apt.
APT="apt-get -o Acquire::http::Proxy=false -o Acquire::https::Proxy=false"

# ---- base packages (first boot) ----
if [ ! -f /var/lib/devkit/.base ]; then
  $APT update
  $APT install -y --no-install-recommends \
    git curl ca-certificates build-essential iptables openssh-client unzip rsync python3
  touch /var/lib/devkit/.base
fi
{{- if .Config.Tools.Node}}

# ---- Node.js from NodeSource's apt repository (re-run when the major changes) ----
# The repository signing key is embedded, not downloaded, so no remote script
# is ever executed. Key: NodeSource, fingerprint
# 6F71 F525 2828 41EE DAF8 51B4 2F59 B5F9 9B1B E0B4. apt verifies every package.
NODE_MAJOR="{{.Config.Tools.Node}}"
if [ "$(cat /var/lib/devkit/.node 2>/dev/null || true)" != "$NODE_MAJOR" ]; then
  install -d -m 755 /etc/apt/keyrings
  cat > /etc/apt/keyrings/nodesource.asc <<'EOF'
{{.NodeSourceKey}}
EOF
  chmod 644 /etc/apt/keyrings/nodesource.asc
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  $APT update
  $APT install -y --allow-downgrades nodejs
  corepack enable || true
  echo "$NODE_MAJOR" > /var/lib/devkit/.node
fi
{{- end}}

# ---- extra packages (re-run only when the list changes) ----
WANT_PKGS="{{join .Config.Tools.Packages " "}}"
if [ -n "$WANT_PKGS" ] && [ "$(cat /var/lib/devkit/.packages 2>/dev/null || true)" != "$WANT_PKGS" ]; then
  $APT update
  $APT install -y --no-install-recommends $WANT_PKGS
  echo "$WANT_PKGS" > /var/lib/devkit/.packages
fi

# ---- proxy account and proxy environment ----
id devkit-proxy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin devkit-proxy
PROXY_URL="http://{{.ProxyListen}}"
# With allow_host the host is reached directly (the firewall permits it), so
# it must bypass the proxy, whose allowlist would otherwise block it.
NO_PROXY_HOSTS="localhost,127.0.0.1{{if .Config.Network.AllowHost}},host.lima.internal{{end}}"
if [ "$MODE" != "none" ]; then
  cat > /etc/profile.d/devkit-proxy.sh <<EOF
export HTTP_PROXY=$PROXY_URL HTTPS_PROXY=$PROXY_URL http_proxy=$PROXY_URL https_proxy=$PROXY_URL
export NO_PROXY=$NO_PROXY_HOSTS no_proxy=$NO_PROXY_HOSTS
EOF
  sed -i '/^\(HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy\|NO_PROXY\|no_proxy\)=/d' /etc/environment
  cat >> /etc/environment <<EOF
HTTP_PROXY=$PROXY_URL
HTTPS_PROXY=$PROXY_URL
http_proxy=$PROXY_URL
https_proxy=$PROXY_URL
NO_PROXY=$NO_PROXY_HOSTS
no_proxy=$NO_PROXY_HOSTS
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
# Lima's host agent confirms boot by running three read-only commands with
# sudo over SSH. Those are always allowed. Anything else requires sudo: true.
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
# The resolvers systemd-resolved forwards to. The file is root-owned, so the
# sandbox cannot add an address of its own to this list.
DNS_IPS="$HOST_IP $(awk '/^nameserver/{print $2}' /run/systemd/resolve/resolv.conf 2>/dev/null | grep -v '^127\.' || true)"
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
# DNS only to the configured resolvers, never to arbitrary port-53 endpoints,
# and not at all when air-gapped.
if [ "${MODE:-allowlist}" != "none" ]; then
  for ip in $DNS_IPS; do
    iptables -A OUTPUT -d "$ip" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$ip" -p tcp --dport 53 -j ACCEPT
  done
fi
# The host is also the gateway. Decide about it before any other rule so
# nothing later (including the proxy) can reach it unless allow_host is set.
if [ "${ALLOW_HOST:-0}" = "1" ]; then
  iptables -A OUTPUT -d "$HOST_IP" -j ACCEPT
else
  iptables -A OUTPUT -d "$HOST_IP" -j REJECT
fi
# allowlist and open: only the proxy's account may open outbound connections,
# so every request is audited. The two modes differ only in the proxy's
# allowlist. none: nothing leaves.
case "${MODE:-allowlist}" in
  allowlist|open)
    iptables -A OUTPUT -m owner --uid-owner devkit-proxy -j ACCEPT ;;
esac
iptables -A OUTPUT -j REJECT
ip6tables -A OUTPUT -j REJECT 2>/dev/null || true
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
# The drop directory belongs to the sandbox user, who could swap the file
# between the hash check and the install. Take a private root-only copy
# first and never look at the staged file again.
tmp="$(mktemp /var/lib/devkit/egressproxy.XXXXXX)"
cp "$f" "$tmp"
rm -f "$f"
want="$(cat /etc/devkit/egress.sha256)"
got="$(sha256sum "$tmp" | awk '{print $1}')"
if [ -n "$want" ] && [ "$got" = "$want" ]; then
  install -m 755 -o root -g root "$tmp" {{.EgressBinary}}
  systemctl restart {{.EgressService}} || true
  echo "devkit: installed egress proxy $got"
else
  echo "devkit: refused egress proxy with hash $got (expected $want)" >&2
fi
rm -f "$tmp"
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
	NodeSourceKey                                                              string
	EgressBinary, EgressLog, DropDir, ProxyListen, WorkspaceDir, EgressService string
}

// nodeSourceKey is NodeSource's apt repository signing key, embedded so the
// guest never fetches or runs anything unsigned to install Node.js.
//
// Fetched from https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key;
// fingerprint 6F71 F525 2828 41EE DAF8 51B4 2F59 B5F9 9B1B E0B4 (key ID
// 2F59B5F99B1BE0B4). Verify with: gpg --show-keys --with-fingerprint <file>
const nodeSourceKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFdDN1ABCADaNd/I3j3tn40deQNgz7hB2NvT+syXe6k4ZmdiEcOfBvFrkS8B
hNS67t93etHsxEy7E0qwsZH32bKazMqe9zDwoa3aVImryjh6SHC9lMtW27JPHFeM
Srkt9YmH1WMwWcRO6eSY9B3PpazquhnvbammLuUojXRIxkDroy6Fw4UKmUNSRr32
9Ej87jRoR1B2/57Kfp2Y4+vFGGzSvh3AFQpBHq51qsNHALU6+8PjLfIt+5TPvaWR
TB+kAZnQZkaIQM2nr1n3oj6ak2RATY/+kjLizgFWzgEfbCrbsyq68UoY5FPBnu4Z
E3iDZpaIqwKr0seUC7iA1xM5eHi5kty1oB7HABEBAAG0Ik5Tb2xpZCA8bnNvbGlk
LWdwZ0Bub2Rlc291cmNlLmNvbT6JAU4EEwEKADgCGwMCHgECF4AWIQRvcfUlKChB
7tr4UbQvWbX5mxvgtAUCaWfGnwULCQgHAgYVCgkICwIEFgIDAQAKCRAvWbX5mxvg
tL0CB/0TTur63uXTPbq+JBQET6jnEVaDrNmpHI/z2RMuj163gmy9CtCwG060c+TI
qzmzlPacbTkGc5C50teX2mhs+5JIthfhMibR6Dgy0zeSVuvt9WJ3TNWBpoW5Ezka
17SA3Xv9UEJS2eyRd7ALf7TGGAj8DG+xRABXl6bJIXh1s7Hki7kwgVrpNxm/EqyX
OrzExm0g2UjgdkbnZrnTyZMB6X8f8fZPo0QcByPvLee2DtkKeE+SZlFXyvnCzcw0
94K45vlWkEdRzmiiWAG7guzZyZYGcCO5EoJ3LUP90qhrmQUfsbtczeoEW17EW1jM
RohLo8BqVyYc1CAFlULIDNeS3aipuQENBFdDN1ABCACq02gutmss6jiD2u50vdAR
x3JOGd92trWRf7qH9/MTToslhoU/LiXhaE0x5+UkKuRbcruCtytn226brvwD0BdO
QGpY81ZAxjTFuKUpIDmrHcrI/N9XLrLKx19kWEttsIPNJOgvx8JoeReOX2hLjcbF
fmz8e6D1K7eZ+hjMfOLxD94tfhQwYtKbfwf0JwxQV5ItQRryd+X+TcA3nyvFWiJ8
Vz92Tf1iG7Z+XasaaZFf2JDuxoiZaSZY7va395ClCEMykFsRbGwgDyB6Fr+6x/UU
sYA4rYV7RumIOUdWngWyWjzVy/cKSWASW4jI5ABWs+AfeRTqmZt6+6B7oIghrB19
ABEBAAGJAR8EGAECAAkFAldDN1ACGwwACgkQL1m1+Zsb4LRPzgf9FTfPA0d2N37q
su5av3bYZJ+w6pvWF3aK2Zdy9ednhCBfPNmhvBRN6mXWixo0DuKEoQMjVpkX0hrq
B9FxEVwCPZ9K/JuJgzMROq7T+7R3rcv+TPMdwk8rjIMeRiw2hFLwbrJ0w/v7/3wT
MESv3GfXbuT0huEedK7bLfqGMgtmqMeCNkoI7Rf3GO2xArGQ6Zc2rTd4L9+D5HHS
IPEixwFZS+Debc7pg3os0bKXEsqMtitvocClOAuPnXpCy04PK450UTr6ZVdirWhJ
Oq8SrSERQwqEJ4PMHybiDKwzSr6mcBURre3G71uTAp7h/DISLTpfVMadcB6eoLWr
/4fBqejAWg==
=wh5k
-----END PGP PUBLIC KEY BLOCK-----`
