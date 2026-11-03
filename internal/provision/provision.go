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
		MiseVersion:   MiseVersion,
		MiseArm64SHA:  MiseArm64SHA,
		MiseAmd64SHA:  MiseAmd64SHA,
		NixVersion:    NixVersion,
		NixArm64SHA:   NixArm64SHA,
		NixAmd64SHA:   NixAmd64SHA,
		AuditScript:   AuditScript,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render provisioning script: %w", err)
	}
	return buf.String(), nil
}

// Toolchain managers are installed by root from release archives pinned by
// SHA-256. Bump deliberately and re-verify the upstream signature.
const (
	// mise: hashes are from the release's SHASUMS256.txt, whose GPG
	// signature by "mise releases <release@mise.jdx.dev>" (fingerprint
	// 2485 3EC9 F655 CE80 B48E 6C3A 8B81 C9D1 7413 A06D) was verified when
	// this pin was made. The release was at least two weeks old at the time.
	MiseVersion  = "v2026.10.15"
	MiseArm64SHA = "d14b44dffea91562ff0611e4ae33472088224da5778a4d071d60e87d463942ff"
	MiseAmd64SHA = "4cf6fcd45b730e0c48c59b9a056ed6701be14abf44f999d69aa70afd1004fc32"
	// Nix: hashes are the ones embedded in the official installer at
	// https://nixos.org/nix/install for this version, cross-checked against
	// a download of the aarch64 archive.
	NixVersion  = "2.35.4"
	NixArm64SHA = "14a940a2d0ae5b2c623dc2ca168311c9367fd4bc416f6ded0c1087089d6de934"
	NixAmd64SHA = "ff66236d2f7e2a21f3350e73668e021ac6a8881ef277a38e16e952bfb22718c3"
)

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

# No background apt. The cloud image runs unattended-upgrades and the
# apt-daily timers at boot; they hold the dpkg lock for as long as their
# download takes, which blocks this script until Lima's boot timeout. Nothing
# they fetch could pass the allowlist afterwards anyway.
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service >/dev/null 2>&1 || true
systemctl stop apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true
systemctl mask apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true
# Provisioning runs before the firewall is applied for this boot and before
# the egress proxy is up, so apt talks to the mirrors directly here. Package
# signatures are still verified by apt. The lock timeout bounds the wait if
# something still holds the lock, instead of hanging the boot.
APT="apt-get -o Acquire::http::Proxy=false -o Acquire::https::Proxy=false -o DPkg::Lock::Timeout=300"
# Same for the toolchain manager archives. A stalled download must fail the
# boot, not hang it.
CURL=(curl -fsSL --noproxy '*' --retry 3 --retry-all-errors --connect-timeout 30 --max-time 900)

# ---- base packages (first boot) ----
if [ ! -f /var/lib/devkit/.base ]; then
  $APT update
  $APT install -y --no-install-recommends \
    git curl ca-certificates build-essential iptables openssh-client unzip xz-utils rsync python3
  touch /var/lib/devkit/.base
fi
DEVKIT_HOME="$(getent passwd "$DEVKIT_USER" | cut -d: -f6)"
{{- if eq .Config.Tools.Manager "mise"}}

# ---- mise, the toolchain manager: pinned release, verified by SHA-256 ----
# The hashes are from the release's signed SHASUMS256.txt (see provision.go).
# Toolchains themselves are installed later by the sandbox user through the
# audited proxy; mise verifies each against upstream checksums or signatures.
MISE_VERSION="{{.MiseVersion}}"
if [ "$(cat /var/lib/devkit/.mise 2>/dev/null || true)" != "$MISE_VERSION" ]; then
  case "$(uname -m)" in
    aarch64) arch=arm64; want="{{.MiseArm64SHA}}" ;;
    x86_64)  arch=x64;   want="{{.MiseAmd64SHA}}" ;;
    *) echo "devkit: unsupported architecture $(uname -m)" >&2; exit 1 ;;
  esac
  tmp="$(mktemp -d /var/lib/devkit/mise.XXXXXX)"
  "${CURL[@]}" -o "$tmp/mise.tar.xz" \
    "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${arch}.tar.xz"
  got="$(sha256sum "$tmp/mise.tar.xz" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    echo "devkit: refused mise ${MISE_VERSION} with hash $got (expected $want)" >&2
    rm -rf "$tmp"; exit 1
  fi
  tar -xJf "$tmp/mise.tar.xz" -C "$tmp"
  install -m 755 -o root -g root "$tmp/mise/bin/mise" /usr/local/bin/mise
  rm -rf "$tmp"
  echo "$MISE_VERSION" > /var/lib/devkit/.mise
fi
# System settings the sandbox user cannot loosen: no plugin backends (they
# are unreviewed shell scripts), provenance checked on every install, and
# repository config files trusted only under the workspace.
install -d -m 755 /etc/mise
cat > /etc/mise/config.toml <<EOF
# Written by devkit on every boot.
[settings]
disable_backends = ["asdf", "vfox"]
paranoid = true
trusted_config_paths = ["$DEVKIT_HOME/{{.WorkspaceDir}}"]
minimum_release_age = "72h"
# The VM is glibc Linux; locking other platforms would fetch checksums from
# hosts outside the allowlist for nothing.
lockfile_platforms = ["linux-arm64", "linux-x64"]
idiomatic_version_file_enable_tools = ["node", "go", "python", "ruby", "java", "rust"]
EOF
chmod 644 /etc/mise/config.toml
cat > /etc/profile.d/devkit-mise.sh <<'EOF'
export PATH="$HOME/.local/share/mise/shims:$PATH"
EOF
{{- else}}
rm -f /etc/profile.d/devkit-mise.sh
{{- end}}
{{- if eq .Config.Tools.Manager "nix"}}

# ---- Nix (multi-user): pinned release, verified by SHA-256 ----
# Installed once. The daemon fetches through the audited proxy; substitutes
# from cache.nixos.org are checked against the cache's signing key by Nix.
NIX_VERSION="{{.NixVersion}}"
if [ ! -f /var/lib/devkit/.nix ]; then
  case "$(uname -m)" in
    aarch64) sys=aarch64-linux; want="{{.NixArm64SHA}}" ;;
    x86_64)  sys=x86_64-linux;  want="{{.NixAmd64SHA}}" ;;
    *) echo "devkit: unsupported architecture $(uname -m)" >&2; exit 1 ;;
  esac
  tmp="$(mktemp -d /var/lib/devkit/nix.XXXXXX)"
  "${CURL[@]}" -o "$tmp/nix.tar.xz" \
    "https://releases.nixos.org/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-${sys}.tar.xz"
  got="$(sha256sum "$tmp/nix.tar.xz" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    echo "devkit: refused Nix ${NIX_VERSION} with hash $got (expected $want)" >&2
    rm -rf "$tmp"; exit 1
  fi
  tar -xJf "$tmp/nix.tar.xz" -C "$tmp"
  cat > "$tmp/extra.conf" <<'EOF'
experimental-features = nix-command flakes
sandbox = true
EOF
  HOME=/root USER=root "$tmp/nix-${NIX_VERSION}-${sys}/install" --daemon --yes --no-channel-add --no-modify-profile \
    --nix-extra-conf-file "$tmp/extra.conf"
  rm -rf "$tmp"
  echo "$NIX_VERSION" > /var/lib/devkit/.nix
elif [ "$(cat /var/lib/devkit/.nix)" != "$NIX_VERSION" ]; then
  echo "devkit: Nix $(cat /var/lib/devkit/.nix) is installed; devkit now pins ${NIX_VERSION}. Recreate the VM (devkit rm) to upgrade." >&2
fi
cat > /etc/profile.d/devkit-nix.sh <<'EOF'
if [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi
EOF
{{- else}}
rm -f /etc/profile.d/devkit-nix.sh
{{- end}}

# ---- extra packages (re-run only when the list changes) ----
WANT_PKGS="{{join .Config.Tools.Packages " "}}"
if [ -n "$WANT_PKGS" ] && [ "$(cat /var/lib/devkit/.packages 2>/dev/null || true)" != "$WANT_PKGS" ]; then
  $APT update
  $APT install -y --no-install-recommends $WANT_PKGS
  echo "$WANT_PKGS" > /var/lib/devkit/.packages
fi

# ---- trust store: the distro's current bundle, minus network.distrust ----
# ca-certificates is the source of truth and is refreshed on every boot, so a
# VM created before a CA was removed upstream catches up on its next start.
# Runs before the firewall, like apt's other work here; apt verifies it.
if [ "$MODE" != "none" ]; then
  ($APT update -q && $APT install -y -q --only-upgrade ca-certificates) >/dev/null 2>&1 \
    || echo "devkit: could not refresh ca-certificates; keeping the installed bundle" >&2
fi
CACONF=/etc/ca-certificates.conf
# Undo the names applied on the previous boot, then apply this boot's. The
# names come from devkit.yaml, validated to letters, digits, space . _ ( ) -.
if [ -f /var/lib/devkit/.distrust ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && sed -i "s|^!mozilla/$f\.crt\$|mozilla/$f.crt|" "$CACONF"
  done < /var/lib/devkit/.distrust
fi
: > /var/lib/devkit/.distrust
{{- range .Config.Network.Distrust}}
n="{{.}}"; f="${n// /_}"; f="${f//./\\.}"
if grep -q "^!\?mozilla/$f\.crt\$" "$CACONF"; then
  sed -i "s|^mozilla/$f\.crt\$|!mozilla/$f.crt|" "$CACONF"
  echo "${n// /_}" >> /var/lib/devkit/.distrust
else
  echo "devkit: network.distrust: no root named '$n' in the system bundle" >&2
fi
{{- end}}
update-ca-certificates --fresh >/dev/null 2>&1 || true
# Runtimes that carry their own root list use the system bundle instead, so
# the distro's updates and network.distrust apply to them too.
cat > /etc/profile.d/devkit-trust.sh <<'EOF'
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/etc/ssl/certs
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt PIP_CERT=/etc/ssl/certs/ca-certificates.crt
export NODE_OPTIONS="--use-openssl-ca${NODE_OPTIONS:+ $NODE_OPTIONS}"
EOF
cat > /usr/local/bin/devkit-audit <<'PYEOF'
{{.AuditScript}}
PYEOF
chmod 755 /usr/local/bin/devkit-audit

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
{{- if eq .Config.Tools.Manager "nix"}}
# The Nix daemon does the downloading, so it needs the proxy too. Nix passes
# the proxy variables into fixed-output builds, which is where flake inputs
# and source tarballs are fetched.
install -d -m 755 /etc/systemd/system/nix-daemon.service.d
if [ "$MODE" != "none" ]; then
  cat > /etc/systemd/system/nix-daemon.service.d/devkit-proxy.conf <<EOF
[Service]
Environment=HTTP_PROXY=$PROXY_URL HTTPS_PROXY=$PROXY_URL http_proxy=$PROXY_URL https_proxy=$PROXY_URL
Environment=NO_PROXY=$NO_PROXY_HOSTS no_proxy=$NO_PROXY_HOSTS
EOF
else
  rm -f /etc/systemd/system/nix-daemon.service.d/devkit-proxy.conf
fi
systemctl daemon-reload
systemctl try-restart nix-daemon.service 2>/dev/null || true
{{- end}}

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
{{- if eq .Config.Tools.Manager "mise"}}
# Toolchain versions from devkit.yaml. The lockfile beside this file pins
# what they resolved to on the first install; it lives with the VM.
install -d -m 700 "$HOME/.config/mise"
cat > "$HOME/.config/mise/config.toml" <<'EOF'
# Written by devkit from devkit.yaml on every boot. Edit devkit.yaml instead.
[settings]
lockfile = true

[tools]
{{- range $tool, $version := .Config.Tools.Versions}}
{{$tool}} = "{{$version}}"
{{- end}}
EOF
{{- end}}
`

// templateData wraps Params with the constants so templates can reference them.
type templateData struct {
	Params
	EgressBinary, EgressLog, DropDir, ProxyListen, WorkspaceDir, EgressService string
	MiseVersion, MiseArm64SHA, MiseAmd64SHA                                    string
	NixVersion, NixArm64SHA, NixAmd64SHA                                       string
	AuditScript                                                                string
}
