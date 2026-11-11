// Package provision renders the scripts Lima runs inside the sandbox VM.
//
// The system script runs as root on every boot. It is the only place the
// network policy is applied, which is what makes the policy trustworthy: the
// sandbox user has no sudo, so code running in the VM cannot loosen it.
package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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
	// ProvisionID fingerprints the policy this script applies. The VM records
	// it so commands can tell when a VM is running provisioning older than the
	// devkit binary. Set by Fingerprint; leave empty when computing it.
	ProvisionID string
	// HostProxy is devkit's proxy on the Mac as the guest reaches it,
	// "192.168.5.2:<port>", under network.enforce: host; empty otherwise.
	// Root's downloads and the in-guest proxy go through it, and the
	// firewall lets the proxy's account reach it and nothing else.
	HostProxy string
}

// System renders the root provisioning script.
func System(p Params) (string, error) {
	return render(systemTmpl, p)
}

// Fingerprint is a short, stable hash of the policy a given Params produces:
// the system script with its own ID blanked, so it captures the firewall,
// DNS, trust, kernel and proxy-hash choices but not the fingerprint itself.
// Identical inputs give the same value; any policy change gives a new one.
func Fingerprint(p Params) (string, error) {
	p.ProvisionID = ""
	p.MountPath = "" // a host path, not policy: the fingerprint must not vary with it
	s, err := System(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12], nil
}

// User renders the per-user provisioning script.
func User(p Params) (string, error) {
	return render(userTmpl, p)
}

func render(src string, p Params) (string, error) {
	// MountPath is the host's working directory, chosen by whoever named it.
	// It lands in a root-run quoted heredoc, where only a line break could
	// end the document early, and in the user script through shq. The script
	// travels inside Lima's YAML, whose parser also treats NEL, U+2028 and
	// U+2029 as line breaks and normalises them to newlines, so those count.
	if strings.ContainsAny(p.MountPath, "\n\r\u0085\u2028\u2029") {
		return "", fmt.Errorf("project path contains a line break, which cannot be provisioned safely: %q", p.MountPath)
	}
	hostIP, hostPort, err := splitHostProxy(p)
	if err != nil {
		return "", err
	}
	t, err := template.New("script").Funcs(template.FuncMap{
		"join": strings.Join,
		"shq":  shellQuote,
		"joinInts": func(xs []int, sep string) string {
			parts := make([]string, len(xs))
			for i, x := range xs {
				parts[i] = strconv.Itoa(x)
			}
			return strings.Join(parts, sep)
		},
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
		HostProxyIP:   hostIP,
		HostProxyPort: hostPort,

		DockerAccount:      DockerAccount,
		DockerHome:         DockerHome,
		DockerSocket:       DockerSocket,
		DockerConfigHelper: DockerConfigHelper,
		DockerProxy:        dockerProxy(),
		DockerConfigScript: dockerConfigScript(p.Config),
		ContainerPreload:   containerPreload,
		DockerDaemonJSON:   dockerDaemonJSON(p.Config),
		FilterAccount:      FilterAccount,
		FilterSocket:       FilterSocket,
		FilterUnit:         FilterUnit,
		FilterBinary:       FilterBinary,
		GuardBinary:        GuardBinary,
		FilterConfig:       FilterConfig,
		GuardConfig:        GuardConfig,
		FilterRuntimes:     filterRuntimes(p.Config),
		GuardRunscBinaries: guardRunscBinaries(),
		GuardRunscJSON:     guardRunscJSON(p.Config),

		GvisorRelease:     GvisorRelease,
		GvisorArm64SHA512: GvisorArm64SHA512,
		GvisorAmd64SHA512: GvisorAmd64SHA512,
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

// gVisor, for tools.container_runtime: gvisor and gvisor-hostnet, is
// installed by root from one release archive per architecture in Google's
// release bucket. The checksums were taken from the .sha512 file published
// beside each archive, at the same origin, so they pin the bytes devkit was
// tested with, not who published them. Bump the release and both together.
const (
	GvisorRelease     = "20261102.0"
	GvisorArm64SHA512 = "e829ca32eef36f4e960460a6dcb094d7945ab507e9bfe0275f09467ab9bfeb846528fddfd42349ad64bb4f5b02148e1065c06e573feb8f6a8b3f47efa30a7d2e"
	GvisorAmd64SHA512 = "3c400f72be459b57b99b1c4f69be96bcd67eef3caf2078e595fc98e688b6b9a3af7802646b3dde7da8a9aba96d34f86be303e0430c7868ab2d13becdd403c0c1"
	// GvisorRunsc is where root installs runsc; gvisor-bin/ sits beside it.
	GvisorRunsc = "/usr/local/bin/runsc"
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
DNS="{{if .Config.Network.DNS}}{{.Config.Network.DNS}}{{else}}proxy{{end}}"

# The stamp says provisioning finished. It goes first, before anything that
# can fail, and is written back only when every step below has succeeded
# (the script runs with set -e), so an aborted provisioning, on a first boot
# or a later one, leaves a VM without one, which devkit up stops and devkit
# shell and sync refuse.
rm -f /etc/devkit/provision.id

mkdir -p /etc/devkit /var/log/devkit /var/lib/devkit {{.DropDir}}
chmod 755 /var/log/devkit

# ---- progress, for devkit up to show while Lima waits on these scripts ----
# Written to the serial console, which Lima records on the host in
# serialv.log, so devkit up can follow it without running anything in the
# guest (an SSH session as the sandbox user would execute files it can
# write). Step names only, nothing secret.
mkdir -p /run/devkit && chmod 755 /run/devkit
step() { printf 'devkit-progress: %s\n' "$*" > /dev/hvc0 2>/dev/null || true; }
# Warnings and notes reach devkit up the same way; stderr alone ends in the
# guest's cloud-init log, where nobody sees it.
warn() { printf 'devkit: %s\n' "$*" >&2; step "warning: $*"; }
note() { printf 'devkit: %s\n' "$*" >&2; step "note: $*"; }
# set -e aborts at the first failing command; this names it on the console
# first, so devkit up can say what failed after it has stopped the VM. The
# command is the script's own text, not its expanded values.
on_error() {
  local cmd="${3//[[:cntrl:]]/ }"
  step "failed: ${cmd:0:200} (line $2, exit $1)"
}
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
step "provisioning started"

# ---- sudo ----
# Lima's host agent confirms boot by running three read-only commands with
# sudo over SSH. Those are always allowed. Anything else requires sudo: true.
# Applied first, before the hold and before any step that can fail for
# reasons outside the VM: the image gives the user passwordless sudo, which
# could lift the hold on a VM whose first provisioning failed and that was
# then started by hand. Lima's checks need nothing more: on every boot after
# the first this policy is already in place when they run.
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

# ---- provisioning hold: no network for the sandbox user until the firewall ----
# The firewall is applied at the end of this script. Until then, and until
# the VM shuts down if any step fails (no stamp is written, and devkit up
# stops the VM), the
# sandbox user's slice and systemd-resolved, which could relay lookups for
# it, have no IP traffic at all: not to the internet, the Mac, Lima's DNS or
# loopback, whatever interface a socket binds to. systemd enforces it per
# cgroup, which the user cannot leave, and it needs no packages, so it holds
# on a first boot whose package installation fails. Root runs this script in
# a system unit and keeps its network; it resolves upstream directly, not
# through resolved. Set at runtime, never as a drop-in file: on systemd 255 a
# drop-in hold cannot be lifted cleanly. Lifted after the firewall, below.
SANDBOX_UID="$(id -u "$DEVKIT_USER")"
HOLD_SLICE="user-$SANDBOX_UID.slice"
step "holding the sandbox user off the network until the firewall is applied"
systemctl set-property --runtime "$HOLD_SLICE" IPAddressDeny=any
systemctl set-property --runtime systemd-resolved.service IPAddressDeny=any
{{- if .Config.Tools.Containers.Docker}}
# tools.containers: docker runs the daemon under an account of its own. That
# account's user manager starts at boot (linger), and its containers' traffic
# leaves through processes it owns, so it is held like the sandbox user. The
# account is made here, before anything can start under it; this needs no
# package and no network.
DOCKER_ACCOUNT={{.DockerAccount}}
DOCKER_HOME={{.DockerHome}}
id "$DOCKER_ACCOUNT" >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir "$DOCKER_HOME" --shell /usr/sbin/nologin "$DOCKER_ACCOUNT"
grep -q "^$DOCKER_ACCOUNT:" /etc/subuid || usermod --add-subuids 2000000000-2000065535 "$DOCKER_ACCOUNT"
grep -q "^$DOCKER_ACCOUNT:" /etc/subgid || usermod --add-subgids 2000000000-2000065535 "$DOCKER_ACCOUNT"
DOCKER_UID="$(id -u "$DOCKER_ACCOUNT")"
DOCKER_SLICE="user-$DOCKER_UID.slice"
systemctl set-property --runtime "$DOCKER_SLICE" IPAddressDeny=any
{{- end}}

# ---- logind stall guard ----
# Lima's boot script terminates the user's sessions to apply /etc/environment
# while its host agent is opening the first SSH session. On some boots that
# race leaves systemd-logind spinning at 100% CPU with its D-Bus dead, so every
# SSH login then waits out pam_systemd's timeout and the boot overruns Lima's
# deadline. A spinning logind never handles SIGTERM, so a plain restart would
# first wait out the 90 s stop timeout: kill it outright and start it again.
# Sessions survive a logind restart.
if ! timeout 5 loginctl list-sessions >/dev/null 2>&1; then
  warn "systemd-logind is unresponsive; killing and restarting it"
  systemctl kill --signal=SIGKILL systemd-logind.service || true
  systemctl start systemd-logind.service || true
  for _ in $(seq 1 20); do
    timeout 2 loginctl list-sessions >/dev/null 2>&1 && break
    sleep 0.5
  done
fi
# Lima enables linger for the user in its own boot scripts, but that call
# fails silently while logind is spinning, and Lima's boot.sh then waits
# forever for the user manager before the user provisioning. Enable it again
# now that logind answers; it is idempotent and starts the user manager.
loginctl enable-linger "$DEVKIT_USER" || true

# ---- name resolution for this boot's downloads ----
# Root resolves upstream directly while it provisions, whatever the mode, so
# its downloads never depend on systemd-resolved, which the boot hold keeps
# off the network until the firewall is up. The boot's own resolver setup is
# applied at the end (see "name resolution: who may ask").
ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf

# ---- policy files, regenerated from devkit.yaml on every boot ----
step "writing the sandbox policy"
# Quoted heredocs: values come from the template, never from shell expansion.
cat > /etc/devkit/network.conf <<'EOF'
MODE={{.Config.Network.Mode}}
ALLOW_HOST={{bool .Config.Network.AllowHost}}
DNS={{if .Config.Network.DNS}}{{.Config.Network.DNS}}{{else}}proxy{{end}}
FORWARD={{joinInts .Config.Network.Forward ","}}
{{- if .HostProxy}}
HOST_PROXY_IP={{.HostProxyIP}}
HOST_PROXY_PORT={{.HostProxyPort}}
{{- end}}
EOF
# What the sandbox may see of the host: nothing, or one mount at one path.
cat > /etc/devkit/source.conf <<'EOF'
SOURCE={{.Config.Source}}
MOUNT_POINT={{if eq .Config.Source "mount"}}{{.MountPath}}{{end}}
MOUNT_WRITABLE={{bool .Config.MountWritable}}
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
{{- if .HostProxy}}
# network.enforce: host. The Mac lets the VM reach devkit's proxy there and
# nothing else, and the guest has no DNS, so root's downloads go through
# that proxy too. It resolves the names and allows exactly the project's
# hosts plus the ones provisioning needs.
HOST_PROXY_URL="http://{{.HostProxy}}"
APT="apt-get -o Acquire::http::Proxy=$HOST_PROXY_URL -o Acquire::https::Proxy=$HOST_PROXY_URL -o DPkg::Lock::Timeout=300"
CURL=(curl -fsSL --proxy "$HOST_PROXY_URL" --retry 3 --retry-all-errors --connect-timeout 30 --max-time 900)
{{- end}}

# ---- kernel console on hvc0: crash reports reach the Mac ----
# The kernel's console is ttyAMA0, which this hypervisor does not provide,
# so nothing the kernel prints reaches the Mac. hvc0 is the console Lima
# records in serialv.log, where devkit on the Mac looks for kernel crash
# reports. Only root can write to it. The drop-in takes effect from the next
# boot; update-grub runs only when it changes. This is detection, not
# enforcement: a failure here warns and provisioning goes on.
step "connecting the kernel console to the Mac"
CONSOLE_DROPIN=/etc/default/grub.d/99-devkit-console.cfg
CONSOLE_WANT='GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT console=hvc0"'
if [ "$(cat "$CONSOLE_DROPIN" 2>/dev/null || true)" != "$CONSOLE_WANT" ]; then
  if ! command -v update-grub >/dev/null 2>&1; then
    warn "update-grub is missing: kernel crash reports will not reach the Mac"
  elif ! { mkdir -p /etc/default/grub.d && printf '%s\n' "$CONSOLE_WANT" > "$CONSOLE_DROPIN"; } 2>/dev/null; then
    warn "could not write $CONSOLE_DROPIN: kernel crash reports will not reach the Mac"
  elif ! grub_out="$(update-grub 2>&1)"; then
    # Removed, so that the next boot tries again.
    rm -f "$CONSOLE_DROPIN"
    warn "update-grub failed, so kernel crash reports will not reach the Mac: $(printf '%s\n' "$grub_out" | tail -n 1)"
  fi
fi
if ! grep -qw 'console=hvc0' /proc/cmdline 2>/dev/null; then
  note "kernel crash reporting to the Mac starts after the VM's next restart (devkit down, then devkit up)"
fi

# ---- base packages (first boot) ----
step "checking base packages (installed on first boot)"
if [ ! -f /var/lib/devkit/.base ]; then
  $APT update
  $APT install -y --no-install-recommends \
    git curl ca-certificates build-essential iptables openssh-client unzip xz-utils rsync python3
  touch /var/lib/devkit/.base
fi
DEVKIT_HOME="$(getent passwd "$DEVKIT_USER" | cut -d: -f6)"
{{- if eq .Config.Tools.Manager "mise"}}

# ---- mise, the toolchain manager: pinned release, verified by SHA-256 ----
step "checking mise (installed on first boot)"
# The hashes are from the release's signed SHASUMS256.txt (see provision.go).
# Toolchains themselves are installed later by the sandbox user through the
# audited proxy; mise verifies each against upstream checksums or signatures.
MISE_VERSION="{{.MiseVersion}}"
if [ "$(cat /var/lib/devkit/.mise 2>/dev/null || true)" != "$MISE_VERSION" ]; then
  case "$(uname -m)" in
    aarch64) arch=arm64; want="{{.MiseArm64SHA}}" ;;
    x86_64)  arch=x64;   want="{{.MiseAmd64SHA}}" ;;
    *) warn "unsupported architecture $(uname -m)"; exit 1 ;;
  esac
  tmp="$(mktemp -d /var/lib/devkit/mise.XXXXXX)"
  "${CURL[@]}" -o "$tmp/mise.tar.xz" \
    "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${arch}.tar.xz"
  got="$(sha256sum "$tmp/mise.tar.xz" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    warn "refused mise ${MISE_VERSION} with hash $got (expected $want)"
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
step "checking Nix (installed on first boot)"
# Installed once. The daemon fetches through the audited proxy; substitutes
# from cache.nixos.org are checked against the cache's signing key by Nix.
NIX_VERSION="{{.NixVersion}}"
if [ ! -f /var/lib/devkit/.nix ]; then
  case "$(uname -m)" in
    aarch64) sys=aarch64-linux; want="{{.NixArm64SHA}}" ;;
    x86_64)  sys=x86_64-linux;  want="{{.NixAmd64SHA}}" ;;
    *) warn "unsupported architecture $(uname -m)"; exit 1 ;;
  esac
  tmp="$(mktemp -d /var/lib/devkit/nix.XXXXXX)"
  "${CURL[@]}" -o "$tmp/nix.tar.xz" \
    "https://releases.nixos.org/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-${sys}.tar.xz"
  got="$(sha256sum "$tmp/nix.tar.xz" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    warn "refused Nix ${NIX_VERSION} with hash $got (expected $want)"
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
  warn "Nix $(cat /var/lib/devkit/.nix) is installed; devkit now pins ${NIX_VERSION}. Recreate the VM (devkit rm) to upgrade."
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
step "checking extra packages"
WANT_PKGS="{{join .Config.AptPackages " "}}"
{{- if .Config.Services.Postgres}}
# services: postgres runs a cluster the sandbox user owns. Ubuntu's packaging
# would also create and start one of its own, as the postgres account; tell
# it not to, and stop one left by an earlier install.
install -d -m 755 /etc/postgresql-common
cat > /etc/postgresql-common/createcluster.conf <<'EOF'
# Written by devkit: the sandbox user runs its own cluster.
create_main_cluster = false
EOF
systemctl disable --now postgresql >/dev/null 2>&1 || true
{{- end}}
{{- if .Config.Tools.Containers.Docker}}
# tools.containers: docker. The packages would start the rootful daemon as
# they install, as root and before the firewall. Masked first, so it never
# runs; the rootless daemon below does not use these units.
systemctl mask docker.service docker.socket containerd.service >/dev/null
{{- end}}
if [ -n "$WANT_PKGS" ] && [ "$(cat /var/lib/devkit/.packages 2>/dev/null || true)" != "$WANT_PKGS" ]; then
  $APT update
  $APT install -y --no-install-recommends $WANT_PKGS
  echo "$WANT_PKGS" > /var/lib/devkit/.packages
fi

# ---- kernel attack surface for unprivileged code ----
step "restricting the kernel attack surface"
# A local privilege escalation is what turns the sandbox user into root, and
# root can drop the firewall. These close the interfaces most kernel exploits
# of recent years needed from an unprivileged process; Ubuntu already
# restricts unprivileged user namespaces, BPF and perf, and this pins the rest.
# Ubuntu's AppArmor restriction lets an unprivileged user namespace be made
# and denies capabilities inside it, but Ubuntu's own profiles exempt named
# programs (rootlesskit, runc, slirp4netns, podman, lxc and more), so a
# tools.packages entry can reopen namespaces with working capabilities.
# kernel.unprivileged_userns_clone, an Ubuntu kernel switch, refuses the
# namespace itself to unprivileged users, exempted or not; root is
# unaffected. tools.containers leaves it open, because rootless containers
# need user namespaces: with true, Lima's containerd runs as the sandbox user;
# with docker, AppArmor below closes them to every account but Docker's. The
# file is rewritten on every boot, so turning containers off closes them again.
cat > /etc/sysctl.d/90-devkit.conf <<'EOF'
kernel.io_uring_disabled = 2
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3
vm.unprivileged_userfaultfd = 0
kernel.yama.ptrace_scope = 1
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.unprivileged_userns_clone = {{if .Config.Tools.Containers.Enabled}}1{{else}}0{{end}}
kernel.sysrq = 0
EOF
sysctl -q -p /etc/sysctl.d/90-devkit.conf || true
# sysctl -p goes on past a key this kernel lacks, and systemd-sysctl skips
# one at boot, so a kernel that is not Ubuntu's cannot fail here. Where the
# switch exists it is applied on its own, and a failure to set it aborts.
if [ -e /proc/sys/kernel/unprivileged_userns_clone ]; then
  sysctl -q -w kernel.unprivileged_userns_clone={{if .Config.Tools.Containers.Enabled}}1{{else}}0{{end}}
else
  note "this kernel has no kernel.unprivileged_userns_clone; unprivileged user namespaces are only restricted by AppArmor"
fi

# The kernel crypto socket API (AF_ALG: algif_aead and its siblings) exposes
# kernel crypto internals to unprivileged processes and has a long history of
# memory-safety bugs, Copy-Fail (CVE-2026-31431) among them. Nothing in a
# normal dev workflow uses it, so the whole family is taken out of reach: the
# modules are blocked from autoloading, and any already loaded and unused are
# removed. This does not stop a kernel bug elsewhere; it removes one reachable
# surface, and every future algif bug with it. The security pocket above still
# patches the specific CVE.
cat > /etc/modprobe.d/devkit-harden.conf <<'EOF'
install af_alg /bin/false
install algif_aead /bin/false
install algif_hash /bin/false
install algif_skcipher /bin/false
install algif_rng /bin/false
EOF
for m in algif_aead algif_hash algif_skcipher algif_rng af_alg; do
  rmmod "$m" 2>/dev/null || true
done

# ---- security updates: Ubuntu's security pocket, before the firewall ----
step "applying Ubuntu security updates (can take a minute)"
# A pinned image gets weaker every week. Only the security pocket is
# applied, so the rest of the system stays at the image's versions. A new
# kernel on disk runs from the next restart.
{{- if and .Config.VM.SecurityUpdatesOn (ne .Config.Network.Mode "none")}}
SEC_SOURCES=/var/lib/devkit/security.sources
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  . /etc/os-release
  uris="$(awk '/^URIs:/{print $2; exit}' /etc/apt/sources.list.d/ubuntu.sources)"
  cat > "$SEC_SOURCES" <<EOF
Types: deb
URIs: $uris
Suites: ${VERSION_CODENAME}-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
  SECAPT="$APT -o Dir::Etc::SourceList=$SEC_SOURCES -o Dir::Etc::SourceParts=/dev/null"
  before="$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -n1)"
  # full-upgrade, not upgrade: a kernel security update arrives as a new
  # package that upgrade would hold back.
  # Error-Mode=any: a failed index download is an error, not a warning
  # followed by an upgrade against the previous lists.
  if $SECAPT -o APT::Update::Error-Mode=any update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive $SECAPT full-upgrade -y -q >/dev/null 2>&1; then
    after="$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -n1)"
    [ "$before" != "$after" ] && note "a kernel security update was installed; run 'devkit down && devkit up' to boot into it"
    # When the pocket was last applied successfully. apt keeps the index
    # files' upstream timestamps, so they say nothing about this boot.
    date -u +%s > /var/lib/devkit/.security-updated && chmod 644 /var/lib/devkit/.security-updated
  else
    warn "could not apply security updates; continuing with the installed versions"
  fi
fi
{{- end}}

# ---- trust store: the distro's current bundle, minus network.distrust ----
step "refreshing the CA trust store"
# ca-certificates is the source of truth and is refreshed on every boot, so a
# VM created before a CA was removed upstream catches up on its next start.
# Runs before the firewall, like apt's other work here; apt verifies it.
if [ "$MODE" != "none" ]; then
  ($APT update -q && $APT install -y -q --only-upgrade ca-certificates) >/dev/null 2>&1 \
    || warn "could not refresh ca-certificates; keeping the installed bundle"
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
# Record only roots this boot actually disables, so removing the entry later
# restores the distro's setting rather than re-enabling a root the distro
# itself had disabled.
if grep -q "^mozilla/$f\.crt\$" "$CACONF"; then
  sed -i "s|^mozilla/$f\.crt\$|!mozilla/$f.crt|" "$CACONF"
  echo "${n// /_}" >> /var/lib/devkit/.distrust
elif grep -q "^!mozilla/$f\.crt\$" "$CACONF"; then
  warn "network.distrust: '$n' is already disabled by the distro"
else
  warn "network.distrust: no root named '$n' in the system bundle"
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
# profile.d only reaches login shells. Non-login SSH commands (an IDE's
# remote server, ssh vm 'node ...') read /etc/environment through PAM; the
# same settings reach them from Lima's block there, which the instance
# config pins (see env in the Lima template), so nothing is written here.
cat > /usr/local/bin/devkit-audit <<'PYEOF'
{{.AuditScript}}
PYEOF
chmod 755 /usr/local/bin/devkit-audit

# ---- proxy account and proxy environment ----
step "configuring the egress proxy"
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
  sed -i '/^#LIMA-START/,/^#LIMA-END/!{/^\(HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy\|NO_PROXY\|no_proxy\)=/d}' /etc/environment
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
  sed -i '/^#LIMA-START/,/^#LIMA-END/!{/^\(HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy\|NO_PROXY\|no_proxy\)=/d}' /etc/environment
fi
# tools.containers: docker. Every kind of session, login shell or not, finds
# the API filter's socket, by the same two routes as the proxy settings.
sed -i '/^#LIMA-START/,/^#LIMA-END/!{/^DOCKER_HOST=/d}' /etc/environment
{{- if .Config.Tools.Containers.Docker}}
echo "export DOCKER_HOST=unix://{{.FilterSocket}}" > /etc/profile.d/devkit-docker.sh
echo "DOCKER_HOST=unix://{{.FilterSocket}}" >> /etc/environment
{{- else}}
rm -f /etc/profile.d/devkit-docker.sh
{{- end}}
# Keep Lima's block at the end of /etc/environment, and never edit inside it:
# the proxy edits above skip it. Lima's boot script rewrites that block on
# every boot and, if the file then differs, terminates the user's sessions,
# which is the trigger for the logind stall above. With the block last and
# untouched, later boots see no change and nothing is terminated.
if grep -q '^#LIMA-START' /etc/environment; then
  limablock="$(sed -n '/^#LIMA-START/,/^#LIMA-END/p' /etc/environment)"
  sed -i '/^#LIMA-START/,/^#LIMA-END/d' /etc/environment
  printf '%s\n' "$limablock" >> /etc/environment
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
{{- if .Config.Tools.Containers.Docker}}

# ---- Docker: rootless, under an account of its own ----
step "setting up Docker under its own account"
# tools.containers: docker. The daemon runs as devkit-docker, never as root
# and never as the sandbox user: rootless Docker needs user namespaces with
# capabilities in them, and only that account is given them (see AppArmor
# below). The rootful units stay masked; one an earlier install started is
# stopped.
for u in docker.socket docker.service containerd.service; do
  if systemctl is-active --quiet "$u"; then systemctl stop "$u"; fi
done
systemctl mask docker.service docker.socket containerd.service >/dev/null
DOCKER_GID="$(id -g "$DOCKER_ACCOUNT")"
SANDBOX_GID="$(id -g "$DEVKIT_USER")"
# The API filter runs as an account of its own, never root, in the Docker
# account's group so that it can pass through the daemon's directory. It is
# the only way to the daemon: anyone who can use the daemon's socket can ask
# for anything the account may do.
FILTER_ACCOUNT={{.FilterAccount}}
id "$FILTER_ACCOUNT" >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$FILTER_ACCOUNT"
usermod -a -G "$DOCKER_ACCOUNT" "$FILTER_ACCOUNT"
# The account's home is traversable, so the filter reaches the socket in
# run/; the image store under .local stays the account's alone.
install -d -o "$DOCKER_ACCOUNT" -g "$DOCKER_ACCOUNT" -m 0711 "$DOCKER_HOME"
install -d -o "$DOCKER_ACCOUNT" -g "$DOCKER_ACCOUNT" -m 0700 "$DOCKER_HOME/.local" "$DOCKER_HOME/.local/share"
install -d -o "$DOCKER_ACCOUNT" -g "$DOCKER_ACCOUNT" -m 0750 "$DOCKER_HOME/run"
chmod 0711 "$DOCKER_HOME"
chmod 0750 "$DOCKER_HOME/run"
# The socket is outside the account's runtime directory, which logind remakes
# 0700 at each boot. The default ACL gives the filter's account read and
# write on the socket the daemon creates there, whatever group the daemon
# gives it. The sandbox user's entries, which an earlier devkit set, go.
run_acl="$(getfacl -cp "$DOCKER_HOME/run")"
if grep -q "^user:$DEVKIT_USER:" <<< "$run_acl"; then setfacl -x "u:$DEVKIT_USER" "$DOCKER_HOME/run"; fi
if grep -q "^default:user:$DEVKIT_USER:" <<< "$run_acl"; then setfacl -x "d:u:$DEVKIT_USER" "$DOCKER_HOME/run"; fi
setfacl -m "u:$FILTER_ACCOUNT:rx" -m "d:u:$FILTER_ACCOUNT:rw" "$DOCKER_HOME/run"
# Traversal only, so the daemon can reach the workspace's path and the
# filter can resolve the symlinks of a bind source in it. Nothing in the
# home is readable this way, and the workspace itself carries no ACL: it is
# shared by the ID-mapped mount in the daemon's own namespace (see below).
setfacl -m "u:$DOCKER_ACCOUNT:x" "$DEVKIT_HOME"
setfacl -m "u:$FILTER_ACCOUNT:x" "$DEVKIT_HOME"
# Its user manager and D-Bus session, which the systemd cgroup driver needs.
# Its slice is held above, so nothing it starts has network yet.
loginctl enable-linger "$DOCKER_ACCOUNT"

# User namespaces stay on in the kernel for this account and close to every
# other. Ubuntu's AppArmor restriction denies capabilities inside a user
# namespace to every program its profiles do not exempt, and the exemption is
# by path. The three Docker needs are made executable by the account only,
# through dpkg-statoverride so that package upgrades keep it; every other
# exempting profile is disabled, so a package that ships an exempted program
# opens nothing. What devkit changes is recorded, and turning Docker off
# undoes exactly that.
if [ ! -r /sys/kernel/security/apparmor/profiles ]; then
  warn "AppArmor is not active, so it cannot close user namespaces to the sandbox user; refusing tools.containers: docker"
  exit 1
fi
DOCKER_OVERRIDES=/etc/devkit/docker-statoverrides
DOCKER_DISABLED=/etc/devkit/docker-apparmor-disabled
touch "$DOCKER_OVERRIDES" "$DOCKER_DISABLED"
chmod 644 "$DOCKER_OVERRIDES" "$DOCKER_DISABLED"
for p in rootlesskit runc slirp4netns; do
  [ -f "/etc/apparmor.d/$p" ] || continue
  for b in $(sed -n 's/^profile [^ ]* \(\/[^ ]*\) flags=(unconfined).*/\1/p' "/etc/apparmor.d/$p"); do
    [ -e "$b" ] || continue
    # The owner and mode before the first override, to put back later.
    if ! awk -v p="$b" '$1==p{f=1} END{exit !f}' "$DOCKER_OVERRIDES"; then
      stat -c '%n %U %G %a' "$b" >> "$DOCKER_OVERRIDES"
    fi
    have="$(dpkg-statoverride --list "$b")" || have=""
    if [ "$have" != "root $DOCKER_ACCOUNT 0750 $b" ]; then
      dpkg-statoverride --force-all --update --add root "$DOCKER_ACCOUNT" 0750 "$b"
    fi
  done
done
loaded_profiles="$(sed 's/ ([^()]*)$//' /sys/kernel/security/apparmor/profiles)"
for f in /etc/apparmor.d/*; do
  [ -f "$f" ] || continue
  n="$(basename "$f")"
  case "$n" in rootlesskit|runc|slirp4netns) continue ;; esac
  grep -q 'flags=(unconfined)' "$f" && grep -qE '^\s*userns,' "$f" || continue
  if [ ! -e "/etc/apparmor.d/disable/$n" ] && [ ! -L "/etc/apparmor.d/disable/$n" ]; then
    ln -s "$f" "/etc/apparmor.d/disable/$n"
    echo "$n" >> "$DOCKER_DISABLED"
  fi
  # A disabled profile is not loaded at the next boot; this one's is unloaded
  # now, since the boot loaded it before this script ran.
  names="$(sed -n 's/^[[:space:]]*profile[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' "$f")"
  [ -n "$names" ] || names="$(apparmor_parser -N "$f")"
  loaded=0
  while IFS= read -r name; do
    if [ -n "$name" ] && grep -qxF -- "$name" <<< "$loaded_profiles"; then loaded=1; fi
  done <<< "$names"
  if [ "$loaded" = 1 ]; then apparmor_parser -R "$f"; fi
done
{{- if .Config.Tools.ContainerRuntime.Gvisor}}

# ---- gVisor: pinned release, verified by SHA-512 ----
step "checking gVisor (downloaded when its pinned release changes)"
# tools.container_runtime runs containers under gVisor's runsc. The archive
# holds runsc, its containerd shim, and gvisor-bin/, helpers runsc looks for
# beside itself. The checksum of the archive that was installed is recorded
# once everything is in place, so a half-done install is redone on the next
# boot, and an installed runsc is never taken on its version string alone.
GVISOR_RELEASE="{{.GvisorRelease}}"
GVISOR_ARCH="$(uname -m)"
case "$GVISOR_ARCH" in
  aarch64) want="{{.GvisorArm64SHA512}}" ;;
  x86_64)  want="{{.GvisorAmd64SHA512}}" ;;
  *) warn "unsupported architecture $GVISOR_ARCH"; exit 1 ;;
esac
GVISOR_STAMP=/etc/devkit/gvisor.sha512
if [ "$(cat "$GVISOR_STAMP" 2>/dev/null || true)" != "$want" ] || [ ! -x /usr/local/bin/runsc ] \
  || [ ! -x /usr/local/bin/containerd-shim-runsc-v1 ] || [ ! -d /usr/local/bin/gvisor-bin ]; then
  rm -f "$GVISOR_STAMP"
  # Left by an install that failed part way; never where runsc looks.
  rm -rf /usr/local/bin/.gvisor-bin.*
  tmp="$(mktemp -d /var/lib/devkit/gvisor.XXXXXX)"
  "${CURL[@]}" -o "$tmp/gvisor.tar.zstd" \
    "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${GVISOR_ARCH}/gvisor.tar.zstd"
  # Checked before anything in the archive is unpacked.
  if ! printf '%s  %s\n' "$want" "$tmp/gvisor.tar.zstd" | sha512sum -c --quiet - >/dev/null 2>&1; then
    warn "refused gVisor ${GVISOR_RELEASE} with SHA-512 $(sha512sum "$tmp/gvisor.tar.zstd" | awk '{print $1}') (expected $want)"
    rm -rf "$tmp"; exit 1
  fi
  mkdir "$tmp/x"
  tar --zstd -xf "$tmp/gvisor.tar.zstd" -C "$tmp/x" --no-same-owner
  for f in runsc containerd-shim-runsc-v1 gvisor-bin/gvisor_sentry; do
    if [ ! -f "$tmp/x/$f" ]; then
      warn "the gVisor ${GVISOR_RELEASE} archive has no $f"
      rm -rf "$tmp"; exit 1
    fi
  done
  # The helpers are copied to a directory beside their final place and
  # renamed into it, so runsc never finds a partly copied set.
  new="$(mktemp -d /usr/local/bin/.gvisor-bin.XXXXXX)"
  cp -R "$tmp/x/gvisor-bin/." "$new/"
  chown -R root:root "$new"
  chmod -R go-w "$new"
  chmod 755 "$new"
  if [ -e /usr/local/bin/gvisor-bin ] || [ -L /usr/local/bin/gvisor-bin ]; then
    mv -T /usr/local/bin/gvisor-bin "$new.old"
  fi
  mv -T "$new" /usr/local/bin/gvisor-bin
  rm -rf "$new.old"
  install -m 755 -o root -g root "$tmp/x/runsc" "$tmp/x/containerd-shim-runsc-v1" /usr/local/bin/
  rm -rf "$tmp"
  echo "$want" > "$GVISOR_STAMP"
  chmod 644 "$GVISOR_STAMP"
fi
{{- end}}

# The daemon's settings and its launcher are root's: the account must not be
# able to change either. Published ports bind to the VM's loopback, and no
# container process gains privileges through setuid programs, unless a
# docker run asks otherwise.
install -d -m 0755 /etc/devkit/docker
cat > /etc/devkit/docker/daemon.json <<'EOF'
{{.DockerDaemonJSON}}
EOF
chmod 644 /etc/devkit/docker/daemon.json
# The workspace is shared by an ID-mapped mount of it over itself, in the
# daemon's own mount namespace: through it the account, and so container
# root, is the sandbox user on disk, and the account's subordinate IDs are
# the sandbox user's. Nothing changes on disk and nothing outside the
# workspace is shared.
subid() { awk -F: -v u="$1" '$1==u {print $2 " " $3; exit}' "$2"; }
IDMAP="u:$SANDBOX_UID:$DOCKER_UID:1 g:$SANDBOX_GID:$DOCKER_GID:1"
read -r U_SUB U_SUBN <<< "$(subid "$DEVKIT_USER" /etc/subuid)"
read -r G_SUB G_SUBN <<< "$(subid "$DEVKIT_USER" /etc/subgid)"
read -r DU_SUB DU_SUBN <<< "$(subid "$DOCKER_ACCOUNT" /etc/subuid)"
read -r DG_SUB DG_SUBN <<< "$(subid "$DOCKER_ACCOUNT" /etc/subgid)"
if [ -n "$U_SUB" ] && [ -n "$DU_SUB" ]; then
  n="$U_SUBN"; if [ "$DU_SUBN" -lt "$n" ]; then n="$DU_SUBN"; fi
  IDMAP="$IDMAP u:$U_SUB:$DU_SUB:$n"
fi
if [ -n "$G_SUB" ] && [ -n "$DG_SUB" ]; then
  n="$G_SUBN"; if [ "$DG_SUBN" -lt "$n" ]; then n="$DG_SUBN"; fi
  IDMAP="$IDMAP g:$G_SUB:$DG_SUB:$n"
fi
# The mount must exist before the daemon first starts, so the workspace is
# made here if devkit's user provisioning has not made it yet.
WS="$DEVKIT_HOME/{{.WorkspaceDir}}"
if [ ! -e "$WS" ] && [ ! -L "$WS" ]; then
  install -d -o "$DEVKIT_USER" -g "$SANDBOX_GID" -m 0755 "$WS"
fi
# The workspace by its real path, which the mount, the API filter and the
# runtime guard all use. Only the home is resolved: the workspace itself is
# the sandbox user's, and a symlink there would let it choose what Docker
# may mount, so the daemon refuses to start on one.
WS_REAL="$(readlink -f "$DEVKIT_HOME")/{{.WorkspaceDir}}"
DOCKER_RUN="/run/user/$DOCKER_UID"
cat > /usr/local/sbin/devkit-dockerd <<EOF
#!/bin/sh
# Written by devkit's provisioning on every boot. devkit-dockerd.service runs
# this as root in a mount namespace of its own (PrivateMounts=yes): it mounts
# the workspace over itself ID-mapped, then becomes $DOCKER_ACCOUNT and starts
# rootless Docker.
set -eu
W='$WS_REAL'
if [ -L "\$W" ] || [ ! -d "\$W" ] || [ "\$(stat -c %u "\$W")" != "$SANDBOX_UID" ]; then
  echo "devkit-dockerd: the workspace \$W is not a directory of the sandbox user's" >&2
  exit 1
fi
mount --bind -o "X-mount.idmap=$IDMAP" "\$W" "\$W"
exec setpriv --reuid $DOCKER_UID --regid $DOCKER_GID --init-groups \\
  env HOME=$DOCKER_HOME XDG_RUNTIME_DIR=$DOCKER_RUN DBUS_SESSION_BUS_ADDRESS=unix:path=$DOCKER_RUN/bus \\
  PATH=/usr/bin:/usr/sbin:/bin:/sbin{{if ne .Config.Network.Mode "none"}} \\
  HTTP_PROXY={{.DockerProxy}} HTTPS_PROXY={{.DockerProxy}} NO_PROXY=localhost,127.0.0.1{{end}} \\
  rootlesskit --state-dir=$DOCKER_RUN/dockerd-rootless --net=slirp4netns --mtu=65520 \\
  --slirp4netns-sandbox=auto --slirp4netns-seccomp=auto --disable-host-loopback=false \\
  --port-driver=builtin --copy-up=/etc --copy-up=/run --propagation=rslave \\
  sh -c "rm -f /run/docker /run/containerd /run/xtables.lock; exec dockerd --config-file=/etc/devkit/docker/daemon.json --host=unix://{{.DockerSocket}} --data-root=$DOCKER_HOME/.local/share/docker --exec-root=$DOCKER_RUN/docker --pidfile=$DOCKER_RUN/docker.pid"
EOF
chmod 755 /usr/local/sbin/devkit-dockerd
# No [Install] section: nothing starts the daemon at boot. This script starts
# it once the firewall is applied and the hold is lifted (see below), or, when
# devkit's guest binary is not installed yet, the install step does once this
# script has finished, so a container that restarts with the VM gets nothing
# before the firewall.
cat > /etc/systemd/system/devkit-dockerd.service <<EOF
[Unit]
Description=devkit: rootless Docker under the $DOCKER_ACCOUNT account
Requires=user@$DOCKER_UID.service
After=user@$DOCKER_UID.service

[Service]
ExecStart=/usr/local/sbin/devkit-dockerd
PrivateMounts=yes
Delegate=yes
Restart=on-failure
RestartSec=2
EOF

# ---- Docker's API filter and runtime guard ----
# Both are devkit's guest binary under other names, installed by root once
# its hash is the one this script expects (see the egress proxy below). On a
# first boot it arrives after this script, and devkit up waits for the
# filter then. Their settings are root's, like the daemon's.
RUNC_REAL=""
if [ -f /etc/apparmor.d/runc ]; then
  RUNC_REAL="$(awk '$1 == "profile" && $4 == "flags=(unconfined)" {print $3; exit}' /etc/apparmor.d/runc)"
fi
if [ -z "$RUNC_REAL" ]; then RUNC_REAL="$(command -v runc || true)"; fi
if [ -z "$RUNC_REAL" ] || [ ! -x "$RUNC_REAL" ]; then
  warn "runc was not found; Docker's runtime guard needs it"
  exit 1
fi
RUNC_REAL="$(readlink -f "$RUNC_REAL")"
DOCKER_INIT="$(readlink -f "$(PATH=/usr/bin:/usr/sbin:/bin:/sbin command -v docker-init || echo /usr/bin/docker-init)")"
DATA_ROOT="$(readlink -f "$DOCKER_HOME")/.local/share/docker"
for v in "$WS_REAL" "$RUNC_REAL" "$DOCKER_INIT" "$DATA_ROOT"; do
  case "$v" in
    ""|[!/]*|*[\"\\]*|*[[:cntrl:]]*) warn "cannot write the path '$v' into Docker's guard settings"; exit 1 ;;
  esac
done
cat > {{.FilterConfig}} <<EOF
{
  "daemon_socket": "{{.DockerSocket}}",
  "workspace": "$WS_REAL",
  "runtimes": {{.FilterRuntimes}},
  "runtime_guard": true,
  "capabilities": ["IPC_LOCK", "NET_BIND_SERVICE"]
}
EOF
cat > {{.GuardConfig}} <<EOF
{
  "runc": "$RUNC_REAL",{{.GuardRunscJSON}}
  "workspace": "$WS_REAL",
  "data_root": "$DATA_ROOT",
  "docker_init": "$DOCKER_INIT"
}
EOF
chmod 644 {{.FilterConfig}} {{.GuardConfig}}
ln -sfn {{.EgressBinary}} {{.FilterBinary}}
ln -sfn {{.EgressBinary}} {{.GuardBinary}}
{{- if .Config.Tools.ContainerRuntime.Gvisor}}
# The guard in front of runsc, one name per gVisor runtime: the name tells
# it which runtime's arguments to expect. Like gVisor itself, the links stay
# if the runtime changes back to runc; guard.json then has no runsc entry,
# and the guard under these names refuses everything.
for l in {{.GuardRunscBinaries}}; do ln -sfn {{.EgressBinary}} "$l"; done
{{- end}}
# Socket activation: systemd holds the socket, root's and the sandbox
# user's group's only, in a directory only root may change, and starts the
# filter on the first connection. A daemon that is not up yet is answered
# with a refusal of the filter's own.
SANDBOX_GROUP="$(id -gn "$DEVKIT_USER")"
cat > /etc/systemd/system/{{.FilterUnit}}.socket <<EOF
[Unit]
Description=devkit: the Docker API filter's socket

[Socket]
ListenStream={{.FilterSocket}}
SocketUser=root
SocketGroup=$SANDBOX_GROUP
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
EOF
# ProtectHome is read-only, not off: the filter resolves symlinks in the
# workspace, through the traversal ACL on the home.
cat > /etc/systemd/system/{{.FilterUnit}}.service <<'EOF'
[Unit]
Description=devkit: Docker API filter
Requires={{.FilterUnit}}.socket
After={{.FilterUnit}}.socket

[Service]
ExecStart={{.FilterBinary}} -config {{.FilterConfig}}
User={{.FilterAccount}}
Group={{.FilterAccount}}
SupplementaryGroups={{.DockerAccount}}
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
IPAddressDeny=any
EOF
systemctl daemon-reload
systemctl enable {{.FilterUnit}}.socket >/dev/null 2>&1
if systemctl is-active --quiet {{.FilterUnit}}.service; then systemctl stop {{.FilterUnit}}.service; fi
systemctl restart {{.FilterUnit}}.socket

# The client's proxy settings, which Docker hands to containers and builds.
# Run by the sandbox user, from the user provisioning and again by devkit up
# after it syncs the workspace.
cat > {{.DockerConfigHelper}} <<'DKEOF'
{{.DockerConfigScript}}
DKEOF
chmod 755 {{.DockerConfigHelper}}
{{- else}}

# ---- Docker off: undo what tools.containers: docker set up ----
# The account and its images stay; its daemon stops, and every change devkit
# recorded to AppArmor and to file modes is put back. The rootful units stay
# masked while their packages are installed.
if [ -f /etc/systemd/system/devkit-dockerd.service ]; then
  step "removing Docker's daemon (tools.containers is not docker)"
  systemctl stop devkit-dockerd.service
  rm -f /etc/systemd/system/devkit-dockerd.service /usr/local/sbin/devkit-dockerd
  systemctl daemon-reload
fi
if [ -f /etc/systemd/system/{{.FilterUnit}}.socket ]; then
  systemctl stop {{.FilterUnit}}.socket {{.FilterUnit}}.service
  systemctl disable {{.FilterUnit}}.socket >/dev/null 2>&1
  rm -f /etc/systemd/system/{{.FilterUnit}}.socket /etc/systemd/system/{{.FilterUnit}}.service
  systemctl daemon-reload
fi
rm -f {{.FilterSocket}} {{.FilterBinary}} {{.GuardBinary}} {{.FilterConfig}} {{.GuardConfig}}
if [ -f /etc/devkit/docker-statoverrides ]; then
  while read -r path owner group mode; do
    [ -n "$path" ] || continue
    if dpkg-statoverride --list "$path" >/dev/null; then dpkg-statoverride --remove "$path"; fi
    if [ -e "$path" ]; then chown "$owner:$group" "$path"; chmod "$mode" "$path"; fi
  done < /etc/devkit/docker-statoverrides
  rm -f /etc/devkit/docker-statoverrides
fi
if [ -f /etc/devkit/docker-apparmor-disabled ]; then
  while read -r n; do
    [ -n "$n" ] || continue
    if [ -L "/etc/apparmor.d/disable/$n" ]; then rm -f "/etc/apparmor.d/disable/$n"; fi
    if [ -f "/etc/apparmor.d/$n" ]; then apparmor_parser -r "/etc/apparmor.d/$n"; fi
  done < /etc/devkit/docker-apparmor-disabled
  rm -f /etc/devkit/docker-apparmor-disabled
fi
if id {{.DockerAccount}} >/dev/null 2>&1; then
  loginctl disable-linger {{.DockerAccount}}
  home_acl="$(getfacl -cp "$DEVKIT_HOME" 2>/dev/null)" || home_acl=""
  if grep -q '^user:{{.DockerAccount}}:' <<< "$home_acl"; then setfacl -x "u:{{.DockerAccount}}" "$DEVKIT_HOME"; fi
fi
if id {{.FilterAccount}} >/dev/null 2>&1; then
  home_acl="$(getfacl -cp "$DEVKIT_HOME" 2>/dev/null)" || home_acl=""
  if grep -q '^user:{{.FilterAccount}}:' <<< "$home_acl"; then setfacl -x "u:{{.FilterAccount}}" "$DEVKIT_HOME"; fi
fi
rm -f {{.DockerConfigHelper}}
{{- end}}

# ---- name resolution: who may ask, and through what ----
# With DNS=proxy (or none) nothing but the proxy may resolve names: libc
# stays pointed at the upstream resolvers and the stub is off, so neither the
# stub nor resolved over D-Bus relays for the sandbox, and the firewall below
# rejects port 53 for every account but the proxy's. With DNS=resolvers the VM
# uses the stub as Ubuntu ships it. Applied last among the steps before the
# firewall, after root's downloads.
mkdir -p /etc/systemd/resolved.conf.d
if [ "$MODE" = "none" ] || [ "${DNS:-proxy}" = "proxy" ]; then
  printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/devkit.conf
  ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
else
  rm -f /etc/systemd/resolved.conf.d/devkit.conf
  ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi
systemctl restart systemd-resolved || true

# ---- firewall ----
step "applying the firewall"
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
# Rebuild under a DROP policy, so the instant between flushing the old rules
# and appending the new ones is closed rather than open; the final REJECT
# rules below catch everything, and the policy goes back to ACCEPT after.
for t in iptables ip6tables; do
  $t -P OUTPUT DROP 2>/dev/null || true
  $t -F OUTPUT 2>/dev/null || true
done
# Connection state is trusted only for root and the proxy. conntrack keys a
# flow by addresses and ports, not by the account that owns it, and an entry
# outlives its socket: a sandbox socket bound to a source port the proxy or
# root has just used matches that entry and would pass as ESTABLISHED. So for
# every other account the only state that counts is the reply direction of a
# connection made to the guest (an SSH session, a forwarded port); anything it
# originates must match an explicit rule below or be rejected.
for t in iptables ip6tables; do
  $t -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  $t -A OUTPUT -m owner --uid-owner 0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  $t -A OUTPUT -m owner --uid-owner devkit-proxy -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  $t -A OUTPUT -m conntrack --ctdir REPLY -j ACCEPT 2>/dev/null || true
done
# Replies from the guest's sshd to the host (Lima's control channel) on
# sessions opened before conntrack loaded, which conntrack may record in the
# wrong direction. Only root can bind port 22, so sandboxed code cannot use it.
iptables -A OUTPUT -d "$HOST_IP" -p tcp --sport 22 -j ACCEPT
{{- if .HostProxy}}
# network.enforce: host. No DNS for any account: the proxy on the Mac
# resolves. The proxy's account may reach that proxy, one TCP port on the
# host, and nothing else; this comes before the host is rejected below.
iptables -A OUTPUT -d "$HOST_PROXY_IP" -p tcp --dport "$HOST_PROXY_PORT" -m owner --uid-owner devkit-proxy -j ACCEPT
{{- else}}
# DNS only to the configured resolvers, never to arbitrary port-53 endpoints,
# and not at all when air-gapped. By default (DNS=proxy) only the proxy's
# account may query them: it resolves allowed hosts itself, and nothing the
# sandbox runs can put data into a query name. systemd-resolved's stub is
# switched off in that mode, so lookups fail closed and at once.
if [ "${MODE:-allowlist}" != "none" ]; then
  if [ "${DNS:-proxy}" = "resolvers" ]; then DNS_OWNER=""; else DNS_OWNER="-m owner --uid-owner devkit-proxy"; fi
  for ip in $DNS_IPS; do
    iptables -A OUTPUT -d "$ip" -p udp --dport 53 $DNS_OWNER -j ACCEPT
    iptables -A OUTPUT -d "$ip" -p tcp --dport 53 $DNS_OWNER -j ACCEPT
  done
fi
{{- end}}
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
{{- if not .HostProxy}}
case "${MODE:-allowlist}" in
  allowlist|open)
    iptables -A OUTPUT -m owner --uid-owner devkit-proxy -j ACCEPT ;;
esac
{{- end}}
iptables -A OUTPUT -j REJECT
ip6tables -A OUTPUT -j REJECT 2>/dev/null || true
for t in iptables ip6tables; do $t -P OUTPUT ACCEPT 2>/dev/null || true; done
mkdir -p /run/devkit && date +%s > /run/devkit/firewall-at && chmod 644 /run/devkit/firewall-at
EOF
chmod 755 /usr/local/sbin/devkit-firewall

# ---- boot hold: the sandbox user has no network until the firewall is up ----
# The firewall above is applied by this script, which Lima runs late in boot.
# Lima's own SSH sessions run as the sandbox user well before that, and sshd
# and bash then read files that user can write (~/.ssh/rc, ~/.bashrc,
# ~/.profile). Code planted there in an earlier session would get unfiltered
# network on every reboot. This unit runs on every later boot before sshd
# starts and rejects all new outbound traffic from the sandbox user until the
# firewall replaces it. Root, which only runs devkit's own provisioning, keeps
# the network it needs for downloads. The first boot needs no hold: nothing of
# the sandbox's exists on a fresh disk.
# The markers delimit what TestNetnsFirewall runs as root on the test host:
# keep only the hold's own lookups and script between them.
# ---- begin boot-hold generator (TestNetnsFirewall runs exactly this) ----
RESOLVE_UID="$(id -u systemd-resolve 2>/dev/null || true)"
# The sandbox's rootless containers run processes as its subordinate UIDs.
SUBUIDS="$(awk -F: -v u="$DEVKIT_USER" '$1==u{print $2"-"($2+$3-1); exit}' /etc/subuid 2>/dev/null || true)"
{{- if .Config.Tools.Containers.Docker}}
# Docker's account is held too: its slirp4netns carries every container's
# traffic, and its user manager starts at boot.
{{- end}}
cat > /usr/local/sbin/devkit-boot-hold <<EOF
#!/bin/sh
# Loopback is held too: the egress proxy and systemd-resolved listen there,
# and either would relay for the sandbox before the firewall exists. Root
# resolves upstream directly and keeps its downloads.
# Decided by owner and direction, never by "established": a held account's
# socket could otherwise ride a tracked flow root opened from the same source
# port (see the firewall). Replies on connections made to the guest, its SSH
# sessions, still pass. systemd-resolved is held in every mode: provisioning
# never needs it, and the sandbox could ask it over D-Bus.
modprobe nf_conntrack 2>/dev/null || true
for t in iptables ip6tables; do
  \$t -P OUTPUT ACCEPT 2>/dev/null || true
  \$t -F OUTPUT 2>/dev/null || true
  for who in $SANDBOX_UID $SUBUIDS{{if .Config.Tools.Containers.Docker}} $DOCKER_UID{{end}}; do
    \$t -A OUTPUT -m owner --uid-owner \$who -m conntrack --ctdir REPLY -j ACCEPT 2>/dev/null || true
    \$t -A OUTPUT -m owner --uid-owner \$who -j REJECT 2>/dev/null || true
  done
  if [ -n "$RESOLVE_UID" ]; then
    \$t -A OUTPUT -m owner --uid-owner $RESOLVE_UID -j REJECT 2>/dev/null || true
  fi
done
EOF
# ---- end boot-hold generator ----
chmod 755 /usr/local/sbin/devkit-boot-hold
cat > /etc/systemd/system/devkit-boot-hold.service <<'EOF'
[Unit]
Description=devkit: no network for the sandbox user until the firewall is applied
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target ssh.socket ssh.service cloud-init-local.service sysinit.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/devkit-boot-hold

[Install]
WantedBy=sysinit.target
EOF
systemctl daemon-reload
systemctl enable devkit-boot-hold.service >/dev/null 2>&1 || true

# ---- egress proxy service ----
cat > /etc/systemd/system/{{.EgressService}}.service <<EOF
[Unit]
Description=devkit egress proxy (domain allowlist + audit log)
After=network-online.target
ConditionPathExists={{.EgressBinary}}

[Service]
EnvironmentFile=/etc/devkit/egress.conf
ExecStart={{.EgressBinary}} -listen {{.ProxyListen}} -audit{{if .HostProxy}} -upstream {{.HostProxy}}{{end}} \$EXTRA_ARGS
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
{{- if .Config.Tools.Containers.Docker}}
  prev="$(sha256sum {{.EgressBinary}} 2>/dev/null | awk '{print $1}')"
{{- end}}
  install -m 755 -o root -g root "$tmp" {{.EgressBinary}}
{{- if or (ne .Config.Network.Mode "none") (not .Config.Tools.Containers.Docker)}}
  systemctl restart {{.EgressService}} || true
{{- end}}
{{- if .Config.Tools.Containers.Docker}}
  # Every runtime in daemon.json is this binary under a guard's name, so the
  # system script starts the daemon only once it is installed; when it was
  # missing or another build, the daemon starts here. Only once this boot's
  # provisioning has finished: /run is emptied at every boot and only the
  # firewall writes firewall-at there, after provisioning has removed the
  # stamp, which it writes back as its last step, after the hold is lifted.
  # Both present means the firewall decides, as when provisioning starts it.
  # A binary that changed under a running daemon gets a restart, so the
  # daemon never keeps probing what it found at its start.
  if [ -f /run/devkit/firewall-at ] && [ -s /etc/devkit/provision.id ]; then
    if ! systemctl is-active --quiet devkit-dockerd.service; then
      systemctl start devkit-dockerd.service || true
    elif [ "$prev" != "$got" ]; then
      systemctl restart devkit-dockerd.service || true
    fi
  fi
  # The binary is Docker's API filter too, started afresh on its next
  # connection; the runtime guard runs it anew for each container.
  systemctl stop {{.FilterUnit}}.service || true
  systemctl restart {{.FilterUnit}}.socket || true
{{- end}}
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

# ---- lift the provisioning hold: the firewall decides from here ----
# On systemd 255, clearing IPAddressDeny or reverting alone leaves the
# slice's filter in place; allowing everything and then reverting removes it.
# resolved's comes off with a revert and a restart. Nothing here is excused:
# if a step fails, the script aborts before the stamp.
step "lifting the provisioning hold"
systemctl set-property --runtime "$HOLD_SLICE" IPAddressAllow=any
systemctl revert "$HOLD_SLICE"
systemctl revert systemd-resolved.service
systemctl restart systemd-resolved
{{- if .Config.Tools.Containers.Docker}}
systemctl set-property --runtime "$DOCKER_SLICE" IPAddressAllow=any
systemctl revert "$DOCKER_SLICE"

# ---- Docker: started once the firewall decides ----
# Never earlier: its containers' traffic leaves through slirp4netns under the
# account's ID, which only the firewall confines. It starts here, before the
# module lock, since the daemon loads what it needs as it starts and creates
# its default bridge. A daemon that does not answer on its socket aborts
# provisioning.
{{- if .Config.VM.LockModulesOn}}
# What containers will need (bridges, veth pairs, overlay, NAT and the
# netfilter matches), loaded before the daemon sets up its bridge from inside
# its user namespace, and because nothing can load after the lock below. A
# module this kernel does not have is skipped. Loaded whether or not the
# daemon starts here: when it starts later, from the install step, the lock
# is already on.
{{.ContainerPreload}}
{{- end}}
# Every runtime in daemon.json is devkit's guest binary under a guard's name.
# On a first boot, or after a devkit upgrade, the binary installed here is
# missing or not the one this script expects: devkit up installs it after
# this script, and a daemon started now would find its runtimes dangling
# (with gVisor it gives up and crashes). The daemon then starts from the
# install step instead, once the binary is in place, and never here.
GUEST_WANT="$(cat /etc/devkit/egress.sha256)"
GUEST_OK=0
if [ -n "$GUEST_WANT" ] && [ "$(sha256sum {{.EgressBinary}} 2>/dev/null | awk '{print $1}')" = "$GUEST_WANT" ]; then GUEST_OK=1; fi
if [ "$GUEST_OK" = 1 ]; then
  step "starting Docker"
  systemctl start devkit-dockerd.service
  docker_up=0
  for _ in $(seq 1 90); do
    if timeout 10 docker --host "unix://{{.DockerSocket}}" info >/dev/null 2>&1; then docker_up=1; break; fi
    sleep 1
  done
  if [ "$docker_up" != 1 ]; then
    warn "Docker did not answer on its socket: $(journalctl -u devkit-dockerd.service -n 5 --no-pager -o cat 2>/dev/null | tr '\n' ' ' | cut -c1-400)"
    exit 1
  fi
  # Then through the API filter, as the sandbox user reaches it, so that a
  # broken filter fails provisioning.
  filter_up=0
  for _ in $(seq 1 30); do
    if timeout 10 setpriv --reuid="$SANDBOX_UID" --regid="$SANDBOX_GID" --init-groups curl -q -fsS -o /dev/null --unix-socket {{.FilterSocket}} http://docker/info; then filter_up=1; break; fi
    sleep 1
  done
  if [ "$filter_up" != 1 ]; then
    warn "Docker's API filter did not answer: $(journalctl -u {{.FilterUnit}}.service -n 5 --no-pager -o cat 2>/dev/null | tr '\n' ' ' | cut -c1-400)"
    exit 1
  fi
else
  note "Docker starts once devkit up has installed devkit's guest binary"
fi
{{- end}}
{{- if .Config.VM.LockModulesOn}}

# ---- lock kernel module loading: the last step that could need a module ----
# Any process can make the kernel load a module, for a socket family nobody
# uses or, from a namespace, a link type or netfilter extension: kernel code
# that would otherwise never run. From here no module loads, for root too,
# until the VM restarts, so this comes after everything above has loaded
# what it needs, and nothing below may need one. It is not in the sysctl
# drop-in, which is applied early in boot and would refuse every module the
# boot loads after it. vm.lock_modules: false turns it off.
step "locking kernel module loading"
{{- if .Config.Tools.Containers.Containerd}}
# What rootless containers will need later (bridges, veth pairs, overlay,
# NAT and the netfilter matches CNI uses), loaded now because nothing can
# load afterwards. A module this kernel does not have is skipped.
{{.ContainerPreload}}
{{- end}}
sysctl -q -w kernel.modules_disabled=1
{{- else}}
note "kernel module loading is not locked (vm.lock_modules: false)"
{{- end}}
echo "{{.ProvisionID}}" > /etc/devkit/provision.id
chmod 644 /etc/devkit/provision.id
step "done"
echo "devkit: provisioning done (network=$MODE)"
`

const userTmpl = `#!/bin/bash
# devkit user provisioning. Runs as the sandbox user on every boot.
set -euo pipefail
{{- if eq .Config.Source "mount"}}
if [ ! -e "$HOME/{{.WorkspaceDir}}" ]; then
  ln -s {{shq .MountPath}} "$HOME/{{.WorkspaceDir}}"
fi
{{- else}}
mkdir -p "$HOME/{{.WorkspaceDir}}"
{{- end}}
{{- if .Config.Tools.Containers.Docker}}
# The proxy Docker's client hands to containers and builds, with the
# workspace's Compose services exempt. devkit up runs it again after a sync.
{{.DockerConfigHelper}}
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
	HostProxyIP, HostProxyPort                                                 string
	DockerAccount, DockerHome, DockerSocket, DockerConfigHelper                string
	DockerProxy, DockerConfigScript, ContainerPreload                          string
	DockerDaemonJSON                                                           string
	FilterAccount, FilterSocket, FilterUnit, FilterBinary, GuardBinary         string
	FilterConfig, GuardConfig, FilterRuntimes                                  string
	GuardRunscBinaries, GuardRunscJSON                                         string
	GvisorRelease, GvisorArm64SHA512, GvisorAmd64SHA512                        string
}

// containerPreload loads the kernel modules rootless containers use, in
// either engine, before module loading is locked.
//
// On a first boot under Docker the daemon starts after the lock, so this is
// everything it loads as it starts as well: llc and stp under the bridge,
// conntrack, and the nf_tables expressions iptables-nft uses for the
// daemon's own rules, besides the xt_ matches.
const containerPreload = `for m in bridge llc stp br_netfilter veth overlay nf_conntrack nf_nat nf_conntrack_netlink tap tun xfrm_user nf_tables nft_ct nft_masq nft_nat nft_reject nft_reject_inet xt_MASQUERADE xt_addrtype xt_comment xt_conntrack xt_mark xt_multiport xt_nat xt_owner xt_tcpudp ipt_REJECT ip6t_REJECT iptable_nat ip6table_nat iptable_filter ip6table_filter nft_chain_nat nft_compat; do
  modprobe -q "$m" 2>/dev/null || true
done`

// splitHostProxy checks Params.HostProxy against the config and returns its
// address and port. Host mode needs it and guest mode must not have it, so
// neither can render a script that half applies host enforcement. It lands
// in root's script, hence the strict form: an IPv4 address and a port.
func splitHostProxy(p Params) (string, string, error) {
	host := p.Config != nil && p.Config.HostEnforced()
	switch {
	case host && p.HostProxy == "":
		return "", "", fmt.Errorf("network.enforce: host needs the host proxy's address")
	case !host && p.HostProxy != "":
		return "", "", fmt.Errorf("a host proxy address is only used with network.enforce: host")
	case !host:
		return "", "", nil
	}
	ip, port, err := net.SplitHostPort(p.HostProxy)
	if err != nil || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil || !strings.Contains(ip, ".") {
		return "", "", fmt.Errorf("host proxy %q must be an IPv4 address and port", p.HostProxy)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", fmt.Errorf("host proxy %q has no valid port", p.HostProxy)
	}
	return ip, port, nil
}

// RootHosts are the hosts root's provisioning fetches from: Ubuntu's
// archive (apt, the security pocket, ca-certificates), the toolchain
// manager's release archive, the hosts the manager itself needs, and
// gVisor's release bucket when a gVisor runtime is configured. Under
// network.enforce: host the proxy on the Mac allows them on top of the
// project's network.allow, because root's downloads go through it.
func RootHosts(c *project.Config) []string {
	// archive.ubuntu.com and security.ubuntu.com serve amd64, ports.ubuntu.com
	// arm64, as the image's ubuntu.sources names them.
	hosts := []string{"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"}
	switch c.Tools.Manager {
	case project.ManagerMise:
		// GitHub release downloads redirect to its asset hosts.
		hosts = append(hosts, "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
	case project.ManagerNix:
		hosts = append(hosts, "releases.nixos.org")
	}
	hosts = append(hosts, project.ManagerHosts[c.Tools.Manager]...)
	if c.Tools.Containers.Docker() && c.Tools.ContainerRuntime.Gvisor() {
		// gVisor's release archive.
		hosts = append(hosts, "storage.googleapis.com")
	}
	return hosts
}

// shellQuote wraps s in single quotes for use as one shell word, with any
// single quote inside it closed, escaped and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
