#!/usr/bin/env bash
# devkit boundary probe.
#
# Written the way hostile project code would be: it runs as the sandbox user
# and tries, one attempt at a time, to reach your Mac, the open internet, your
# files and the sandbox's own policy. It is a reporter, not an exploit: every
# check prints what it tried and what happened. Nothing here is a payload, and
# nothing leaves data anywhere.
#
# Outcomes are judged against the policy in devkit.yaml, which root writes to
# /etc/devkit/network.conf at boot:
#   [held]    the sandbox stopped the attempt
#   [note]    the attempt worked and the policy allows it (open, allow_host, DNS)
#   [LEAKED]  the attempt worked and the policy says it must not: enforcement failed
#
# Run it inside a devkit VM:  devkit shell ./probe.sh
# or let the install step run it:  devkit up
set -u

held=0 leaked=0
held()   { printf '  \033[32m[held]\033[0m    %s\n' "$1"; held=$((held+1)); }
leaked() { printf '  \033[31m[LEAKED]\033[0m  %s\n' "$1"; leaked=$((leaked+1)); }
note()   { printf '  \033[33m[note]\033[0m    %s\n' "$1"; }
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

# The policy, as root applied it. Readable, not writable.
MODE=allowlist ALLOW_HOST=0
if [ -r /etc/devkit/network.conf ]; then . /etc/devkit/network.conf; fi
printf 'Policy: network.mode=%s allow_host=%s\n' "$MODE" "$ALLOW_HOST"

# tcp HOST PORT: true if a TCP connection opens within 4 seconds.
tcp() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# udp_rejected HOST: true if the firewall refuses the packet at send time.
# That is iptables REJECT's signature (EPERM). A closed port on a reachable
# host looks different: the send succeeds and a refusal comes back later.
udp_rejected() {
  python3 - "$1" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", (sys.argv[1], 2222))
except PermissionError:
    sys.exit(0)
sys.exit(1)
PY
}

HOST_IP="$(getent hosts host.lima.internal 2>/dev/null | awk '{print $1; exit}')"
GW="$(ip route 2>/dev/null | awk '/default/{print $3; exit}')"

section "Reaching your Mac"
seen=""
for addr in host.lima.internal "${HOST_IP:-}" "${GW:-}"; do
  [ -n "$addr" ] || continue
  case " $seen " in *" $addr "*) continue ;; esac
  seen="$seen $addr"
  if udp_rejected "$addr"; then
    held "firewall rejects packets to $addr"
    fw=1
  elif [ "$ALLOW_HOST" = 1 ]; then
    note "packets to $addr leave the VM (allow_host: true)"
    fw=0
  else
    leaked "packets to $addr leave the VM although allow_host is false"
    fw=0
  fi
  for port in 22 2222 5432 3000; do
    if tcp "$addr" "$port"; then
      if [ "$ALLOW_HOST" = 1 ]; then note "opened TCP to $addr:$port (allow_host: true)"
      else leaked "opened TCP to $addr:$port"; fi
    elif [ "$fw" = 0 ]; then
      note "$addr:$port closed (host reachable, nothing listening there)"
    fi
  done
done
# Through the proxy. In allowlist mode it refuses the host by policy before
# connecting (403). In open mode it tries, and the firewall rejects even the
# proxy's own connection to the host, which the proxy reports as 502.
code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://host.lima.internal:2222/ 2>/dev/null)"
case "$code" in
  403) held "proxy refuses to connect to your Mac (403)" ;;
  502) if [ "$ALLOW_HOST" = 1 ]; then note "proxy could not connect to :2222 on your Mac (nothing listening)"
       else held "proxy tried your Mac and the firewall rejected it (502)"; fi ;;
  000) if [ "$MODE" = none ]; then held "proxy is off (none mode)"
       elif [ "$ALLOW_HOST" = 1 ]; then note "host bypasses the proxy (allow_host: true); nothing listening on :2222"
       else held "no response from the proxy for your Mac"; fi ;;
  *)   if [ "$ALLOW_HOST" = 1 ]; then note "reached your Mac on :2222, HTTP $code (allow_host: true)"
       else leaked "reached your Mac through the proxy, HTTP $code"; fi ;;
esac

section "Reaching the open internet"
# Plain HTTP so the proxy's verdict is visible as a status code; over HTTPS a
# denied CONNECT shows up as 000.
code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://example.com/ 2>/dev/null)"
case "$code" in
  403) held "example.com denied by the proxy (403); not on the allowlist" ;;
  000) held "example.com unreachable (no proxy, no route)" ;;
  *)   if [ "$MODE" = open ]; then note "example.com fetched, HTTP $code (open mode, logged ALLOWED)"
       else leaked "example.com fetched, HTTP $code, in $MODE mode"; fi ;;
esac
if curl -s -m 8 --noproxy '*' -o /dev/null http://1.1.1.1/ 2>/dev/null; then
  leaked "reached 1.1.1.1 directly, bypassing the proxy"
else
  held "direct connection bypassing the proxy refused"
fi
if [ "$(curl -s -m 8 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ 2>/dev/null)" = 200 ]; then
  note "registry.npmjs.org reachable (on the allowlist, logged ALLOWED)"
fi

section "Exfiltrating over DNS"
# DNS to the configured resolvers is allowed unless the mode is none, so the
# proxy can resolve names. A determined program can tunnel data through query
# names. Documented in SECURITY.md as an accepted risk; none mode closes it.
if getent hosts example.com >/dev/null 2>&1; then
  if [ "$MODE" = none ]; then leaked "DNS resolves in none mode"
  else note "DNS resolves external names (tunnelling is possible; network.mode none stops it)"; fi
else
  held "DNS does not resolve"
fi

section "Reading your files and the VM's secrets"
# The host filesystem is never mounted, so these exist only on your Mac.
for p in /Users "$HOME/.aws/credentials" "$HOME/.config/gcloud"; do
  if ls -d "$p" >/dev/null 2>&1; then leaked "reached $p"; else held "$p not present in the VM"; fi
done
if findmnt -t virtiofs -n 2>/dev/null | grep -q .; then
  note "a host directory is mounted (source: mount): $(findmnt -t virtiofs -n -o TARGET | head -n1)"
else
  held "no host directory mounted"
fi
# The guest user has its own ~/.ssh with an authorized_keys holding your
# public key, which is how SSH in works. What must never appear is a private
# key from your Mac. Match a real PEM header, and look only where a copied-in
# secret would land, not in toolchains or this script.
if grep -rslE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
     "$HOME/.ssh" "$HOME/.aws" "$HOME/.gnupg" "$HOME/.config/gcloud" \
     /mnt/lima-cidata 2>/dev/null | grep -q .; then
  leaked "found a private key from the host in the VM"
else
  held "no host private key reachable in the VM"
fi

section "Changing the sandbox's own policy"
if sudo -n true 2>/dev/null; then
  leaked "got root via sudo (sudo: true in devkit.yaml?)"
else
  held "sudo refused"
fi
if iptables -F 2>/dev/null; then leaked "flushed the firewall"; else held "cannot touch the firewall (no CAP_NET_ADMIN)"; fi
for f in /usr/local/sbin/devkit-firewall /etc/devkit/network.conf /usr/local/bin/devkit-egressproxy; do
  if [ -w "$f" ]; then leaked "$f is writable"; else held "$(basename "$f") is root-only"; fi
done
pid="$(systemctl show -p MainPID --value devkit-egress 2>/dev/null)"
if [ -z "${pid:-}" ] || [ "$pid" = 0 ]; then
  if [ "$MODE" = none ]; then note "proxy not running (none mode)"; else leaked "proxy is not running in $MODE mode"; fi
elif kill "$pid" 2>/dev/null; then
  leaked "signalled the egress proxy (pid $pid)"
else
  held "cannot signal the egress proxy"
fi

section "Tampering with the toolchain pins"
for lock in "$HOME/.config/mise/mise.lock" "$HOME/workspace/flake.lock"; do
  [ -e "$lock" ] || continue
  # Writable by the sandbox user, as expected: the pin guards against upstream
  # changing an archive, not against the sandbox, which can already run code.
  # Rewriting it only breaks this VM; it never reaches your Mac.
  note "$(basename "$lock") is in the VM and never copied back to your Mac"
done

printf '\n\033[1mSummary\033[0m  held %d, leaked %d\n' "$held" "$leaked"
if [ "$leaked" -gt 0 ]; then
  printf '  \033[31m%s\033[0m\n' "Enforcement failed somewhere: the policy says no and the attempt worked."
  exit 1
fi
printf '  \033[32m%s\033[0m\n' "Every attempt the policy forbids was stopped. Now read devkit logs to see them."
