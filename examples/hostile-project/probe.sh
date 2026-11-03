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
MODE=allowlist ALLOW_HOST=0 DNS=proxy SOURCE=copy MOUNT_POINT=
if [ -r /etc/devkit/network.conf ]; then . /etc/devkit/network.conf; fi
# source.conf is read as data, not sourced: MOUNT_POINT is a host path and
# may contain spaces or shell metacharacters.
if [ -r /etc/devkit/source.conf ]; then
  SOURCE="$(sed -n 's/^SOURCE=//p' /etc/devkit/source.conf)"
  MOUNT_POINT="$(sed -n 's/^MOUNT_POINT=//p' /etc/devkit/source.conf)"
fi
printf 'Policy: network.mode=%s allow_host=%s source=%s%s\n' "$MODE" "$ALLOW_HOST" "$SOURCE" "${MOUNT_POINT:+ at $MOUNT_POINT}"

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
# Through the proxy, as a CONNECT tunnel: the answer to CONNECT is decided
# before any bytes flow, so it is unambiguous. 403 is the allowlist refusing
# the host by policy; 502 means the proxy dialled and the firewall rejected
# it; 200 means a TCP tunnel to your Mac is open. (A plain-HTTP request would
# be ambiguous: the proxy also answers 502 after connecting to a non-HTTP
# listener such as sshd and failing to parse its reply.)
# --noproxy '' because with allow_host the host is in NO_PROXY, which curl
# honours even with -x; the check must measure the proxy, not a bypass.
code="$(curl -s -m 8 -p -x http://127.0.0.1:3128 --noproxy '' -o /dev/null -w '%{http_connect}' https://host.lima.internal:2222/ 2>/dev/null)"
case "$code" in
  403) held "proxy refuses a tunnel to your Mac (403)" ;;
  502) if [ "$ALLOW_HOST" = 1 ]; then note "proxy dialled your Mac :2222 and nothing answered (allow_host: true; a closed port, not the firewall)"
       else held "proxy tried to dial your Mac and the firewall rejected it (502)"; fi ;;
  200) if [ "$ALLOW_HOST" = 1 ]; then note "proxy opened a tunnel to your Mac :2222 (allow_host: true)"
       else leaked "proxy opened a TCP tunnel to your Mac :2222"; fi ;;
  000) if [ "$MODE" = none ]; then held "proxy is off (none mode)"
       else held "no response from the proxy for your Mac"; fi ;;
  *)   leaked "unexpected CONNECT answer $code for your Mac" ;;
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
# By default only the proxy may resolve names (network.dns: proxy), so a
# query name cannot carry data out. With dns: resolvers the whole VM may
# query its resolvers, and a program can tunnel data through query names.
if getent hosts example.com >/dev/null 2>&1; then
  if [ "${DNS:-proxy}" = resolvers ] && [ "$MODE" != none ]; then note "DNS resolves external names (dns: resolvers; tunnelling is possible)"
  else leaked "DNS resolves although network.dns is $DNS in $MODE mode"; fi
else
  held "DNS does not resolve for the sandbox user (only the proxy resolves)"
fi
# A tunnel to a non-web port of an allowed host is not a web request.
code="$(curl -s -m 8 -p -x http://127.0.0.1:3128 --noproxy '' -o /dev/null -w '%{http_connect}' https://github.com:22/ 2>/dev/null)"
case "$code" in
  403) held "proxy refuses a tunnel to github.com:22 (403); allowed hosts are web ports only" ;;
  200) leaked "proxy opened a tunnel to github.com:22" ;;
  000) if [ "$MODE" = none ]; then held "proxy is off (none mode)"; else held "no tunnel to github.com:22"; fi ;;
  *)   held "tunnel to github.com:22 not established ($code)" ;;
esac

section "Reading your files and the VM's secrets"
# The host filesystem is never mounted unless devkit.yaml says source: mount,
# and then exactly one directory, at the path root recorded in source.conf.
for p in /Users "$HOME/.aws/credentials" "$HOME/.config/gcloud"; do
  if ls -d "$p" >/dev/null 2>&1; then
    case "$SOURCE:$MOUNT_POINT" in
      mount:"$p"/*|mount:"$p") note "$p exists as the parent of the project mount (source: mount)" ;;
      *) leaked "reached $p" ;;
    esac
  else held "$p not present in the VM"; fi
done
# One target per line; findmnt escapes whitespace as \x20, so decode it
# before comparing with the configured path.
mounts=0
while IFS= read -r raw; do
  [ -n "$raw" ] || continue
  mounts=$((mounts+1))
  m="$(printf '%b' "$raw")"
  if [ "$SOURCE" = mount ] && [ "$m" = "$MOUNT_POINT" ]; then note "project directory mounted at $m (source: mount, as configured)"
  else leaked "host directory mounted at $m, which devkit.yaml does not ask for"; fi
done < <(findmnt -t virtiofs -n -o TARGET 2>/dev/null)
if [ "$mounts" = 0 ]; then
  if [ "$SOURCE" = mount ]; then leaked "source: mount is configured but nothing is mounted at $MOUNT_POINT"
  else held "no host directory mounted"; fi
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
