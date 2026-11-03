#!/usr/bin/env bash
# devkit boundary probe.
#
# This is deliberately written the way hostile project code would be: it runs
# as the sandbox user and tries, one attempt at a time, to reach your Mac, the
# open internet, your files and the sandbox's own policy. It is a reporter, not
# an exploit: every check prints what it tried and whether the sandbox stopped
# it. Nothing here is a working payload, and nothing leaves data anywhere.
#
# Run it inside a devkit VM:  devkit shell ./probe.sh
# or let the install step run it:  devkit up
#
# What you should see depends on network.mode. See README.md for the table.
set -u

pass=0 held=0 leaked=0

# held: the sandbox stopped the attempt (the good outcome for an attack).
# leaked: the attempt succeeded (a boundary did not hold).
# note: an outcome that is expected and allowed, so neither good nor bad.
held()   { printf '  \033[32m[held]\033[0m    %s\n' "$1"; held=$((held+1)); }
leaked() { printf '  \033[31m[LEAKED]\033[0m  %s\n' "$1"; leaked=$((leaked+1)); }
note()   { printf '  \033[33m[note]\033[0m    %s\n' "$1"; }
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

# tcp HOST PORT: true if a TCP connection opens within 4 seconds.
tcp() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

HOST_IP="$(getent hosts host.lima.internal 2>/dev/null | awk '{print $1; exit}')"
GW="$(ip route 2>/dev/null | awk '/default/{print $3; exit}')"

section "Reaching your Mac"
for addr in "host.lima.internal" "${HOST_IP:-}" "${GW:-}"; do
  [ -n "$addr" ] || continue
  for port in 22 2222 5432 3000; do
    if tcp "$addr" "$port"; then
      leaked "opened TCP to the host at $addr:$port"
    else
      held "host $addr:$port refused"
    fi
  done
done

section "Reaching the open internet"
# A host that is not on a Node project's default allowlist.
code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' https://example.com/ 2>/dev/null)"
case "$code" in
  200) leaked "fetched https://example.com (not on the allowlist)" ;;
  403) held "example.com denied by the proxy (403)" ;;
  *)   held "example.com not reachable (curl said '${code:-error}')" ;;
esac
# Skipping the proxy entirely.
if curl -s -m 8 --noproxy '*' -o /dev/null https://1.1.1.1/ 2>/dev/null; then
  leaked "reached 1.1.1.1 directly, bypassing the proxy"
else
  held "direct connection bypassing the proxy refused"
fi
# An allowed host, to show the boundary is a boundary and not a wall.
if [ "$(curl -s -m 8 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ 2>/dev/null)" = "200" ]; then
  note "registry.npmjs.org reachable (on the allowlist, logged ALLOWED)"
fi

section "Exfiltrating over DNS"
# DNS to the configured resolver is allowed in allowlist/open mode so the proxy
# can resolve names. That means a determined program can tunnel data through
# query names. This is a documented, accepted risk; none mode closes it.
if getent hosts example.com >/dev/null 2>&1; then
  note "DNS resolves external names (tunnelling is possible; network.mode none stops it)"
else
  held "DNS does not resolve (air-gapped)"
fi

section "Reading your files and the VM's secrets"
# The host home is never mounted, so these paths exist only on your Mac.
for p in /Users "$HOME/.aws/credentials" "$HOME/.config/gcloud"; do
  if ls -d "$p" >/dev/null 2>&1; then
    leaked "reached $p"
  else
    held "$p not present in the VM"
  fi
done
# The guest user has its own ~/.ssh holding an authorized_keys with your public
# key, which is how SSH in works and is expected. What must never appear is a
# private key from your Mac. Match a real PEM header, and look only where a
# copied-in secret would land, not in toolchains or this script.
if grep -rslE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
     "$HOME/.ssh" "$HOME/.aws" "$HOME/.gnupg" "$HOME/.config/gcloud" \
     /mnt/lima-cidata 2>/dev/null | grep -q .; then
  leaked "found a private key from the host in the VM"
else
  held "no host private key reachable in the VM"
fi

section "Changing the sandbox's own policy"
if sudo -n true 2>/dev/null; then
  leaked "got root via sudo"
else
  held "sudo refused"
fi
if iptables -F 2>/dev/null; then
  leaked "flushed the firewall"
else
  held "cannot touch the firewall (no CAP_NET_ADMIN)"
fi
for f in /usr/local/sbin/devkit-firewall /etc/devkit/network.conf /usr/local/bin/devkit-egressproxy; do
  if [ -w "$f" ]; then
    leaked "$f is writable"
  else
    held "$(basename "$f") is root-only"
  fi
done
# The proxy must keep running: stopping it would be denial of service.
pid="$(systemctl show -p MainPID --value devkit-egress 2>/dev/null)"
if [ -n "${pid:-}" ] && [ "$pid" != 0 ] && kill "$pid" 2>/dev/null; then
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
  note "$(basename "$lock") is in the VM and not copied back to your Mac"
done

printf '\n\033[1mSummary\033[0m\n'
printf '  held %d, leaked %d\n' "$held" "$leaked"
if [ "$leaked" -gt 0 ]; then
  printf '  \033[31m%s\033[0m\n' "A boundary did not hold. Check devkit.yaml and the mode you are in."
  exit 1
fi
printf '  \033[32mEvery escape attempt was stopped.\033[0m Now read devkit logs to see them.\n'
