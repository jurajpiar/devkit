# Security model

devkit's adversary is code running inside the sandbox: a malicious dependency,
a hostile pull request, or a coding agent that goes off-script. The goal is that
such code cannot read or change anything on your Mac, cannot reach services on
it, and cannot talk to the internet beyond what you allowed, while you can see
everything it tried.

## Summary

| Risk | `allowlist` (default) | `open` | `none` |
|---|---|---|---|
| Read or write host files | Blocked | Blocked | Blocked |
| Reach services on the host (databases, agents, IDE) | Blocked | Blocked | Blocked |
| Reach the internet | Allowed hosts only, logged | Anything, logged | Blocked |
| Exfiltrate data over DNS (through the resolver) | Blocked (`dns: resolvers` reopens it) | Blocked (same) | Blocked |
| Tunnel to a non-web port of an allowed host | Blocked unless `host:port` is listed | Blocked unless listed | Blocked |
| Expose a listener to the Mac | Only ports in `forward` | Only ports in `forward` | Only ports in `forward` |
| Change its own network policy | Blocked | Blocked | Blocked |
| Escape the VM | Hypervisor boundary | Hypervisor boundary | Hypervisor boundary |

## The boundary

Each project runs in its own Lima virtual machine on Apple's
Virtualization.framework. That is the only security boundary devkit relies on.
There is no shared kernel between projects or with the host. Containers inside
the VM are available as a convenience, not as a protection layer.

## What is enforced, and how

**No host filesystem.** The instance config has `mounts: []`. Lima's default
home-directory mount is never created. `source: mount` is the explicit opt-in,
read-only unless `mount_writable: true`.

**Nothing comes back on its own.** devkit copies files into the VM (`source:
copy`, the proxy binary) and never out of it, with one exception you start
yourself: `devkit push` reads a git bundle of one branch, capped in size, into
a private temporary file, and git checks every object before storing it under
`refs/devkit/`, never in your branches or work tree. Nothing is pushed until
you confirm, and no git hooks run on the Mac. Toolchain lockfiles stay in the
VM. The end-to-end suite has a hostile
workspace rewrite every file devkit might be tempted to bring back and checks
that the project directory on the host is byte-for-byte unchanged.

**Guest output on your terminal.** The blocked-host summary that `devkit up`
prints is built from hostnames the sandbox chose, so it is stripped of
control characters first. Everything else devkit shows you is streamed raw:
dependency and toolchain installs, `devkit shell`, `devkit logs`. A hostile
install script can therefore write terminal control sequences at you, the
same as any build you run on your Mac. Your terminal emulator is the defence
there, not devkit.

**No access to the host.** The guest can normally reach the host at
`host.lima.internal`, which is also its gateway. The firewall rejects all
traffic to that address except the proxy's DNS to the configured resolvers,
unless `network.allow_host: true`, in which case the host is reachable
directly and is listed in `NO_PROXY`, so that traffic is not audited. In
`none` mode DNS is rejected too, unless `allow_host: true`, which keeps the
host reachable and, with it, any resolver running there.

**Nothing listens towards the Mac.** Lima would forward every port the guest
listens on to `127.0.0.1` on the host. devkit tells it to forward only the
ports in `network.forward`. The reason is not the listener itself but what
you might do with it: a page served by the sandbox, opened in your browser,
runs with the browser's network, which the firewall never sees. The same goes
for an IDE's remote session, whose local client acts on what the extension
host in the guest asks of it. Treat anything you open from the sandbox as a
bridge you chose to build.

**No network before the firewall.** The firewall is applied by root
provisioning, which Lima runs late in boot. Lima's own SSH sessions run as
the sandbox user well before that, and sshd and bash then read files that user
can write: `~/.ssh/rc`, `~/.bashrc`, `~/.profile`. Code planted there in one
session would otherwise get unfiltered network, your Mac included, early in
every later boot; the end-to-end suite planted exactly that and saw direct
HTTP 200s from it before the fix. A unit installed on the first boot now runs
on every later boot before sshd starts and rejects all new outbound traffic
from the sandbox user until the firewall replaces it, and the firewall itself
is rebuilt under a DROP policy so the moment between old and new rules is
closed. The hold decides by account and direction only, so loopback is held
too (the egress proxy and systemd-resolved listen there and would relay), and
in DNS=proxy and none modes systemd-resolved itself is held, which closes
lookups the sandbox asks of it over D-Bus. The first boot needs no hold:
nothing of the sandbox's exists on a fresh disk.

**A failed provisioning does not leave an open VM.** Provisioning removes its
stamp (`/etc/devkit/provision.id`) when it starts and writes it back only
after the firewall is applied. When `devkit up` finds a running VM without
it, whether or not `limactl start` reported an error, it stops the VM, names
the step that failed (the script reports it on the serial console) and exits
non-zero, before anything is copied in or installed. `devkit shell` and
`devkit sync` refuse such a VM. A VM someone starts by hand is held inside
the guest instead: before any download, the script sets `IPAddressDeny=any`
on the sandbox user's slice and on systemd-resolved, which systemd enforces
per cgroup for every socket, loopback and interface-bound ones included, and
it lifts that only once the firewall is in place. If provisioning fails, the
hold stays until the VM shuts down. It starts when the script starts, not at
boot, so on a VM that has never finished a first provisioning (and so has no
boot-hold unit yet) Lima's early SSH sessions have the network every first
boot has. The stamp is read over SSH as the sandbox user, whose shell startup
files could print a false answer; the in-guest hold does not rely on it.

**Connection state is trusted only for root and the proxy.** conntrack keys
a flow by addresses and ports, not by the account that owns it, and an entry
outlives its socket. A firewall that accepts "established" traffic before it
checks the owner lets a sandbox socket bound to a source port the proxy just
used for a lookup ride that live entry out; a sweep of every ephemeral port
got 70 DNS queries answered that way before this rule. So "established"
passes only for root and the proxy, and every other account may send only in
the reply direction of a connection made to the guest, its SSH sessions and
forwarded ports, plus what an explicit rule allows. The end-to-end suite
repeats the sweep while the proxy is resolving names and requires no answer. `devkit up`'s progress display follows the serial console from
the host for the same reason: polling over SSH would execute those files.

**Egress allowlist.** In `allowlist` and `open` modes an iptables `OUTPUT`
chain accepts loopback, established connections, and packets owned by the
proxy's service account, including that account's DNS to the resolvers in
`/run/systemd/resolve/resolv.conf`. Everything else is rejected, so port 53
cannot be used to reach arbitrary endpoints, and by default no other account
can query a resolver at all: the proxy resolves allowed hosts itself, against
the upstream resolvers rather than the local stub, so a query name cannot
carry data out of the sandbox. `network.dns: resolvers` reopens DNS to the
VM for tools that resolve before they use the proxy. The proxy is an
HTTP/CONNECT proxy; in `allowlist` mode it enforces `network.allow`, in
`open` mode it allows every host. An allowed host is reachable on ports 80
and 443 only, unless the entry names another port, so allowing GitHub is not
a tunnel to its SSH port or to anything else it listens on. It is the only
process that can open outbound TCP connections. Tools pick it up from
`HTTP_PROXY`/`HTTPS_PROXY`, set system-wide, and apt is configured separately.

**The guest is patched.** Root applies Ubuntu's security pocket on every
boot, before the firewall comes up, so the sandbox does not sit at the pinned
image's patch level while the image ages. That matters more than anything
else on this page once an attacker is inside: a local privilege escalation
turns the sandbox user into root, and root can drop the firewall and reach
your Mac's loopback services through Lima's gateway. A kernel update installed
this way runs from the next boot; `devkit up` does not reboot a VM whose
configuration has not changed, so `devkit down && devkit up` is what boots
into it. `vm.security_updates: false` turns the step off.

**One less surface for the privilege escalation.** Patching closes known
holes; it cannot close the one nobody has reported yet. So the guest also
takes away interfaces unprivileged code rarely needs and kernel exploits
often ride in on. A sysctl drop-in disables io_uring and restricts BPF, perf,
userfaultfd and ptrace. Unprivileged user namespaces are refused outright
with Ubuntu's `kernel.unprivileged_userns_clone = 0`, on top of AppArmor's
`kernel.apparmor_restrict_unprivileged_userns`. AppArmor alone is not enough:
it denies capabilities inside a new namespace, but Ubuntu ships profiles
exempting named programs (`rootlesskit`, `runc`, `slirp4netns`, `podman`,
`lxc` and others), so installing one through `tools.packages` would give
unprivileged code a namespace with a working `CAP_NET_ADMIN`; we tested this
with `rootlesskit`. The kernel switch refuses the namespace itself, exempted
program or not; root is unaffected. The exception is `tools.containers: true`:
Lima's rootless containerd needs user namespaces, so that configuration
leaves the switch open and relies on AppArmor's restriction alone, exemptions
included. The value follows `devkit.yaml` on every boot, so turning
containers off closes them again. On a kernel without the switch,
provisioning carries on with AppArmor's restriction only and says so.

**Docker's API is filtered.** With `tools.containers: docker` the daemon runs
rootless under its own account, and its socket is reachable only by
devkit's API filter, which runs under another account, not root. The
sandbox user's `DOCKER_HOST` is the filter's socket. The filter forwards a
call only if it is in its table and its body decodes strictly (exact field
names, no duplicates, no unknown fields) and validates; it forwards its own
re-encoding of the body, never the client's bytes, so the daemon reads what
was checked. It refuses privileged containers, added capabilities beyond
Docker's defaults and two harmless ones, the VM's namespaces, devices,
sysctls, security-option changes, runtimes other than the configured one,
published ports beyond loopback, and bind mounts from outside the
workspace; it drops `NET_RAW` from every container. Because the daemon
resolves bind paths after the check, a runtime guard in front of `runc`
reads the mounts each container actually got before its process starts and
deletes it unless they come from the workspace, Docker's volumes or its
per-container files. Under gVisor the guard is not used and the filter's
check of bind paths stands alone. BuildKit's session stream is not parsed.
The Docker account is the boundary for containers: container root is that
account.

**No kernel modules after provisioning.** Any process can make the kernel
load a module, for a socket family nobody uses or, from a namespace, a link
type or a netfilter extension: kernel code that would otherwise never run.
The last step of provisioning, after the firewall is applied and the
provisioning hold lifted, sets `kernel.modules_disabled = 1`, which refuses
every later load, to root as well, until the VM restarts; each boot
provisions and locks again. With `containers: true`, the modules containers
use (bridge, veth, overlay, NAT and the netfilter matches) are loaded first.
The cost is that something which needs a module nothing loaded beforehand
fails, usually with "operation not supported" or "Operation not permitted"
(a macvlan network, an iptables match devkit does not use). A restart does
not help on its own, since every boot locks again; `vm.lock_modules: false`
and `devkit up`, which restarts the VM, leave loading open, and `devkit up`
notes it.

Separately, the kernel crypto socket family `AF_ALG` is
blocked from loading and unloaded if present. That family exposes kernel
crypto internals to any process and has produced a string of memory-safety
bugs, Copy-Fail (CVE-2026-31431) the latest; a dev workload does its crypto
in userspace libraries and never misses it. This does not stop a kernel
out-of-bounds write in code that is still reachable: nothing short of not
running that code does, and that is the next point. It removes one whole
class of reachable bug in advance.

**What it would take to go further, and why it is not the default.** The
remaining gap is that any reachable kernel bug, in a subsystem we did not
foresee, still escalates. Closing it means not trusting the guest kernel at
all: running the project's processes inside a userspace kernel such as gVisor
*within* the VM, so an exploit meets gVisor's syscall emulation before it ever
reaches the real kernel. That is real defence in depth but it is not free,
a measurable cost on syscall-, file- and network-heavy work, and an IDE's
remote session would have to run inside that inner sandbox rather than in the
VM. It is a roadmap item, an opt-in mode, not something to impose on every
project. The VM boundary already keeps a guest-root attacker off your files;
this would additionally keep a kernel exploit off the host's loopback.
Software that ignores proxy settings is simply blocked by the firewall.

**Config values cannot inject into the policy.** `network.allow`, `repo`,
`branch`, `tools.versions` and `tools.packages` are validated against strict
grammars, and the policy files are written through quoted heredocs, so a
hostile `devkit.yaml` cannot run commands as root in the VM. `install:` is
deliberately free-form: it runs as the sandbox user, which is the thing being
sandboxed.

**TLS trust is the distro's, kept current, and auditable.** Non-browser TLS
clients check no revocation: a mis-issued certificate from a compromised CA
stays valid for them until their trust bundle is updated. devkit keeps the
VM's bundle current by refreshing `ca-certificates` on every boot, and makes
that bundle authoritative for runtimes that would otherwise carry their own
stale copy (Node via `--use-openssl-ca`, Python and pip via `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `PIP_CERT`, curl via `CURL_CA_BUNDLE`).
`network.distrust` removes named roots on top of that, for cases where the
distro lags the browsers, such as a cross-signing root they have stopped
trusting. There is no CA list inside devkit to go stale: `devkit audit`
compares what the system, Node, Java, certifi bundles and certificate files
in the project trust against Mozilla's current root store, fetched through
the proxy, and names anything trusted that should not be, with the
`distrust` entry to add. `devkit up` runs it shallowly every time. What it
cannot fix is a compiled program that embeds its own bundle and ignores the
environment, though it can find one by fingerprint; and the proxy cannot
inspect certificates, because TLS 1.3 encrypts them.

**Container images the project does not pin are reported, not blocked.**
devkit pins by hash everything it downloads itself; a project's images are
the project's choice, and a tag is mutable. The audit reads the project's
compose files and Dockerfiles (it needs no Docker: an image list cannot say
how an image was requested, since a pulled image carries both tag and digest
either way) and counts each reference as pinned (`@sha256:` and 64 hex
characters), unpinned, or unresolved. Variables are resolved from the
compose file's `.env` and from defaults in the reference, and a Dockerfile's
from the `ARG` defaults before its first `FROM`; anything else, including a
build argument passed on the command line, is unresolved, which is reported
rather than assumed fine. Without PyYAML in the VM the compose reading falls
back to line matching and says it is approximate. File names and references
are stripped of control characters before they reach the terminal, and a
file over 256 KB, binary or not a regular file is named as not read. Unpinned
and unresolved images do not change the audit's exit status: they are
common, and the audit's verdict stays about trust.

**Toolchains are installed by the sandbox user.** Root installs only the
manager (mise or Nix) from a release archive pinned by SHA-256 in devkit's
source, with the pin taken after verifying the upstream signature. The
toolchains come in afterwards as the sandbox user, through the proxy and into
the audit log. mise runs with plugin backends disabled, provenance checks on
every install, a three-day minimum release age, and a lockfile written in the
VM on the first run and enforced with `--locked` afterwards. The sandbox user
owns that lockfile, so it guards against upstream changing an archive, not
against the sandbox itself, which can already run anything. Nix checks every
substitute against the cache's signing key and pins inputs in `flake.lock`.

**Air gap.** `network.mode: none` rejects all outbound traffic including DNS.
Incoming SSH still works because its return packets are an established
connection. Combined with `allow_host: true` the gap has one opening: the
host, and therefore DNS through the host's resolver. Pair them only when
that is what you want.

**The sandbox cannot loosen the policy.** The user account inside the VM can
run exactly three commands as root, all read-only checks Lima's host agent
needs to confirm the machine booted. Policy lives in a root-only provisioning script that Lima regenerates from
`devkit.yaml` on every boot. To change the policy you edit the file on the host
and run `devkit up`, which restarts the VM. Setting `sudo: true` removes this
guarantee; it is there for convenience and says so in the config.

**Trusted proxy binary.** The host drops the proxy into a staging directory
owned by the sandbox user. A root systemd unit copies it to a root-only
location, hashes that copy, and installs it only if the SHA-256 matches the
hash baked into the provisioning script. The staged file is never read twice,
so the sandbox cannot swap it between the check and the install.

**Audit log.** The proxy logs every request as `ALLOWED` or `BLOCKED` with the
target host to `/var/log/devkit/egress.log`. `devkit logs` reads it, and
`devkit up` prints a summary of blocked hosts after installing dependencies.

**Localhost-only exposure.** Lima forwards ports the guest listens on to
`127.0.0.1` on the host. Nothing is reachable from your network.

## Enforcement on the Mac (`network.enforce: host`)

With `network.enforce: host` the network policy no longer rests on the guest
alone. Lima's host agent, the Mac process that carries all of the VM's
traffic, is started under a macOS sandbox profile through `sandbox-exec`. It
may open outbound connections only to unix sockets under Lima's home and,
over TCP (`remote tcp`, not `remote ip`, which would admit UDP too), to the
VM's SSH forward on the Mac's loopback and devkit's host proxy on the Mac's
loopback. Unix sockets are not allowed wholesale: when they were, Lima's
built-in DNS resolved names through the Mac's resolver socket, which is a
channel out. No root is needed on the Mac.

The host proxy is `devkit hostproxy`, one per VM, started by `devkit up`
before the VM and stopped by `devkit down` and `devkit rm`. `devkit up`
reuses a running one only if it has the same allowlist and was started by the
same devkit binary, compared by the SHA-256 of its executable, so that an
upgrade or rebuild of devkit replaces it; otherwise it restarts it on the same
port. It applies the same allowlist and web-ports policy as the in-guest
proxy, to the project's
`network.allow` plus the hosts root's provisioning fetches from (Ubuntu's
archive, ports and security hosts, and the toolchain manager's download
hosts); in `open` mode it allows any host on the web ports. It refuses to
dial any address of the Mac: loopback, link-local, and every address
assigned to one of the Mac's interfaces at that moment (its LAN address, the
VM network's gateway), IPv4 and IPv6. It checks after resolution, and refuses
a name when any address it resolves to is one of these, so neither an IP
literal in `open` mode nor an allowed name can be pointed at the Mac's own
services. Other machines on the Mac's LAN are not refused by this; the
allowlist decides about them as about any host. It hands redirects back to
the in-guest proxy to decide. Its log, in `~/.devkit/<vm>/hostproxy.log`, is the
authoritative record of what left, and `devkit logs` shows it. In the guest,
root's apt and downloads and the in-guest proxy use it as their upstream, the
proxy's account may reach only it, and no account may send a DNS query.

With root in the guest, the firewall flushed and the in-guest proxy stopped,
`TestHostEnforcement` runs a raw-socket probe and requires every route it
tries to fail except the host proxy: TCP to internet hosts on several ports,
IPv6, DNS over UDP and TCP to public resolvers and to Lima's own, NTP, a
listener on the Mac's loopback, UDP to a listener at the host proxy's port
number, a sweep of the Mac's ports, other addresses
on Lima's network. The profile's rules themselves are also checked without a
VM by the `internal/hostenforce` tests.

What it does not cover:

- **Hosts the host proxy allows** stay reachable for root in the guest, on
  the web ports: the project's allowlist and the provisioning hosts above.
- **A VM started outside devkit** (`limactl start` by hand) runs without the
  profile. devkit records the host agent's pid at each start it makes and
  warns when the running one differs; it cannot prevent it.
- **The vsock channel** between Lima's guest agent and host agent was not
  attacked.
- **`sandbox-exec` is deprecated.** If macOS stops shipping it, devkit
  refuses to start a host-enforced VM rather than start it unprotected.
- **Outbound firewalls on the Mac**, such as LuLu, see the host proxy as a
  new program and must be told to allow it.
- `allow_host: true`, `dns: resolvers` and `mode: none` are refused with
  host enforcement.

## Kernel crash reports, read on the Mac

**What is detected.** Kernel crash reports from the guest: panics, Oopses,
`BUG:` and `kernel BUG at`, KASAN and UBSAN reports, watchdog lockups,
stack-protector failures and list corruption. Failed exploit attempts often
crash the kernel before one succeeds, so these are worth seeing.

**From where.** The system script adds `console=hvc0` to the kernel command
line through a grub drop-in. hvc0 is the serial console Lima records on the
Mac in `~/.lima/<vm>/serialv.log`; on this hypervisor the kernel's default
console, ttyAMA0, does not exist, so before this nothing the kernel printed
reached the Mac. Messages at levels 0 to 3 (emergency to error) arrive,
which includes every crash report. devkit scans the log on the Mac; nothing
runs in the guest to do it. The sandbox user cannot write to `/dev/hvc0`,
`/dev/console` or `/dev/kmsg`, and when a process named like a crash report ("BUG:
unable to") crashes, the kernel logs nothing for it (both tested). The
scanner matches a signature only at the start of a kernel message, directly
after its timestamp, so names and other text the sandbox chooses, which
appear later in kernel lines, cannot forge a report; devkit's own progress
lines and systemd's status lines are not kernel lines and never match.
Everything shown is stripped of control characters and escape sequences.

**From when.** The drop-in takes effect from the boot after the one that
wrote it: a new VM reports crashes only after its first restart (`devkit
down`, then `devkit up`), and devkit says so instead of reporting "none". If
`update-grub` is missing or fails, provisioning warns and goes on: this is
detection, not enforcement.

**The limit.** This catches the noisy attempt, not the clean one. An exploit
that works the first time crashes nothing, and once it has root it can lower
the console level or rewrite the command line, after which only what it lets
through gets out. A guest that hangs without printing a
report is not seen either. A report is a reason to act; the absence of one
proves nothing.

**What to do on a report.** Every command that uses the VM warns until you
act, and `devkit audit` exits 1, even with the VM stopped. A crash can be a
failed attempt to break out or simply a kernel bug. If you cannot explain
it, discard the VM with `devkit rm`: a VM where an exploit has been attempted is not worth
repairing. Otherwise acknowledge it with `devkit audit --ack-crashes`. A
kernel that has panicked does not answer while Lima still lists the VM as
Running; devkit names it, and `devkit down` forces it off.

Reports are kept in `~/.devkit/<vm>/kernel-crashes.json` across restarts,
since Lima starts a new serial log at every VM start; `devkit up` and
`devkit down` read the log before that happens. A VM started with
`limactl` directly, rather than devkit, can lose a crash from before that
start.

## What the escape tests cover

`tests/e2e/escape_test.go` runs inside a real VM and tries, as the sandbox
user, to: reach the host by name, gateway IP, every port form, UDP and IPv6,
directly and through the proxy; flush the firewall, open raw sockets, bind
port 22, switch to the proxy's user, kill the proxy, or use a user namespace
to get around the OUTPUT chain; read secrets from Lima's cidata, find a host
mount, or dial the host over vsock; write to any policy file; and get a file
back onto the host by rewriting the workspace before `devkit up`. Hypervisor
escapes are not tested, because no test of ours would find one.

`examples/hostile-project` is the same idea by hand: a project whose code and
install step try the same escapes and report, line by line, whether each was
stopped. Run it in any mode to watch the boundary hold, and loosen
`devkit.yaml` to watch it give way where you told it to.

## Accepted risks

- **DNS exfiltration with `dns: resolvers`.** With the default `dns: proxy`
  the sandbox cannot send a query. If you switch to `resolvers`, DNS to the
  configured resolvers is open to every account, and a determined attacker
  can tunnel data through query names to a domain they control.
- **Root in the guest.** The firewall and the uid separation are what keep
  the host's loopback and the open internet out of reach. A privilege
  escalation in the guest removes both; the VM boundary still protects your
  files. `network.enforce: host` (opt-in, see "Enforcement on the Mac"
  above) moves the line for the network: the Mac then refuses everything but
  devkit's host proxy, whatever root in the guest does. The mitigations are the security-pocket updates at boot, the kernel
  surface we take away (unprivileged user namespaces unless
  `containers: true`, module loading after provisioning, io_uring, BPF,
  perf, and the `AF_ALG` crypto family), and, for those who want it, an inner gVisor
  sandbox on the roadmap. See "The guest is patched" and the two points
  after it. A kernel bug in a subsystem none of that covers still escalates;
  that is the residual risk and the reason the boundary we rely on is the
  hypervisor, not the guest kernel.
- **Allowed hosts are trusted.** If you allow `**.github.com`, code can push to
  any GitHub repository it has credentials for. Keep the list tight and read
  the log.
- **Credentials you bring in.** Nothing is copied into the VM except your
  project directory (minus `exclude`), a one-commit `.git` built from it (no
  history, hooks, config or credentials) and your SSH public key. If you paste a
  token into the sandbox, assume the sandbox has it.
- **Commits you push from the VM.** `devkit push` is the one way VM-written
  content leaves with your credentials, and your review is its only gate.
  The VM commits under your git identity and can forge any author. Pushed
  commits run in CI, and if you merge `refs/devkit/...` into your Mac's
  checkout, its hooks, direnv and scripts run code the VM wrote. Push to a
  feature branch behind branch protection, and read the files the review
  flags. The bundle itself is checked by `git index-pack --strict` with no
  hooks; a bug in git's pack parsing is the residual risk there. See "What
  git in the VM changes" in the README.
- **Hypervisor bugs.** A VM escape in Virtualization.framework would defeat
  everything here. There is no mitigation beyond keeping macOS updated.
- **Resource use.** The VM is sized by `vm:`. Code inside can exhaust its own
  CPU, memory and disk but not the host's beyond those limits.
- **Supply chain before the sandbox.** devkit itself and Lima are installed
  by you; verify them. The Ubuntu image, mise and Nix are pinned by digest,
  and apt verifies Ubuntu packages. See "What gets downloaded" in the README.
  Between boot and the end of provisioning the firewall is not yet applied,
  and root uses that window to fetch and hash-check the manager's archive.
  The sandbox user gets no network in it: see "No network before the
  firewall" above.
- **Toolchain verification is uneven.** mise verifies Node against upstream's
  signed checksums, Go against a same-origin checksum, Python and Ruby builds
  against GitHub attestations, and `rustup-init` not at all. The lockfile
  turns each of those into a pin after the first run, so the exposure is the
  first `devkit up` and every `--relock`. Nix verifies everything against the
  cache key but trusts the hashes you commit in `flake.lock`.
- **Lima user key.** Lima's SSH key in `~/.lima/_config/user` grants access to
  every Lima VM on the machine. That is Lima's design, not devkit's.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a public
issue.
