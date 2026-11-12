# Security model

devkit is designed to contain untrusted project code: malicious dependencies,
hostile pull requests and coding agents that run unsafe commands. Its default
policy blocks access to your Mac's files and services, and limits outbound
traffic to allowed hosts. The proxy logs requests made through it.

**Host** means your Mac. **Guest** means the project's Ubuntu VM. The **sandbox
user** is the account that runs project code inside that VM.

Start with the [summary](#summary) and [accepted risks](#accepted-risks). The
sections below explain [guest controls](#what-is-enforced-and-how), [host
enforcement](#enforcement-on-the-mac-networkenforce-host), [Git
review](#git-review-and-credentials) and [crash
reports](#kernel-crash-reports-read-on-the-mac).

## Summary

This table assumes the default guest protections: no host mounts, no general
sudo access, `allow_host: false` and `dns: proxy`. It describes unprivileged
project code; guest root can remove the guest controls.

| Risk | `allowlist` (default) | `open` | `none` |
|---|---|---|---|
| Read or write host files | Blocked | Blocked | Blocked |
| Reach services on the host (databases, agents, IDE) | Blocked | Blocked | Blocked |
| Reach the internet | Allowed hosts and ports, via the logged proxy | Any host on permitted ports, via the logged proxy | Blocked |
| Exfiltrate data over DNS (through the resolver) | Blocked (`dns: resolvers` reopens it) | Blocked (same) | Blocked |
| Tunnel to a non-web port of an allowed host | Blocked unless `host:port` is listed | Blocked unless listed | Blocked |
| Expose a listener to the Mac | Only ports in `forward` | Only ports in `forward` | Only ports in `forward` |
| Change its own network policy | Blocked | Blocked | Blocked |
| Escape the VM | Hypervisor boundary | Hypervisor boundary | Hypervisor boundary |

## The boundary

Each project runs in its own Lima virtual machine on Apple's
Virtualization.framework. The hypervisor separates the guest kernel from your
Mac; projects do not share a kernel with each other or the host.

Guest network controls depend on the guest kernel remaining trustworthy.
Optional host enforcement adds a network boundary on the Mac. Containers inside
the VM provide convenience, not an additional security boundary.

## What is enforced, and how

### Host files

The instance config has `mounts: []`. Lima's default home-directory mount is
never created. `source: mount` is the explicit opt-in, read-only unless
`mount_writable: true`.

### Copying data out of the VM

devkit copies project files and the proxy binary into the VM. It does not copy
changes back into your working tree. Toolchain lockfiles stay in the VM.

The explicit exception is `devkit push`. It reads a size-limited Git bundle into
a private temporary file on your Mac. Git checks every object before storing the
branch under `refs/devkit/`, outside your branches and working tree. Pushing
requires confirmation unless you pass `--yes`; no Git hooks run on the Mac. See
[Git review and credentials](#git-review-and-credentials).

The end-to-end suite rewrites workspace files inside the VM and checks that the
host project directory remains byte-for-byte unchanged.

### Terminal output

The blocked-host summary that `devkit up` prints is built from hostnames the
sandbox chose, so it is stripped of control characters first, as are the file
names `devkit sync` reports from the VM. Several other streams are shown raw: dependency and toolchain installs, `devkit
shell`, `devkit logs`. A hostile install script can therefore write terminal
control sequences at you, the same as any build you run on your Mac. Your
terminal emulator is the defence there, not devkit.

### Access to host services

The guest can normally reach the host at `host.lima.internal`, which is also its
gateway. The firewall rejects all traffic to that address except the proxy's DNS
to the configured resolvers, unless `network.allow_host: true`, in which case
the host is reachable directly and is listed in `NO_PROXY`, so that traffic is
not audited. In `none` mode DNS is rejected too, unless `allow_host: true`,
which keeps the host reachable and, with it, any resolver running there.

### Forwarded ports and IDE connections

Lima would forward every port the guest listens on to `127.0.0.1` on the host.
devkit tells it to forward only the ports in `network.forward`. The reason is
not the listener itself but what you might do with it: a page served by the
sandbox, opened in your browser, runs with the browser's network, which the
firewall never sees. The same goes for an IDE's remote session, whose local
client acts on what the extension host in the guest asks of it. Treat anything
you open from the sandbox as a bridge you chose to build.

### Network access during boot

Root applies the firewall late in boot. Before then, Lima opens SSH sessions as
the sandbox user. Those sessions read user-writable files such as `~/.ssh/rc`,
`~/.bashrc` and `~/.profile`. Code planted in those files could otherwise use an
unrestricted network on the next boot. An end-to-end test demonstrated direct
HTTP access through this gap before it was fixed.

A unit installed during the first boot now runs before sshd on later boots. It
blocks new outbound traffic from the sandbox user until the firewall is ready.
The firewall is rebuilt under a DROP policy, so replacing the rules does not
briefly reopen the network.

The temporary block includes loopback: otherwise the sandbox could relay
requests through the proxy or systemd-resolved. In `dns: proxy` and `none`
modes, systemd-resolved is also blocked, including lookups requested over D-Bus.
A fresh VM has no existing sandbox files to run during its first boot.

`devkit up` reads progress from the serial console on the Mac. It does not poll
over SSH, which would execute those user-writable startup files.

### Failed provisioning

Provisioning removes `/etc/devkit/provision.id` when it starts and writes it
back only after applying the firewall. If `devkit up` finds a running VM without
that stamp, it stops the VM, reports the failed step and exits with a non-zero
status. It does this even if `limactl start` reported success, and before
copying project files or installing project dependencies. `devkit shell` and
`devkit sync` also refuse a VM without the stamp.

The guest has a separate safeguard for manual starts. Before any download, the
provisioning script sets `IPAddressDeny=any` on the sandbox user's systemd slice
and on systemd-resolved. This needs no additional packages and blocks sockets
per cgroup, including loopback and interface-bound sockets. The script lifts the
block only once the firewall is ready. If provisioning fails, the block remains
until shutdown.

There are two limits:

- The provisioning block starts with the script. A VM that has never finished
  provisioning has no boot-hold unit yet, so Lima's earlier SSH sessions still
  have the network access normally available on a first boot.
- The Mac reads the stamp over SSH as the sandbox user. Modified shell startup
  files could forge the response. The guest's network block does not depend
  on that response.

### Connection tracking

Linux connection tracking (`conntrack`) identifies flows by addresses and ports,
not by the account that owns a socket. Its entries can outlive the socket. A
sandbox process can therefore reuse a source port the proxy used for DNS and try
to send through the existing flow.

Before the fix, a sweep of ephemeral ports received 70 DNS answers this way. The
firewall now accepts established outbound flows only for root and the proxy.
Other accounts may reply to connections made to the guest, such as SSH and
forwarded ports, or use an explicitly allowed path.

The end-to-end suite repeats the port sweep while the proxy resolves names and
requires that none of the sandbox's queries receive an answer.

### Outbound connections and DNS

In `allowlist` and `open` modes, the iptables `OUTPUT` chain permits loopback,
connection replies under the ownership rules above, and permitted traffic from
the proxy's service account. It also honours explicit DNS and host-access
options. Other outbound traffic is rejected.

By default, only the proxy can query the resolvers listed in
`/run/systemd/resolve/resolv.conf`. It resolves allowed hosts directly through
those upstream resolvers, bypassing the local stub. The sandbox cannot send
its own DNS queries. `network.dns: resolvers` lets all guest accounts query
the configured resolvers, including queries that could carry data out.

The HTTP/CONNECT proxy enforces `network.allow` in `allowlist` mode and allows
any host in `open` mode. Host entries allow ports 80 and 443; other ports must
be listed explicitly. Allowing GitHub therefore does not also allow its SSH
port. Tools use the system-wide `HTTP_PROXY` and `HTTPS_PROXY` settings;
apt has a separate proxy configuration.

### Security updates

Root applies Ubuntu's security updates on every boot, before the firewall comes
up, so the sandbox does not sit at the pinned image's patch level while the
image ages. A local privilege escalation can turn the sandbox user into root.
Under guest enforcement, root can remove the firewall and reach your Mac's
loopback services through Lima's gateway. A kernel update installed this way
runs from the next boot; `devkit up` does not reboot a VM whose configuration
has not changed, so `devkit down && devkit up` is what boots into it.
`vm.security_updates: false` turns the step off.

### Restricted kernel features

The guest disables or restricts kernel interfaces that development workloads
rarely need and that can expose privilege-escalation bugs. A sysctl drop-in
disables io_uring and restricts BPF, perf, userfaultfd and ptrace.

By default, Ubuntu's `kernel.unprivileged_userns_clone = 0` also prevents
unprivileged user namespaces. AppArmor's
`kernel.apparmor_restrict_unprivileged_userns` remains enabled, but is not
sufficient on its own: Ubuntu exempts programs including `rootlesskit`, `runc`,
`slirp4netns`, `podman` and `lxc`. Tests with `rootlesskit` showed that an
exempted program could create a namespace with `CAP_NET_ADMIN`. The kernel
switch prevents the namespace itself; root is unaffected.

`tools.containers: true` leaves user namespaces enabled because Lima's rootless
containerd needs them. That mode relies on AppArmor, including its exemptions.
Turning containers off closes namespaces again on the next boot. If the kernel
lacks the switch, provisioning warns and uses AppArmor alone.

### Kernel module loading

Kernel modules add executable code to the guest kernel. Socket families, network
link types and netfilter extensions can trigger module loading, including
through requests from unprivileged processes.

The last provisioning step sets `kernel.modules_disabled = 1`. After that, even
root cannot load another module until the VM restarts. Each boot provisions and
locks again. With `containers: true`, devkit first loads the bridge, veth,
overlay, NAT and netfilter modules that containers need.

A tool that needs an unloaded module may fail with "operation not supported" or
"Operation not permitted". Restarting alone will not fix that, because each boot
locks loading again. Set `vm.lock_modules: false` and run `devkit up` to leave
loading enabled for the project.

The `AF_ALG` kernel crypto socket family is separately blocked from loading and
unloaded if present. This removes a source of kernel attack surface; it does not
protect against bugs in other reachable kernel code.

### Further isolation with gVisor

Kernel restrictions cannot rule out every privilege-escalation bug. An
additional sandbox such as gVisor could run project processes behind a userspace
kernel inside the VM, reducing their direct access to the guest kernel.

This is an opt-in roadmap item. It has compatibility and performance costs, and
an IDE's remote processes would need to run inside the extra sandbox to benefit.
The VM would still provide the boundary between the guest kernel and your Mac.

### Configuration validation

`network.allow`, `repo`, `branch`, `tools.versions` and `tools.packages` are
validated against strict grammars, and the policy files are written through
quoted heredocs, so a hostile `devkit.yaml` cannot run commands as root in the
VM. `install:` is deliberately free-form: it runs as the sandbox user, which is
the thing being sandboxed.

### TLS trust and certificate audits

devkit refreshes Ubuntu's `ca-certificates` package on every boot. It also
points supported runtimes at that system bundle:

- Node: `--use-openssl-ca`.
- Python and pip: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `PIP_CERT`.
- curl: `CURL_CA_BUNDLE`.

`network.distrust` removes additional named roots, for example when Ubuntu's
trust decisions lag behind Mozilla's. Updating root certificates does not
provide per-certificate revocation checking.

`devkit audit` compares the system, Node, Java, certifi and project certificate
bundles with Mozilla's current root store, fetched through the proxy. It reports
roots absent from that store and suggests `distrust` entries. `devkit up` runs a
shallow audit; `devkit audit --deep` scans every file.

A compiled program can embed its own bundle and ignore the environment. The
audit may find embedded certificates by fingerprint, but it cannot make the
program use the system bundle. The proxy passes TLS through without inspecting
certificates; TLS 1.3 encrypts them.

### Container image audits

`devkit audit` reads Compose files and Dockerfiles and classifies image
references as:

- **Pinned:** `@sha256:` followed by 64 hexadecimal characters.
- **Unpinned:** a tag or bare image name, which can refer to different code later.
- **Unresolved:** a variable whose value the audit cannot determine.

The audit reads the source files because Docker's image list cannot show whether
an image was originally requested by tag or digest. Docker is not required.

Compose variables are resolved from `.env` and reference defaults. Dockerfile
variables use `ARG` defaults before the first `FROM`. Other values, including
build arguments supplied on the command line, remain unresolved.

Without PyYAML, Compose parsing falls back to line matching and is labelled
approximate. Files over 256 KB, binary files and non-regular files are reported
as unread. File names and references are stripped of control characters before
display.

Unpinned and unresolved images are informational: they do not change the audit's
exit status.

### Toolchain installation

Root installs only the manager (mise or Nix) from a release archive pinned by
SHA-256 in devkit's source, with the pin taken after verifying the upstream
signature. The toolchains come in afterwards as the sandbox user, through the
proxy and into the audit log. mise runs with plugin backends disabled,
provenance checks on every install, a three-day minimum release age, and a
lockfile written in the VM on the first run and enforced with `--locked`
afterwards. The sandbox user owns that lockfile, so it guards against upstream
changing an archive, not against the sandbox itself, which can already run
anything. Nix checks every substitute against the cache's signing key and pins
inputs in `flake.lock`.

### Disabling outbound traffic

`network.mode: none` rejects all outbound traffic including DNS. Incoming SSH
still works because its return packets are an established connection. Combined
with `allow_host: true` the gap has one opening: the host, and therefore DNS
through the host's resolver. Pair them only when that is what you want.

### Policy ownership

The user account inside the VM can run exactly three commands as root, all
read-only checks Lima's host agent needs to confirm the machine booted. Policy
lives in a root-only provisioning script that Lima regenerates from
`devkit.yaml` on every boot. To change the policy you edit the file on the host
and run `devkit up`, which restarts the VM. Setting `sudo: true` removes this
guarantee; it is there for convenience and says so in the config.

### Proxy binary verification

The host drops the proxy into a staging directory owned by the sandbox user. A
root systemd unit copies it to a root-only location, hashes that copy, and
installs it only if the SHA-256 matches the hash baked into the provisioning
script. The staged file is never read twice, so the sandbox cannot swap it
between the check and the install.

### Network logs

The proxy logs every request as `ALLOWED` or `BLOCKED` with the target host to
`/var/log/devkit/egress.log`. `devkit logs` reads it, and `devkit up` prints a
summary of blocked hosts after installing dependencies.

### Local port bindings

Ports listed in `network.forward` bind to `127.0.0.1` on the Mac. These forwards
are not exposed on the Mac's LAN interfaces.

## Enforcement on the Mac (`network.enforce: host`)

Host enforcement adds a network control outside the guest. Lima's host agent
runs under a macOS sandbox profile through `sandbox-exec`. No root access is
needed on the Mac.

### What the host agent can reach

The profile permits outbound connections only to:

- Unix sockets under Lima's home directory.
- The VM's SSH forward on the Mac's loopback interface, over TCP.
- devkit's host proxy on the Mac's loopback interface, over TCP.

The TCP rules use `remote tcp`. Using `remote ip` would also permit UDP.
Unix sockets are restricted because allowing all of them let Lima resolve DNS
through the Mac's resolver socket, creating a path for data to leave the VM.

### Host proxy policy and lifecycle

`devkit up` starts one `devkit hostproxy` per VM before starting the VM.
`devkit down` and `devkit rm` stop it. An existing proxy is reused only if its
allowlist and executable SHA-256 match the current configuration and binary.
Otherwise, devkit restarts it on the same port.

The host proxy applies the same hostname and port rules as the guest proxy.
Its allowlist includes both `network.allow` and the hosts needed for
provisioning: Ubuntu's archive, ports and security hosts, plus the toolchain
manager's download hosts. In `open` mode, any host is allowed on web ports.

After resolving a name, the proxy refuses it if any returned address is
loopback, link-local or assigned to a Mac interface. This covers IPv4 and IPv6,
the Mac's LAN address and the VM gateway. IP literals are checked too. Other
machines on the LAN are subject to the allowlist, not automatically blocked.
Redirects are returned to the guest proxy for a new policy decision.

Inside the VM, root's downloads and apt requests use the host proxy, as does
the guest proxy. The guest proxy's account can reach only the host proxy, and
no guest account can send DNS queries.

### Logs and tests

`devkit logs` reads `~/.devkit/<vm>/hostproxy.log`, the record of requests that
reached the host proxy, including root's provisioning requests. Requests
refused by the guest proxy stay in the guest log; `devkit up` still summarises
those blocks.

`TestHostEnforcement` removes the guest firewall and stops the guest proxy,
then probes as guest root. It tests TCP, IPv6, DNS over UDP and TCP, NTP,
listeners on the Mac, a port sweep and other addresses on Lima's network.
Only the host proxy should remain reachable. Tests in `internal/hostenforce`
also check the profile directly on the Mac, without a VM.

The profile blocks ICMP sent from the Mac. A ping inside the guest may time
out or receive a local reply from Lima's network stack; that reply does not
show that a packet reached the external destination.

### Limitations

- **Allowed hosts remain reachable by guest root.** This includes provisioning
  hosts as well as the project's allowlist.
- **Manual starts bypass the profile.** A VM started with `limactl start`
  lacks host enforcement. devkit records the host agent's process ID when it
  starts the VM and warns if the running agent differs. Stop and restart
  through devkit to restore the profile.
- **The vsock channel is untested.** The tests did not attack communication
  between Lima's guest agent and host agent.
- **`sandbox-exec` is deprecated.** devkit refuses to start a host-enforced
  VM if the required support is missing; it does not silently fall back to
  guest enforcement. This mode requires macOS.
- **Outbound firewalls may block the proxy.** Tools such as LuLu need to
  allow the `devkit` binary.
- **Some options are incompatible.** Host enforcement rejects
  `allow_host: true`, `dns: resolvers` and `mode: none`. The first two require
  other host access; `none` would prevent first-boot package installation.

## Git review and credentials

`devkit push` lets you publish commits made inside the VM while keeping your
credentials on the Mac. Reviewing those commits is part of the security
boundary: the VM can write malicious code and forge commit authors.

### What you need to review

- **Commits the VM wrote can reach your remote.** That is the point of `devkit
  push`, and your review is the approval step (`--yes` skips the prompt). A malicious dependency can change
  files that an agent then commits, and rely on a long diff to hide it. The
  review lists every commit, the diffstat, the commits a forced push would
  remove, and the changed files that run outside the VM. It cannot judge the
  code for you.
- **Authorship from the VM proves nothing.** The VM commits as you: it gets
  your `user.name` and `user.email`, and can write any author it likes, so
  the review's "other author" note catches only the careless case.
- **Pushed commits run elsewhere.** CI runs them, with whatever secrets your
  workflows expose to that branch. If you bring them into your checkout on
  the Mac (`git merge refs/devkit/...`), your husky hooks, direnv, editor tasks
  and npm scripts there run code the VM wrote. That is the risk of checking
  out any untrusted pull request, and the one place where devkit's rule that
  project code never runs on the Mac depends on you.

### What runs on the Mac

- **Parsing untrusted bytes.** A bundle from the VM is read by devkit's
  header parser and `git index-pack --strict`, the same code as any `git
  fetch` from an untrusted remote, capped at 512 MiB. Text in the push review is
  stripped of control characters and bidi overrides before display.
- **devkit runs git on your Mac.** In a copied project's directory (to build
  the snapshot), and against your remotes (clone, sync, `ls-remote`, push),
  with your own git config and credentials, as when you run git there
  yourself, but with hooks disabled.
- **A copied project's sync keeps snapshots on the Mac,** in
  `~/.devkit/<vm>/sync.git`, a private repository that is never the
  project's own and is outside the project directory, so a project cannot
  supply or influence it (devkit refuses that directory, or the one above
  it, if it is a symlink). git there runs with none of your config or the project's, no hooks, and
  only plumbing (`fast-import` fed from `tar`), so the project's files are
  data: no attributes, filters or conversions apply. The VM's answer to which
  snapshot it has is accepted only as a commit id this Mac holds, and the
  file names it reports back are stripped of control characters and bidi
  overrides before display.

### How credentials and checkouts are handled

- **Cloning uses a bare repository**, so no project file is checked out
  on the Mac; https and ssh only; no submodules, hooks or templates.
- **Credentials stay out of the VM.** Without `devkit push`, the way to push
  from the VM was a token or an agent inside it, usable by every dependency.

**To keep the gate meaningful:** push to a feature branch and merge through a
pull request with branch protection; don't expose CI secrets to branches from
the VM; read the flagged files; and don't merge `refs/devkit/...` into your
Mac's checkout and then run the project's tooling there unless you have read
what it changes.

## Kernel crash reports, read on the Mac

### Detected reports

Kernel crash reports from the guest: panics, Oopses, `BUG:` and `kernel BUG at`,
KASAN and UBSAN reports, watchdog lockups, stack-protector failures and list
corruption. Failed exploit attempts often crash the kernel before one succeeds,
so these are worth seeing.

### Reading reports on the Mac

The provisioning script adds `console=hvc0` to the kernel command line through
a grub drop-in. Lima records that serial console in
`~/.lima/<vm>/serialv.log` on the Mac. The default console, `ttyAMA0`, does not
exist on this hypervisor, so the extra setting is needed to capture kernel
output. Messages at levels 0 to 3 (emergency to error) include the detected
crash reports.

devkit scans the log on the Mac. The sandbox user cannot write to `/dev/hvc0`,
`/dev/console` or `/dev/kmsg`. Tests also check that crashing a process named
"BUG: unable to" does not produce a kernel report.

The scanner matches signatures at the start of a kernel message, immediately
after its timestamp. User-chosen names elsewhere in a line cannot forge a
match, and devkit progress messages and systemd status lines are excluded.
Displayed reports are stripped of control characters and escape sequences.

### When reporting starts

The drop-in takes effect from the boot after the one that wrote it: a new VM
reports crashes only after its first restart (`devkit down`, then `devkit up`),
and devkit says so instead of reporting "none". If `update-grub` is missing or
fails, provisioning warns and goes on: this is detection, not enforcement.

### Detection limits

This catches the noisy attempt, not the clean one. An exploit that works the
first time crashes nothing, and once it has root it can lower the console level
or rewrite the command line, after which only what it lets through gets out. A
guest that hangs without printing a report is not detected either. A report is a
reason to act; the absence of one proves nothing.

### Responding to a report

Every command that uses the VM warns until you act, and `devkit audit` exits 1,
even with the VM stopped. A crash can be a failed exploit or an ordinary kernel
bug. If you cannot explain it, discard the VM with `devkit rm`. Otherwise
acknowledge it with `devkit audit --ack-crashes`. A kernel that has panicked
does not answer while Lima still lists the VM as Running; devkit names it, and
`devkit down` forces it off.

Reports are kept in `~/.devkit/<vm>/kernel-crashes.json` across restarts, since
Lima starts a new serial log at every VM start; `devkit up` and `devkit down`
read the log before that happens. A VM started with `limactl` directly, rather
than devkit, can lose a crash from before that start.

## What the escape tests cover

The [escape-test reference](docs/escape-tests.md) maps each attempted escape to
its control, tests and remaining limits.

`tests/e2e/escape_test.go` runs inside a real VM and tries, as the sandbox user,
to: reach the host by name, gateway IP, every port form, UDP and IPv6, directly
and through the proxy; flush the firewall, open raw sockets, bind port 22,
switch to the proxy's user, kill the proxy, or use a user namespace to get
around the OUTPUT chain; read secrets from Lima's cidata, find a host mount, or
dial the host over vsock; write to any policy file; and get a file back onto the
host by rewriting the workspace before `devkit up`. The suite does not test for
hypervisor escapes.

`examples/hostile-project` is the same idea by hand: a project whose code and
install step try the same escapes and report, line by line, whether each was
stopped. Run it in any mode to watch the boundary hold, and loosen `devkit.yaml`
to watch it give way where you told it to.

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
  devkit's host proxy, whatever root in the guest does. The mitigations are the security updates at boot, the kernel
  surface we take away (unprivileged user namespaces unless
  `containers: true`, module loading after provisioning, io_uring, BPF,
  perf, and the `AF_ALG` crypto family), and, for those who want it, an inner gVisor
  sandbox on the roadmap. See [security updates](#security-updates) and
  [restricted kernel features](#restricted-kernel-features). A kernel bug in a subsystem none of that covers still escalates;
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
  content leaves with your credentials, and your review is the approval step (`--yes` skips the prompt).
  The VM commits under your git identity and can forge any author. Pushed
  commits run in CI, and if you merge `refs/devkit/...` into your Mac's
  checkout, its hooks, direnv and scripts run code the VM wrote. Push to a
  feature branch behind branch protection, and read the files the review
  flags. The bundle itself is checked by `git index-pack --strict` with no
  hooks; a bug in git's pack parsing is the residual risk there. See [Git review and credentials](#git-review-and-credentials).
- **Hypervisor bugs.** A VM escape in Virtualization.framework would defeat
  everything here. There is no mitigation beyond keeping macOS updated.
- **Resource use.** The VM is sized by `vm:`. Code inside can exhaust its own
  CPU, memory and disk but not the host's beyond those limits.
- **Supply chain before the sandbox.** devkit itself and Lima are installed
  by you; verify them. The Ubuntu image, mise and Nix are pinned by digest,
  and apt verifies Ubuntu packages. See the [download verification table](README.md#what-gets-downloaded-and-how-it-is-verified).
  Between boot and the end of provisioning the firewall is not yet applied,
  and root uses that window to fetch and hash-check the manager's archive.
  The sandbox user gets no network in it: see [network access during boot](#network-access-during-boot)
  and [failed provisioning](#failed-provisioning).
- **Toolchain verification is uneven.** mise verifies Node against upstream's
  signed checksums, Go against a same-origin checksum, Python and Ruby builds
  against GitHub attestations, and `rustup-init` not at all. The lockfile
  turns each of those into a pin after the first run, so the exposure is the
  first `devkit up` and every `--relock`. Nix verifies everything against the
  cache key but trusts the hashes you commit in `flake.lock`.
- **Lima user key.** Lima's SSH key in `~/.lima/_config/user` grants access to
  every Lima VM on the machine. That is Lima's design, not devkit's.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a
public issue.
