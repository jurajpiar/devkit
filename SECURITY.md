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
| Exfiltrate data over DNS (through the resolver) | Possible | Possible | Blocked |
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

**Nothing comes back.** devkit copies files into the VM (`source: copy`, the
proxy binary) and never out of it. There is no guest-to-host copy in the code
and toolchain lockfiles stay in the VM. The end-to-end suite has a hostile
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
traffic to that address except DNS to the configured resolvers unless
`network.allow_host: true`, in which case the host is reachable directly and
is listed in `NO_PROXY`, so that traffic is not audited. In `none` mode DNS is
rejected too.

**Egress allowlist.** In `allowlist` and `open` modes an iptables `OUTPUT`
chain accepts loopback, established connections, DNS to the resolvers in
`/run/systemd/resolve/resolv.conf`, and packets owned by the proxy's service
account. Everything else is rejected, so port 53 cannot be used to reach
arbitrary endpoints. The proxy is an HTTP/CONNECT proxy; in `allowlist` mode
it enforces `network.allow`, in `open` mode it allows every host. It is the
only process that can open outbound TCP connections. Tools pick it up from
`HTTP_PROXY`/`HTTPS_PROXY`, set system-wide, and apt is configured separately.
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
connection.

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

- **DNS exfiltration.** In `allowlist` and `open` modes DNS to the configured
  resolvers is allowed so the proxy can resolve names. A determined attacker
  can tunnel data through DNS queries to a domain they control. Use `none`
  when that matters.
- **Allowed hosts are trusted.** If you allow `**.github.com`, code can push to
  any GitHub repository it has credentials for. Keep the list tight and read
  the log.
- **Credentials you bring in.** Nothing is copied into the VM except your
  project directory (minus `exclude`) and your SSH public key. If you paste a
  token into the sandbox, assume the sandbox has it.
- **Hypervisor bugs.** A VM escape in Virtualization.framework would defeat
  everything here. There is no mitigation beyond keeping macOS updated.
- **Resource use.** The VM is sized by `vm:`. Code inside can exhaust its own
  CPU, memory and disk but not the host's beyond those limits.
- **Supply chain before the sandbox.** devkit itself and Lima are installed
  by you; verify them. The Ubuntu image, mise and Nix are pinned by digest,
  and apt verifies Ubuntu packages. See "What gets downloaded" in the README.
  Between boot and the end of provisioning the firewall is not yet applied;
  only root runs during that window, and that is when the manager's archive
  is fetched and hash-checked.
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
