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
`branch`, `tools.node` and `tools.packages` are validated against strict
grammars, and the policy files are written through quoted heredocs, so a
hostile `devkit.yaml` cannot run commands as root in the VM.

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
  by you; verify them. The Ubuntu image is pinned by digest, Node.js comes
  from NodeSource's apt repository verified against a signing key embedded in
  devkit, and apt verifies Ubuntu packages. See "What gets downloaded" in the
  README. Between boot and the end of provisioning the firewall is not yet
  applied; only root runs during that window.
- **Lima user key.** Lima's SSH key in `~/.lima/_config/user` grants access to
  every Lima VM on the machine. That is Lima's design, not devkit's.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a public
issue.
