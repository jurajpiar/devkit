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
| Exfiltrate data over DNS | Possible | Possible | Blocked |
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
`host.lima.internal`, which is also its gateway and DNS resolver. The firewall
rejects all traffic to that address except DNS unless `network.allow_host: true`.
In `none` mode DNS is rejected too.

**Egress allowlist.** In `allowlist` mode an iptables `OUTPUT` chain accepts
loopback, established connections, DNS, and packets owned by the proxy's
service account. Everything else is rejected. The proxy is an HTTP/CONNECT proxy
with the allowlist; it is the only process that can open outbound TCP
connections. Tools pick it up from `HTTP_PROXY`/`HTTPS_PROXY`, set system-wide,
and apt is configured separately. Software that ignores proxy settings is
simply blocked by the firewall.

**Air gap.** `network.mode: none` rejects all outbound traffic including DNS.
Incoming SSH still works because its return packets are an established
connection.

**The sandbox cannot loosen the policy.** The user account inside the VM can
run exactly three commands as root, all read-only checks Lima's host agent
needs to confirm the machine booted. Policy lives in a root-only provisioning script that Lima regenerates from
`devkit.yaml` on every boot. To change the policy you edit the file on the host
and run `devkit up`, which restarts the VM. Setting `sudo: true` removes this
guarantee; it is there for convenience and says so in the config.

**Trusted proxy binary.** The host drops the proxy into a staging directory. A
root systemd unit installs it only if its SHA-256 matches the hash baked into
the provisioning script. Code in the VM cannot substitute its own binary.

**Audit log.** The proxy logs every request as `ALLOWED` or `BLOCKED` with the
target host to `/var/log/devkit/egress.log`. `devkit logs` reads it, and
`devkit up` prints a summary of blocked hosts after installing dependencies.

**Localhost-only exposure.** Lima forwards ports the guest listens on to
`127.0.0.1` on the host. Nothing is reachable from your network.

## Accepted risks

- **DNS exfiltration.** In `allowlist` and `open` modes DNS is allowed so the
  proxy can resolve names. A determined attacker can tunnel data through DNS
  queries. Use `none` when that matters.
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
- **Supply chain before the sandbox.** devkit itself, Lima, Ubuntu cloud images
  and NodeSource packages are downloaded over the network. Verify what you
  install.
- **Lima user key.** Lima's SSH key in `~/.lima/_config/user` grants access to
  every Lima VM on the machine. That is Lima's design, not devkit's.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a public
issue.
