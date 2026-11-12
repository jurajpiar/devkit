# Escape tests and their limits

This reference maps attempted escapes to the controls and tests that cover them.
**Host** means your Mac; **guest** means the project VM. These tests check
specific behaviours, not the absence of every possible escape.

See the [security model](../SECURITY.md) for the assumptions behind these
controls and the [README](../README.md#how-it-works) for an overview.

## Default guest enforcement

The end-to-end suite checks these controls on a real VM. `TestNetnsFirewall`
also checks the firewall rules in Linux network namespaces; the proxy has its
own unit tests. Guest root can remove the guest's network controls. Other
exceptions depend on configuration, trusted destinations or bugs in the software
that enforces the boundary.

### Direct internet connections

**Attempt:** Direct connection to the internet.

**Control:** The firewall permits outbound internet connections only from the
`devkit-proxy` account.

**Limit:** Root in the guest flushes the firewall, or you set `sudo: true`.

**Tests:** `direct connections bypassing the proxy are rejected`;
`TestNetnsFirewall`.

### Unlisted hosts and non-web ports

**Attempt:** Proxy to another host, or to port 22.

**Control:** Proxy: allowlist, ports 80 and 443 only.

**Limit:** You allow the host (or use `open` mode), explicitly allow the non-web
port, or trust an allowed host that the attacker controls. `open` mode alone
does not allow non-web ports.

**Tests:** `allowed hosts are reachable on web ports only`;
`TestProxyRefusesConnectToNonWebPort`,
`TestHTTPAllowsOnlyWebPortsWithoutAPortEntry`.

### Data sent through DNS queries

**Attempt:** DNS query with data in the name.

**Control:** Firewall: port 53 only for the proxy's account; resolver stub off.

**Limit:** You set `dns: resolvers`; or root in the guest; an allowed host the
attacker controls makes DNS unnecessary anyway.

**Tests:** `DNS is not a side channel`; `TestNetnsFirewall`.

### Reusing the proxy’s tracked DNS connection

**Attempt:** Send from a source port the proxy just used, riding its tracked DNS
flow.

**Control:** Firewall: connection state is trusted only for root and the proxy;
every other account may only reply on connections made to it.

**Limit:** Root in the guest, or `sudo: true`.

**Tests:** `DNS cannot ride another account's tracked connections`;
`TestNetnsFirewall`.

### Connections to your Mac

**Attempt:** Connect to your Mac.

**Control:** Firewall: host rejected for every account, the proxy included.

**Limit:** You set `allow_host: true`; or root in the guest, the one case the
suite leaves red.

**Tests:** `host is unreachable under every address form`; `TestNetnsFirewall`.

### Code run before the firewall starts

**Attempt:** Code planted in a login file (`~/.bashrc`, `~/.ssh/rc`) that runs
during the next boot, before the firewall exists.

**Control:** Boot hold: until the firewall is applied, no new connection from
the sandbox user or its container UIDs, loopback included, and no upstream DNS
from systemd-resolved.

**Limit:** Root in the guest, or `sudo: true`.

**Tests:** `TestBootWindowIsClosed`; `TestNetnsFirewall`.

### Listeners exposed to your Mac

**Attempt:** Listen for your Mac to connect.

**Control:** Lima: forward nothing unless listed in `network.forward`.

**Limit:** You list the port; or your IDE's own SSH tunnelling forwards it for
you, which Lima never sees.

**Tests:** `guest listeners are not forwarded to the Mac unless configured`.

### Access to host files

**Attempt:** Read or write your files.

**Control:** Lima: `mounts: []`; devkit never copies out of the VM on its own.

**Limit:** You use `source: mount` (read-only by default, writable with
`mount_writable: true`), approve a `devkit push` and merge its commits into your
checkout, or copy output out yourself; or a hypervisor escape.

**Tests:** `nothing from the VM lands on the host`.

### Commits pushed to your remote

**Attempt:** Get code onto your remote, and from there into CI or your checkout.

**Control:** `devkit push` only: the VM holds no credentials; you review the
commits and see flagged files that may run outside the VM. The push asks for
confirmation unless `--yes` was supplied.

**Limit:** You approve the push, including by using `--yes`; see [Git review and
credentials](../SECURITY.md#git-review-and-credentials).

**Tests:** `TestPushReviewsThenPushesWithHostCredentialsAndNoHooks`,
`TestReviewShowsEveryCommitWhateverItsText`,
`TestReviewShowsWhatAForcedPushRemoves`.

### Malicious Git bundles

**Attempt:** Exploit git on your Mac with a crafted bundle.

**Control:** devkit parses the header itself; `git index-pack --strict` checks
every object; size capped at 512 MiB; no hooks run.

**Limit:** A bug in git's own pack parsing, the code every `git fetch` from an
untrusted remote runs.

**Tests:** `TestImportRejectsAMaliciousTree`,
`TestImportChecksObjectsEvenWhenTheRepoDisablesFsck`.

### Changes to the policy or proxy

**Attempt:** Rewrite the policy or swap the proxy.

**Control:** Root-only policy files; proxy installed only if its SHA-256
matches.

**Limit:** Root in the guest; or the devkit binary or devkit.yaml on your Mac is
tampered with, which is outside the sandbox entirely.

**Tests:** `policy files are root-only`.

### Guest privilege escalation

**Attempt:** Become root.

**Control:** No general sudo access; io_uring, unprivileged BPF and `AF_ALG` off; unprivileged
user namespaces refused (unless `containers: true`; with `containers: docker`,
open to Docker's own account only); module loading locked after
provisioning; security updates at boot.

**Limit:** A kernel bug in a subsystem still reachable and not yet in the
installed security updates, or `sudo: true`.

**Tests:** `unprivileged kernel attack surface is reduced`, `security updates
are applied`, `TestKernelLockdown`.

### Host services reached by guest root

**Attempt:** Root reaches your Mac's loopback services.

**Control:** Nothing inside the guest.

**Limit:** An attacker needs guest root, for example through a privilege
escalation or `sudo: true`. With no host mounts, accessing host files also
requires crossing the hypervisor boundary.

**Tests:** `TestRootInGuestReachesHost`, kept red on purpose.

## With host enforcement enabled

`network.enforce: host` adds controls on the Mac. `TestHostEnforcement` checks
them with guest root, the guest firewall removed and the guest proxy stopped.
See [host
enforcement](../SECURITY.md#enforcement-on-the-mac-networkenforce-host) for
setup restrictions and remaining risks.

### Direct connection to the internet, any port, IPv4 or IPv6

**Control:** Refused on the Mac: the host agent may not dial it.

**Limit:** Allowed destinations can still be reached through the host proxy;
direct connections remain blocked.

### DNS query with data in the name, to any resolver or to Lima's own

**Control:** No answer: the Mac's resolver socket is out of the host agent's
reach.

**Limit:** An allowed host the attacker controls makes DNS unnecessary anyway.

### Connect to your Mac's loopback services

**Control:** Refused on the Mac, except the host proxy and the VM's own SSH
forward, which leads back into the guest.

**Limit:** A gap in the profile or in Lima; the host proxy itself refuses
addresses of the Mac: loopback, link-local and any address on one of its
interfaces, such as its LAN address, by IP or by a name that resolves to one.

### Rewrite the in-guest policy or swap the in-guest proxy

**Control:** Possible, and no longer enough: the host proxy's allowlist is
outside the guest.

**Limit:** You change `devkit.yaml` on the Mac.

### Through the host proxy to another host or port

**Control:** Refused by the host proxy, ports 80 and 443 only unless listed.

**Limit:** The host is in `network.allow` or is one root's provisioning needs:
Ubuntu's archive, ports and security hosts and the toolchain manager's download
hosts; or `open` mode.
