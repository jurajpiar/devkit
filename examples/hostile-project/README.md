# hostile-project

A project whose code actively tries to break out of the devkit sandbox, so you
can watch the sandbox stop it. It is the manual counterpart to the automated
escape suite in `tests/e2e/escape_test.go`.

`probe.sh` runs as the sandbox user and, one attempt at a time, tries to reach
your Mac, the open internet, your files, and the sandbox's own firewall and
proxy. It judges each outcome against the policy root applied at boot, which
it reads from `/etc/devkit/network.conf`:

- `[held]` the sandbox stopped it.
- `[note]` it worked and the policy allows it: `open` mode, `allow_host`, DNS.
- `[LEAKED]` it worked and the policy says it must not. Enforcement failed;
  this should never appear.

It is a reporter, not an exploit. There is no working payload, and it sends no
data anywhere. The `postinstall` hook runs the same script, so `devkit up` also
shows you install-time code being sandboxed.

## Run it

```bash
cd examples/hostile-project
devkit init --force       # a Node project, allowlist mode by default
devkit up                 # installs deps; the postinstall probe runs and reports
devkit shell ./probe.sh   # run the probe again on demand
devkit logs               # the proxy's view: every host it allowed or blocked
```

## What you should see, per mode

| Attempt | `allowlist` (default) | `open` | `none` |
|---|---|---|---|
| Send packets to your Mac | held | held | held |
| Fetch an off-allowlist host | held (proxy 403) | note (fetched, logged) | held (no route) |
| Bypass the proxy directly | held | held | held |
| Resolve a DNS name | held (`dns: resolvers` makes it a note) | held (same) | held |
| Tunnel to github.com:22 through the proxy | held | held | held |
| Vendor a stale root CA (`certs/`, see `devkit audit`) | named stale | named stale | only flagged with a recent cached Mozilla store |
| Read host files or Lima secrets | held | held | held |
| sudo, edit the firewall, kill the proxy | held | held | held |

One of these is `note`, not `held`, on purpose, so the example teaches the
real boundary rather than pretending there is none:

- **DNS, only if you ask for it.** By default only the proxy resolves names
  and the sandbox cannot send a query, so this row is `held`. With
  `network.dns: resolvers` the VM may query its resolvers, a determined
  program can tunnel data out through query names, and the row becomes a
  `note`. See [SECURITY.md](../../SECURITY.md).
- **Off-allowlist hosts in `open` mode.** `open` means any host, still through
  the audited proxy and still in `devkit logs`; the firewall keeps rejecting
  anything that skips the proxy.

## Loosen the policy and watch

Change `devkit.yaml`, run `devkit up`, run the probe again. A `held` turns
into a `note` where you opened the door, and nowhere else:

- `network.allow_host: true`: packets to your Mac now leave the VM, and any
  port with a listener on the Mac opens.
- `network.mode: open`: example.com is fetched, and `devkit logs` shows it.
- `network.mode: none`: DNS stops resolving, and the proxy is off.
- `sudo: true`: the sudo check reports `LEAKED`, which is accurate. Root in
  the VM can switch the firewall off; the config says so on that line.

`LEAKED` for anything else means devkit has a bug. Please report it.

## The vendored trust store

`certs/vendored-ca-bundle.pem` is the other half of the demonstration, the
one the probe cannot run because it is about trust rather than reach. It
vendors the Izenpe.com root, which Ubuntu's `ca-certificates` still carries
but Mozilla no longer trusts for TLS, the way a dependency might ship its own
bundle. Run `devkit audit` in this project and it is named as stale, with the
`network.distrust` entry that would remove it from the system bundle too. A
fresh VM without this file audits clean.
