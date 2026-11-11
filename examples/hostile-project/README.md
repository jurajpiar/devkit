# Hostile project example

This example tests the devkit sandbox by attempting actions that its default
policy should block. It is the manual counterpart to the automated
[escape tests](../../tests/e2e/escape_test.go).

`probe.sh` runs as the sandbox user and, one attempt at a time, tries to reach
your Mac, the open internet, your files, and the sandbox's own firewall and
proxy. It judges each outcome against the policy root applied at boot, which
it reads from `/etc/devkit/network.conf`:

- `[held]`: the attempt was blocked.
- `[note]`: the attempt worked and the policy allows it.
- `[LEAKED]`: a protection checked by the probe did not hold. This is unexpected
  with the default policy; deliberately enabling sudo also produces this result.

The script makes network probes and checks permissions; it does not contain
a working exploit payload. The `postinstall` hook runs the same script, so
`devkit up` also demonstrates the controls during dependency installation.

## Run it

```bash
cd examples/hostile-project
devkit init --force       # a Node project, allowlist mode by default
devkit up                 # installs deps; the postinstall probe runs and reports
devkit shell ./probe.sh   # run the probe again on demand
devkit logs               # the proxy's view: every host it allowed or blocked
```

## Expected results

These results assume guest enforcement and the example's other default
settings. Certificate checks come from `devkit audit`, separately from the
network probe.

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

Some settings deliberately allow an attempt and produce a `note`:

- **DNS, only if you ask for it.** By default only the proxy resolves names
  and the sandbox cannot send a query, so this row is `held`. With
  `network.dns: resolvers` the VM may query its resolvers, a determined
  program can tunnel data out through query names, and the row becomes a
  `note`. See [SECURITY.md](../../SECURITY.md).
- **Off-allowlist hosts in `open` mode.** `open` means any host, still through
  the audited proxy and still in `devkit logs`; the firewall keeps rejecting
  anything that skips the proxy.

## Compare policy settings

Change one setting in `devkit.yaml`, run `devkit up`, then run the probe
again. These settings change the expected results:

- `network.allow_host: true`: packets to your Mac now leave the VM, and any
  port with a listener on the Mac opens.
- `network.mode: open`: example.com is fetched, and `devkit logs` shows it.
- `network.mode: none`: outbound traffic and DNS are blocked, and the proxy
  is off. Keep `allow_host: false` for this comparison.
- `sudo: true`: the sudo check reports `LEAKED`, which is accurate. Root in
  the VM can switch the firewall off; the config says so on that line.

An unexpected `LEAKED` result needs investigation. Report suspected
vulnerabilities privately, as described in [SECURITY.md](../../SECURITY.md#reporting).

## The vendored trust store

`certs/vendored-ca-bundle.pem` demonstrates a dependency shipping its own
certificate bundle. It contains the Izenpe.com root, chosen as a fixture for
the stale-root check.

Run `devkit audit` to compare it with the Mozilla root store used by the
audit. If the root is absent from that store, the audit reports it and
suggests a `network.distrust` entry to remove it from the system bundle too.
This checks certificate trust; `probe.sh` checks connectivity and permissions.
