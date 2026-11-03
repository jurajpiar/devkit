# hostile-project

A project whose code actively tries to break out of the devkit sandbox, so you
can watch the sandbox stop it. It is the manual counterpart to the automated
escape suite in `tests/e2e/escape_test.go`.

`probe.sh` runs as the sandbox user and, one attempt at a time, tries to reach
your Mac, the open internet, your files, and the sandbox's own firewall and
proxy. Each line reports what it tried:

- `[held]` the sandbox stopped it. This is the outcome you want for an attack.
- `[LEAKED]` the attempt succeeded. A boundary did not hold; investigate.
- `[note]` an outcome that is expected and allowed, so neither good nor bad.

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
| Reach your Mac | held | held | held |
| Fetch an off-allowlist host | held (proxy 403) | note (allowed, logged) | held |
| Bypass the proxy directly | held | held | held |
| Resolve a DNS name | note (possible) | note (possible) | held |
| Read host files or Lima secrets | held | held | held |
| sudo, edit the firewall, kill the proxy | held | held | held |

Two of these are `note`, not `held`, on purpose, so the example teaches the
real boundary rather than pretending there is none:

- **DNS.** In `allowlist` and `open` modes the VM may query its resolver, so a
  determined program can tunnel data out through query names. `network.mode:
  none` closes it. This is listed as an accepted risk in
  [SECURITY.md](../../SECURITY.md).
- **Off-allowlist hosts in `open` mode.** `open` means any host, still through
  the audited proxy and still in `devkit logs`; the firewall keeps rejecting
  anything that skips the proxy.

## Try to make it leak

This is the point of the example. Loosen `devkit.yaml` and watch a `held` turn
into a `note` or a `LEAKED`:

- Set `network.allow_host: true`, run `devkit up`, and the host checks start
  reporting the Mac as reachable, by design.
- Add `example.com` to `network.allow` and the off-allowlist fetch is allowed.
- Set `sudo: true` and the policy checks leak, because root can switch the
  firewall off. The config says as much on that line.
