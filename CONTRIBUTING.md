# Contributing

## Setup

You need Go 1.23 or newer and an Apple silicon Mac. Install Lima, then build
and test from the repository root:

```bash
brew install lima
make build          # cross-compiles the egress proxy and builds devkit
make test           # unit tests, no VM
make test-e2e       # creates real VMs, one test after another; over half an hour
```

The end-to-end suite skips what needs more unless you ask for it:

```bash
DEVKIT_E2E=1 DEVKIT_E2E_SUDO=1 DEVKIT_E2E_NIX=1 go test ./tests/e2e/ -v -count=1 -timeout 150m
DEVKIT_E2E=1 go test ./tests/e2e/ -run 'TestKernelLockdown$' -v -count=1 -timeout 60m   # one test
```

`DEVKIT_E2E_SUDO=1` adds the tests that need root in the guest, and
`DEVKIT_E2E_NIX=1` the Nix toolchain. One of the root tests,
`TestRootInGuestReachesHost`, fails on purpose: it records what root in the
guest can still reach when only the guest enforces the network. With an
outbound firewall on the Mac such as LuLu, set `DEVKIT_E2E_BIN` to a fixed
absolute path and allow that binary once; the host-enforcement tests make
their connections from it.

To see devkit from a user's side first, follow
[docs/walkthrough.md](docs/walkthrough.md).

## Principles

- Keep one VM per project. Do not add a mode that shares a kernel.
- Changes to the security policy in `internal/provision/provision.go` need an
  end-to-end test in `tests/e2e` that checks the affected guarantee.
- Keep secure defaults. Make convenience options opt-in and explain their
  security trade-offs in the configuration comments.
- Keep `devkit.yaml` small. Add a key only when it meets a clear user need.
- Keep general sudo access disabled by default. Put features that need root
  inside the VM in the provisioning script.

## Pull requests

Before opening a pull request, format changed Go files with `gofmt`, then run
`go vet ./...` and `make test`. Run the relevant end-to-end tests for security
policy changes.

For changes to provisioning, the firewall or the proxy, explain which threats
the change addresses and whether it changes any security guarantees.

## Reporting security issues

Report vulnerabilities privately to the maintainer. See
[SECURITY.md](SECURITY.md) for the threat model and known limitations.
