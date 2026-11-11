# Contributing

## Setup

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
guest can still reach when only the guest enforces the network. With an outbound firewall on the Mac such as LuLu, set
`DEVKIT_E2E_BIN` to a fixed absolute path and allow that binary once; the
host-enforcement tests make their connections from it.

To see devkit from a user's side first, follow
[docs/walkthrough.md](docs/walkthrough.md).

## Principles

- One VM per project is the product. Do not add a mode that shares a kernel.
- The security policy is `internal/provision/provision.go`. Changes there need
  an end-to-end test in `tests/e2e` that proves the guarantee still holds.
- Secure by default, convenience by opt-in, and every opt-in says what it costs
  in the config comment.
- Keep `devkit.yaml` small. A new key needs a reason a user would understand.
- No sudo for the sandbox user. If a feature needs root in the VM, it belongs in
  the provisioning script.

## Pull requests

Run `gofmt`, `go vet ./...` and `make test` before opening one. Describe the
threat model impact of any change to provisioning, the firewall or the proxy.

## Reporting security issues

Privately to the maintainer, not in a public issue.
