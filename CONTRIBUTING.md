# Contributing

## Setup

You need Go 1.23 or newer and an Apple silicon Mac. Install Lima, then build
and test from the repository root:

```bash
brew install lima
make build          # cross-compiles the egress proxy and builds devkit
make test           # unit tests, no VM
make test-e2e       # creates a real VM; several minutes on first run
```

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
