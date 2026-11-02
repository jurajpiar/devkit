# Contributing

## Setup

```bash
brew install lima
make build          # cross-compiles the egress proxy and builds devkit
make test           # unit tests, no VM
make test-e2e       # creates a real VM; several minutes on first run
```

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
