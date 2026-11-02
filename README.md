# devkit

Disposable sandbox VMs for untrusted code and coding agents, on macOS.

Every project gets its own virtual machine on Apple's hypervisor. The VM cannot
see your files, cannot reach services on your Mac, and can only talk to the
hosts you allow. Every outbound connection goes through an audited proxy. When
you are done, delete the machine.

> Work in progress. Expect rough edges; see [SECURITY.md](SECURITY.md) for what
> is and is not guaranteed.

## Why

Running `npm install` on a stranger's pull request, or letting a coding agent
loose on a repository, executes arbitrary code on your laptop with your SSH
keys, cloud credentials and local databases in reach. devkit moves that work
into a machine you can throw away.

## Requirements

- macOS on Apple silicon
- [Lima](https://lima-vm.io/) 1.1 or newer (`brew install lima`)
- Go 1.23 or newer to build from source

## Install

```bash
git clone https://github.com/jurajpiar/devkit.git
cd devkit
make install        # cross-compiles the egress proxy for the VM, embeds it, installs devkit
devkit doctor       # checks Lima, the proxy binary and the host
```

`make install` copies the binary to `/usr/local/bin`. A plain `go build` also
works; devkit then builds the proxy with your Go toolchain on first use.

## Use

```bash
cd my-project
devkit init         # writes devkit.yaml (Node.js version from .nvmrc or package.json)
devkit up           # creates the VM, copies the code in, installs dependencies
devkit shell        # shell inside the VM, in ~/workspace
devkit logs         # every host the sandbox tried to reach, allowed or blocked
devkit rm           # delete the VM and everything in it
```

The first `devkit up` downloads the Ubuntu image (about 220 MB, checked
against a pinned digest) and provisions the machine, which takes a few minutes.
After that, `up` takes seconds.

Dependencies are installed from the lockfile only (`npm ci`, `pnpm install
--frozen-lockfile`, `yarn install --frozen-lockfile`). Without a lockfile
devkit falls back to `npm install` and tells you to commit the result.

To work from VS Code or Cursor, use the Remote-SSH extension and connect to
`devkit-<name>`. devkit maintains the entry in `~/.ssh/config`; `devkit
connect` prints the steps. Ports your app listens on inside the VM appear on
`127.0.0.1` on your Mac automatically.

## Configuration

`devkit init` writes this file. Edit it and run `devkit up` again to apply; the
VM restarts if the change needs it.

```yaml
name: my-project
source: copy            # copy | git | mount
# repo: https://github.com/you/repo.git   # for source: git
# branch: main

tools:
  node: "22"            # Node.js major version (22, 24 or 26 are LTS), or omit
  containers: false     # rootless containerd + nerdctl inside the VM
  # packages: [postgresql-client]

vm:
  cpus: 4
  memory_gb: 8
  disk_gb: 50

ssh_port: 2222

network:
  mode: allowlist       # allowlist | open | none
  allow:
    - registry.npmjs.org
    - github.com
    - "**.github.com"
  allow_host: false     # reach services on your Mac

# exclude: [.git, node_modules]   # never copied into the VM (defaults apply)
# mount_writable: false           # source: mount only; lets the sandbox edit your files
# sudo: false                     # root inside the VM can disable the firewall
```

**Source methods**

| `source` | What happens | Notes |
|---|---|---|
| `copy` | The directory is copied into the VM on `up` and `sync` | Default. Host is never touched again. |
| `git` | The repo is cloned inside the VM | Set `repo` and `branch`. `sync` pulls. |
| `mount` | The directory is mounted read-only | Opt in. `mount_writable: true` lets the sandbox edit your files. |

**Network modes**

| `mode` | Outbound traffic | Use |
|---|---|---|
| `allowlist` | Only hosts in `allow`, via the audited proxy; the firewall rejects everything else | Default |
| `open` | Any host, via the audited proxy; the firewall still rejects direct connections | Trusted code, want the log |
| `none` | Nothing, not even DNS | Air-gap after dependencies are installed: `devkit up --network none` |

Allowed hosts are hostnames or IPs: `example.com` exact, `*.example.com` one
level, `**.example.com` any depth. Anything else is rejected at validation.
DNS is permitted only to the VM's configured resolvers.

The sandbox cannot reach your Mac in any mode unless `allow_host` is true. With
`allow_host: true` the VM reaches the host directly at `host.lima.internal`,
bypassing the proxy and its log.

**Containers** are opt-in. With `containers: true` the VM gets rootless
containerd and `nerdctl` for databases and services.

## Commands

| Command | Description |
|---|---|
| `devkit init [repo-url]` | Write `devkit.yaml`. Flags: `--name`, `--node`, `--network`, `--force` |
| `devkit up` | Create or start the VM, sync source, install dependencies. Flags: `--network`, `--no-sync`, `--no-install` |
| `devkit shell [cmd]` | Shell in the VM, or run a command |
| `devkit sync` | Copy the directory again, or `git pull` |
| `devkit logs [-f] [-n N]` | Egress audit log |
| `devkit connect` | IDE connection instructions |
| `devkit down` | Stop the VM, keep its disk |
| `devkit rm [-f]` | Delete the VM |
| `devkit ls` | List devkit VMs |
| `devkit doctor` | Check the host |

## How it works

- One Lima instance per project, `vmType: vz`, no host mounts, no sudo for the
  sandbox user beyond the three read-only commands Lima needs to confirm boot.
- A root-only provisioning script, regenerated from `devkit.yaml` on every boot,
  applies the firewall and starts the egress proxy. Code in the VM cannot change
  the policy because it has no root. Config values are validated against a
  strict grammar before they reach the script.
- The egress proxy is a small Go HTTP/CONNECT proxy embedded in the `devkit`
  binary. Root inside the VM copies the staged binary to a private location and
  installs it only if its SHA-256 matches the one recorded at provisioning time.
- In `allowlist` and `open` modes the firewall rejects every outbound packet
  except those from the proxy's user, DNS to the configured resolvers, and the
  host when `allow_host` is set. In `none` mode it rejects everything.

## What gets downloaded, and how it is verified

| Resource | Source | Verification |
|---|---|---|
| Ubuntu 24.04 Minimal cloud image | cloud-images.ubuntu.com, release pinned in `internal/lima/template.go` | SHA-256 digest pinned; Lima refuses a mismatch |
| Node.js | NodeSource apt repository for the configured major | apt signature check against NodeSource's key, which is embedded in devkit (fingerprint `6F71 F525 2828 41EE DAF8 51B4 2F59 B5F9 9B1B E0B4`). No remote script is run |
| apt packages | Ubuntu archives | Ubuntu's signing keys shipped in the image |
| Project dependencies | Whatever the lockfile says, inside the sandbox | Lockfile integrity hashes, enforced by `npm ci` and friends |
| devkit's own Go modules | proxy.golang.org | `go.sum`; `go mod verify` passes |
| Lima | Homebrew | Homebrew's bottle checksums |

Bump the image deliberately: update the release path and both digests together
from the `SHA256SUMS` file for that release.

## Project layout

```
cmd/devkit            CLI entry point
cmd/egressproxy       the proxy that runs inside the VM
internal/app          commands
internal/project      devkit.yaml schema and validation
internal/detector     Node.js version detection for devkit init
internal/lima         limactl wrapper and instance config rendering
internal/provision    scripts that run inside the VM (the security policy)
internal/egressproxy  proxy implementation
internal/embedded     embedded proxy binary
tests/e2e             creates a real VM and checks the guarantees
```

## License

MIT
