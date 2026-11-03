# devkit

Disposable sandbox VMs for untrusted code and coding agents, on macOS.

Every project gets its own virtual machine on Apple's hypervisor. The VM cannot
see your files, cannot reach services on your Mac, and can only talk to the
hosts you allow. Every outbound connection goes through an audited proxy. When
you are done, delete the machine.

> **Proof of concept.** Much of this code base was written with heavy AI
> assistance and has not had an independent review. Use with care until it is
> lifted out of PoC state, if ever. Expect rough edges; see
> [SECURITY.md](SECURITY.md) for what is and is not guaranteed.

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

`make install` copies the binary to `~/.local/bin`; no sudo is needed, but make
sure that directory is on your `PATH`. Pass `BINDIR=/some/dir` to install
elsewhere. A plain `go build` also works; devkit then builds the proxy with
your Go toolchain on first use.

## Use

```bash
cd my-project
devkit init         # detects the languages used, writes devkit.yaml
devkit up           # creates the VM, copies the code in, installs toolchains and dependencies
devkit shell        # shell inside the VM, in ~/workspace
devkit logs         # every host the sandbox tried to reach, allowed or blocked
devkit rm           # delete the VM and everything in it
```

The first `devkit up` downloads the Ubuntu image (about 220 MB, checked
against a pinned digest), provisions the machine and installs the toolchains
from `tools.versions`, which takes a few minutes. After that, `up` takes
seconds.

Dependencies are installed from whichever lockfile is present and from nothing
else: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install
--frozen-lockfile`, `go mod download`, `cargo fetch --locked`, `uv sync
--frozen`, `bundle install`, and so on. Set `install:` in `devkit.yaml` when
the guess is wrong. A Node project without a lockfile gets `npm install` and a
reminder to commit the result.

To work from VS Code or Cursor, use the Remote-SSH extension and connect to
`devkit-<name>`. devkit maintains the entry in `~/.ssh/config`; `devkit
connect` prints the steps. Ports your app listens on inside the VM appear on
`127.0.0.1` on your Mac automatically.

## How traffic leaves the VM

```mermaid
flowchart LR
    subgraph host["macOS host"]
        you["you, IDE"]
        svc["services on your Mac"]
    end
    subgraph vm["sandbox VM (Lima, vz)"]
        user["sandbox user<br/>shell, npm, coding agents"]
        proxy["egress proxy<br/>runs as devkit-proxy<br/>allowlist check, logs every host"]
        fw["iptables OUTPUT<br/>written by root at boot"]
    end
    net(("internet"))
    blocked["rejected"]

    you -- "ssh 127.0.0.1:port" --> user
    user -- "HTTP_PROXY / HTTPS_PROXY" --> proxy
    user -. "direct connection" .-> fw
    proxy --> fw
    fw -- "from devkit-proxy: ACCEPT" --> net
    fw -- "DNS to VM resolvers: ACCEPT" --> net
    fw -- "allow_host: true" --> svc
    fw -- "anything else: REJECT" --> blocked
```

The proxy decides by hostname and writes one line per connection to the log
that `devkit logs` shows. It does not inspect content; TLS passes through
untouched. A program that ignores the proxy variables is rejected by the
firewall rather than let out, because only the proxy's user may open outbound
connections. In `none` mode the firewall rejects everything, including DNS.

## Configuration

`devkit init` writes this file. Edit it and run `devkit up` again to apply; the
VM restarts if the change needs it.

```yaml
name: my-project
source: copy            # copy | git | mount
# repo: https://github.com/you/repo.git   # for source: git
# branch: main

tools:
  manager: mise         # mise | nix | none, see Toolchains below
  versions:             # mise tool: version, seeded by devkit init
    node: "22"
    go: "1.27"
  containers: false     # rootless containerd + nerdctl inside the VM
  packages: [pkg-config]  # extra apt packages

# install: make deps    # replaces the lockfile-based install devkit picks

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

## Toolchains

`tools.manager` decides how language toolchains get into the VM. `devkit init`
picks `mise` unless `--toolchain` or `DEVKIT_TOOLCHAIN` says otherwise, and
seeds versions from the files it finds: `.nvmrc`, `engines.node`, `go.mod`,
`rust-toolchain.toml`, `.python-version`, `.ruby-version`, `.java-version`.

| | `mise` | `nix` | `none` |
|---|---|---|---|
| What you edit | `tools.versions` in `devkit.yaml` | `flake.nix` in the repo | `tools.packages` |
| Languages | Node, Go, Python, Ruby, Rust, Java, Zig, Bun, Deno, and CLIs from the aqua registry | Everything in nixpkgs | Whatever Ubuntu 24.04 ships |
| Pinning | `.devkit/mise.lock`, written by devkit on the first `up` | `flake.lock`, commit it | Ubuntu release |
| Download verification | Upstream checksums and signatures where published; GitHub attestations for Python and Ruby builds; `rustup-init` is unverified | Every store path checked against the cache's signing key; every input hashed in `flake.lock` | apt signatures |
| Disk per VM | A 30 MB binary plus each toolchain | A few hundred MB for Nix plus each toolchain's own closure | Nothing extra |
| Learning curve | None | You will edit `flake.nix` eventually | None |

**mise.** Root installs a pinned, hash-checked mise release at boot and
locks its settings in `/etc/mise/config.toml`: plugin backends (asdf, vfox)
are disabled because they are unreviewed shell scripts, provenance is checked
on every install, and releases younger than three days are skipped. The
sandbox user then installs `tools.versions` through the audited proxy. The
first `devkit up` records every download's URL and checksum in
`.devkit/mise.lock` beside `devkit.yaml`; every later `up` installs with
`--locked` and refuses anything else. Change a version and run `devkit up
--relock`. A `mise.toml` or `.nvmrc` in the repository layers on top, as mise
normally does.

**nix.** Root installs a pinned, hash-checked multi-user Nix once; the daemon
fetches through the proxy, so `devkit logs` shows it. `devkit init --toolchain
nix` writes a `flake.nix` with a dev shell for the toolchains it detected,
unless the repo already has one. `devkit up` evaluates it, and `devkit shell`
drops you into `nix develop`. If the repo had no `flake.lock`, the one from the
first evaluation is copied back for you to commit. IDE terminals over SSH are
not inside the dev shell; run `nix develop` there.

**none.** Only `tools.packages` from apt. Right for C and C++ projects, where
`build-essential`, `cmake` and `clang` from Ubuntu are usually what you want,
and for anything else you would rather install by hand with `install:`.

Rust is the weak spot in every column: `rustup-init` is fetched without a
signature check by mise, and nixpkgs' `rustc` is fine but `rustup` is not
there. Java through mise checks a catalogue checksum only; prefer
`packages: [openjdk-21-jdk]` under `none` or `mise` when that matters.
Solidity tooling is covered by npm (Hardhat) and by `binaries.soliditylang.org`
for solc, which both Hardhat and Foundry verify; install Foundry with
`install:` and pin its version.

## Commands

| Command | Description |
|---|---|
| `devkit init [repo-url]` | Write `devkit.yaml`. Flags: `--name`, `--toolchain`, `--node`, `--network`, `--force` |
| `devkit up` | Create or start the VM, sync source, install toolchains and dependencies. Flags: `--network`, `--no-sync`, `--no-install`, `--relock` |
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
- Toolchain managers are installed by root from release archives pinned by
  SHA-256 in `internal/provision/provision.go`. The toolchains themselves are
  installed by the sandbox user, through the proxy, so they show in the log.
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
| mise | GitHub release pinned in `internal/provision/provision.go` | SHA-256 pinned; the pin was taken from the release's `SHASUMS256.txt` after checking its GPG signature (fingerprint `2485 3EC9 F655 CE80 B48E 6C3A 8B81 C9D1 7413 A06D`). No install script is run |
| Toolchains via mise | nodejs.org, dl.google.com, GitHub releases, as mise documents per tool | mise's per-tool checks (Node: `SHASUMS256.txt` plus OpenPGP; Go: published `.sha256`; Python, Ruby: GitHub attestations), then pinned by URL and checksum in `.devkit/mise.lock` |
| Nix | releases.nixos.org, version pinned in `internal/provision/provision.go` | SHA-256 pinned, cross-checked against the hash in the official installer |
| Nix packages | cache.nixos.org, flake inputs | Nix verifies the cache's Ed25519 signature; `flake.lock` pins every input by hash |
| apt packages | Ubuntu archives | Ubuntu's signing keys shipped in the image |
| Project dependencies | Whatever the lockfile says, inside the sandbox | Lockfile integrity hashes, enforced by `npm ci` and friends |
| devkit's own Go modules | proxy.golang.org | `go.sum`; `go mod verify` passes |
| Lima | Homebrew | Homebrew's bottle checksums |

Bump the image deliberately: update the release path and both digests together
from the `SHA256SUMS` file for that release. Bump mise and Nix the same way:
verify the upstream signature, then change the version and both hashes.

## Project layout

```
cmd/devkit            CLI entry point
cmd/egressproxy       the proxy that runs inside the VM
internal/app          commands
internal/project      devkit.yaml schema and validation
internal/detect       language detection for devkit init
internal/lima         limactl wrapper and instance config rendering
internal/provision    scripts that run inside the VM (the security policy)
internal/egressproxy  proxy implementation
internal/embedded     embedded proxy binary
tests/e2e             creates a real VM and checks the guarantees
```

## License

MIT
