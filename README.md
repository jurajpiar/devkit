# devkit

One disposable virtual machine per project, so untrusted code and coding
agents can run without reaching your files, your services or the open
internet. macOS on Apple silicon, built on [Lima](https://lima-vm.io/).

> **Proof of concept.** Much of this code base was written with heavy AI
> assistance and has not had an independent review. Use with care until it is
> lifted out of PoC state, if ever. Expect rough edges; see
> [SECURITY.md](SECURITY.md) for what is and is not guaranteed.

## What you get

**Your Mac is out of reach.** A pull request's `npm install`, a Cargo build
script or an agent with shell access runs in its own Ubuntu VM with no shared
folders, no route to your Mac and no sudo. Files go in, never out: devkit has
no code path that copies anything from the VM to your Mac. The worst case is
a trashed VM, which `devkit rm` deletes.

**The internet is allowlisted and logged.** Only the hosts you name are
reachable. Every connection leaves through one proxy, which writes the host
to a log you can read with `devkit logs`. Nothing else can open a connection,
because the firewall only lets the proxy's own user out. One flag air-gaps the
machine once dependencies are in.

**Toolchains and dependencies are pinned.** Node, Go, Rust, Python, Ruby and
Java are installed by [mise](https://mise.jdx.dev) from a release devkit pins
by hash, checked against upstream signatures where they exist, and then locked
to the exact checksums seen on first install. Dependencies come from the
lockfile and nothing newer. Prefer Nix? `--toolchain nix` uses a `flake.nix`
instead.

**It works like a normal machine.** `devkit init` reads your version files and
writes one YAML file. `devkit up` builds the VM in about a minute. VS Code,
Cursor and Zed connect over SSH, and ports your app listens on appear on
`127.0.0.1`.

## Quick start

```bash
brew install lima
git clone https://github.com/jurajpiar/devkit.git && cd devkit
make install                # builds into ~/.local/bin; pass BINDIR=... to change
devkit doctor               # checks Lima, the proxy binary and the host

cd ~/code/some-project
devkit init                 # detects the languages used, writes devkit.yaml
devkit up                   # creates the VM, copies the code in, installs toolchains and dependencies
devkit shell                # a shell inside the VM, in ~/workspace
devkit logs                 # every host the sandbox tried to reach, allowed or blocked
devkit rm                   # delete the VM and everything in it
```

The first `devkit up` downloads the Ubuntu image (about 220 MB, checked
against a pinned digest), provisions the machine and installs the toolchains,
which takes a few minutes. After that, `up` takes seconds. Edit `devkit.yaml`
and run `devkit up` again to apply changes; the VM restarts if it has to.

Shell completion comes from `devkit completion`:

```bash
devkit completion fish > ~/.config/fish/completions/devkit.fish
devkit completion zsh > "${fpath[1]}/_devkit"        # or: eval "$(devkit completion zsh)"
```

To work from an IDE, connect with Remote-SSH to the host `devkit-<name>`.
devkit maintains that entry in `~/.ssh/config`, and `devkit connect` prints
the steps. Building from source needs Go 1.23 or newer; `make install` also
cross-compiles the proxy that runs inside the VM.

## How it works, in one picture

```mermaid
sequenceDiagram
    participant Mac as Your Mac
    participant Code as Project code<br/>in the VM
    participant Proxy as Allowlist proxy<br/>in the VM
    participant FW as Firewall<br/>in the VM
    participant Net as Internet

    Mac->>Code: ssh (the only way in)

    Code->>Proxy: fetch registry.npmjs.org
    Note over Proxy: on the list, logged ALLOWED
    Proxy->>FW: connect as the proxy's user
    FW->>Net: accepted
    Net-->>Code: response

    Code->>Proxy: fetch evil.example
    Note over Proxy: not on the list, logged BLOCKED
    Proxy-->>Code: 403

    Code->>FW: connect directly, skipping the proxy
    FW-->>Code: rejected

    Code->>FW: connect to your Mac
    FW-->>Code: rejected

    Code->>FW: DNS query
    FW->>Net: accepted, to the VM's resolvers only
```

Three things make this hold. The VM has no shared folders and no sudo, so the
code sees an empty Ubuntu machine. A firewall written by root at boot lets
only the proxy's own user open connections, so a program that ignores the
proxy settings is rejected rather than let out. And the proxy decides by
hostname and logs every attempt, which is what `devkit logs` shows. It does
not inspect content; TLS passes through untouched. DNS is the one direct
exception: the VM may query its configured resolvers, so a determined program
can tunnel data through DNS. `none` mode closes that too by rejecting
everything, DNS included.

To see this for yourself rather than take it on trust, `examples/hostile-project`
is a project whose code tries to break out and reports, line by line, whether
each attempt was stopped. Run it, then loosen `devkit.yaml` and watch the
boundary give way exactly where you told it to.

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

**Dependencies** are installed from whichever lockfile is present and from
nothing else: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install
--frozen-lockfile`, `go mod download`, `cargo fetch --locked`, `uv sync
--frozen`, `bundle install`, and so on. Set `install:` when the guess is wrong.
A Node project without a lockfile gets `npm install` and a reminder to commit
the result.

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
| Pinning | `mise.lock` inside the VM, written on the first `up` | `flake.lock`, commit it | Ubuntu release |
| Download verification | Upstream checksums and signatures where published; GitHub attestations for Python and Ruby builds; `rustup-init` is unverified | Every store path checked against the cache's signing key; every input hashed in `flake.lock` | apt signatures |
| Disk per VM | A 30 MB binary plus each toolchain | A few hundred MB for Nix plus each toolchain's own closure | Nothing extra |
| Learning curve | None | You will edit `flake.nix` eventually | None |

**mise.** Root installs a pinned, hash-checked mise release at boot and
locks its settings in `/etc/mise/config.toml`: plugin backends (asdf, vfox)
are disabled because they are unreviewed shell scripts, provenance is checked
on every install, and releases younger than three days are skipped. The
sandbox user then installs `tools.versions` through the audited proxy. The
first `devkit up` records every download's URL and checksum in the VM's
`mise.lock`; every later `up` installs with `--locked` and refuses anything
else. Change a version and run `devkit up --relock`. The lock lives and dies
with the VM, because devkit never copies anything from the VM to your Mac. A
`mise.toml` or `.nvmrc` in the repository layers on top, as mise normally
does.

**nix.** Root installs a pinned, hash-checked multi-user Nix once; the daemon
fetches through the proxy, so `devkit logs` shows it. `devkit init --toolchain
nix` writes a `flake.nix` with a dev shell for the toolchains it detected,
unless the repo already has one. `devkit up` evaluates it, and `devkit shell`
drops you into `nix develop`. Commit a `flake.lock` from the host (`nix flake
lock`) when you want the inputs pinned for everyone; the one the VM writes
stays in the VM. IDE terminals over SSH are not inside the dev shell; run
`nix develop` there.

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
| `devkit down [name]` | Stop the VM, keep its disk |
| `devkit rm [-f] [name]` | Delete the VM. Without a name, the current project's; completion lists the devkit VMs |
| `devkit ls` | List devkit VMs |
| `devkit doctor` | Check the host |

## Under the hood

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
| Toolchains via mise | nodejs.org, dl.google.com, GitHub releases, as mise documents per tool | mise's per-tool checks (Node: `SHASUMS256.txt` plus OpenPGP; Go: published `.sha256`; Python, Ruby: GitHub attestations), then pinned by URL and checksum in the VM's `mise.lock` |
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

## Roadmap

- `devkit cp vm:path dest`: an explicit, user-initiated way to pull a file
  out of the VM, such as a build artefact or a test report. devkit itself will
  still never write to the host on its own; whatever comes out is treated as
  untrusted data, and you name both paths.
- Escape tests for `source: mount`, including a read-only mount refusing
  writes, in a VM of their own.
- `nix develop` for IDE terminals over SSH, probably through direnv.
- Rust toolchain verification: pin `rustup-init` by hash in devkit until mise
  verifies it.
- Foundry as a first-class, hash-pinned install for Solidity projects.

## License

MIT
