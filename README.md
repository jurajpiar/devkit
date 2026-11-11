# devkit

devkit runs each project in a disposable Ubuntu virtual machine on your Mac. It
is designed for untrusted code and coding agents, with controls over host access
and outbound network traffic. It uses [Lima](https://lima-vm.io/) and requires
macOS on Apple silicon.

> **Proof of concept.** Much of the code was written with AI assistance and
> has not had an independent review. Expect rough edges and read the
> [security model](SECURITY.md) before relying on its protections.

## What you get

- **An isolated workspace.** By default, the VM has no shared host folders,
  no general sudo access and no access to services on your Mac. Delete it
  with `devkit rm` when you are finished.
- **Controlled network access.** Project traffic goes through an allowlist
  proxy. `devkit logs` shows the hosts it allowed or blocked. You can disable
  outbound access after installing dependencies.
- **Managed toolchains.** [mise](https://mise.jdx.dev) installs language
  toolchains and locks their download checksums after the first install.
  `--toolchain nix` uses a `flake.nix` instead. Dependency installation uses
  project lockfiles where available.
- **Reviewed pushes.** `devkit clone` fetches a repository without checking
  it out on your Mac, and `devkit push` pushes commits made in the VM from
  your Mac, after you review them. The VM never holds your credentials.
- **Familiar tools.** Use a shell or connect VS Code, Cursor or Zed over SSH.
  Ports you list in `network.forward` are exposed on your Mac's `127.0.0.1`.

Start with [Quick start](#quick-start) or the ten-minute
[walkthrough](docs/walkthrough.md), which covers a checkout you already have
(`devkit init`) and a repository you do not have yet (`devkit clone`) through
to a pull request. Then see
[Configuration](#configuration), [Toolchains](#toolchains) or the [command
reference](#commands). Contributors can use the [contributing
guide](CONTRIBUTING.md).

## Quick start

You need Go 1.23 or newer to build from source. `make install` also builds the
proxy that runs inside the VM.

```bash
brew install lima
git clone https://github.com/jurajpiar/devkit.git && cd devkit
make install                # builds into ~/.local/bin; pass BINDIR=... to change
devkit doctor               # checks Lima, the proxy binary and the host

cd ~/code/some-project
devkit init                 # detects the languages used, writes devkit.yaml
devkit up                   # creates the VM and installs the project
devkit shell                # a shell inside the VM, in ~/workspace
devkit logs                 # every host the sandbox tried to reach, allowed or blocked
devkit rm                   # delete the VM and everything in it
```

The first `devkit up` downloads the Ubuntu image (about 220 MB, checked against
a pinned digest), provisions the machine and installs the toolchains, which
takes a few minutes. After that, `up` takes seconds. Edit `devkit.yaml` and run
`devkit up` again to apply changes; the VM restarts if it has to.

If provisioning fails, `up` names the failed step, stops the VM and exits with a
non-zero status. Fix the cause and run it again. `devkit shell` and `devkit
sync` refuse to use a VM whose provisioning did not finish.

Shell completion comes from `devkit completion`:

```bash
devkit completion fish > ~/.config/fish/completions/devkit.fish
devkit completion zsh > "${fpath[1]}/_devkit"        # or: eval "$(devkit completion zsh)"
```

To start from a repository rather than a directory on your Mac:

```bash
devkit clone github.com/org/repo   # bare clone on the Mac: no project file is written out
cd repo && devkit up               # the VM checks the files out
devkit push                        # later: review the VM's commits, then push them from the Mac
```

To work from an IDE, connect with Remote-SSH to the host `devkit-<name>`. devkit
maintains that entry in `~/.ssh/config`, and `devkit connect` prints the steps.

## How it works

```mermaid
sequenceDiagram
    participant Mac as Your Mac
    participant Code as Project code<br/>in the VM
    participant Proxy as Allowlist proxy<br/>in the VM
    participant FW as Firewall<br/>in the VM
    participant Net as Internet

    Mac->>Code: ssh, the way in (plus ports you list in network.forward)

    Code->>Proxy: fetch registry.npmjs.org
    Note over Proxy: on the list, logged ALLOWED
    Proxy->>FW: resolve the name and connect, as the proxy's user
    FW->>Net: accepted
    Net-->>Code: response

    Code->>Proxy: fetch evil.example
    Note over Proxy: not on the list, logged BLOCKED
    Proxy-->>Code: 403

    Code->>FW: connect directly, skipping the proxy
    FW-->>Code: rejected

    Code->>FW: connect to your Mac
    FW-->>Code: rejected

    Code->>FW: DNS query, data hidden in the name
    FW-->>Code: rejected, only the proxy resolves names
```

The default setup has three layers:

1. **A separate VM.** Project code runs in Ubuntu without shared host folders
   or general sudo access.
2. **A firewall.** Only the proxy's account may open outbound connections.
   Programs that ignore the proxy settings are blocked. On later boots, a
   temporary network block protects the sandbox until the firewall is ready.
3. **An allowlist proxy.** It checks hostnames and logs each request. It does
   not inspect the content of TLS connections.

By default, only the proxy can resolve DNS names. `dns: resolvers` lets the
whole VM use DNS, which also allows code to send data through query names.
`none` mode blocks outbound traffic, including DNS, unless you explicitly allow
host access.

The [hostile project example](examples/hostile-project/README.md) demonstrates
these controls and reports whether each attempted escape was blocked.

## Security at a glance

By default, project code runs without shared host folders or general sudo
access. It can reach allowed hosts only through the logged proxy. Root inside
the VM can remove those guest controls; the VM boundary still separates the
guest kernel from your Mac.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/escape-map-dark.svg">
  <img alt="Ten escape attempts, each stopped at the layer that blocks it, and the one allowed path: HTTPS to an allowed host on port 443, logged" src="docs/escape-map-light.svg">
</picture>

The [escape-test reference](docs/escape-tests.md) lists each attempted escape,
its control, its tests and the conditions under which it can still succeed. The
[security model](SECURITY.md) explains the remaining risks.

### Enforcement on the Mac: `network.enforce: host`

This opt-in mode also enforces the network policy on your Mac, so guest root
cannot remove it. Lima's host agent runs under a macOS sandbox profile and sends
outbound requests through a devkit proxy on the Mac. It needs no root access on
the Mac. `devkit logs` reads the host proxy's log; requests blocked by the guest
proxy remain in the guest log.

Host enforcement is new and uses Apple's deprecated `sandbox-exec`. devkit
refuses to start in this mode if the required support is missing. It cannot be
combined with `allow_host: true`, `dns: resolvers` or `mode: none`. Always start
the VM through devkit: a manual `limactl start` bypasses the profile. If an
outbound firewall such as LuLu blocks the host proxy, allow the `devkit` binary
there.

See [host enforcement](SECURITY.md#enforcement-on-the-mac-networkenforce-host)
for the full policy, provisioning exceptions and untested paths.

### Reviewing code from the VM

`devkit push` imports a checked Git bundle, shows a review and asks before
pushing with your Mac's credentials (`--yes` skips the prompt). Read the changes
carefully: pushed code can run in CI or in your local checkout, and commit
authorship does not prove who wrote it. See [Git review and
credentials](SECURITY.md#git-review-and-credentials).

### Responding to a kernel crash

From the VM's first restart, devkit reads guest kernel crash reports from Lima's
serial log on the Mac. Commands warn about unacknowledged reports; `devkit
audit` exits with status 1 even if the VM is stopped.

If you cannot explain a crash, discard the VM with `devkit rm`. Otherwise,
acknowledge it with `devkit audit --ack-crashes`. A crash may be a failed
exploit or an ordinary bug. The absence of a crash report does not prove the VM
is safe. See [kernel crash
reports](SECURITY.md#kernel-crash-reports-read-on-the-mac).

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
# services: [postgres]  # PostgreSQL 16 in the VM, no Docker; see Services

vm:
  cpus: 4
  memory_gb: 8
  disk_gb: 50
  # security_updates: true   # apply Ubuntu's security pocket at every boot
  # lock_modules: true   # no kernel module loads after provisioning, root included, until restart

ssh_port: 2222

network:
  mode: allowlist       # allowlist | open | none
  allow:
    - registry.npmjs.org
    - github.com
    - "**.github.com"
  allow_host: false     # reach services on your Mac
  # dns: proxy          # proxy (only the proxy resolves names) | resolvers
  # forward: [3000]     # guest ports exposed on 127.0.0.1; nothing otherwise
  # distrust: [AAA Certificate Services]   # root CAs the VM must not trust
  # enforce: guest      # guest | host: the Mac enforces egress too (Enforcement on the Mac, above)

# exclude: [.git, node_modules]   # never copied into the VM (defaults apply)
# mount_writable: false           # source: mount only; lets the sandbox edit your files
# sudo: false                     # root inside the VM can disable the firewall
```

### Source methods

| `source` | What happens | Notes |
|---|---|---|
| `copy` | The directory is synced into the VM on `up` and `sync`: what changed on the Mac arrives, what changed in the VM is kept | Default. Nothing is copied back to your working tree. A git checkout gets a `.git` like a fresh clone's, see below. |
| `git` | `devkit clone <url>` creates a bare clone on the Mac; the VM checks out the files | Supports private repositories. `sync` fetches on the Mac and fast-forwards the VM. |
| `mount` | The directory is mounted read-only | Opt in. `mount_writable: true` lets the sandbox edit your files. |

If you use `devkit init <url>` instead of `devkit clone`, there is no bare clone
on the Mac. In that case, the VM clones a public repository through the proxy.

### Git in a copied project

Your host `.git` directory is never copied. If the project directory is the root
of a Git checkout, devkit creates a separate repository in the VM with:

- Your current commit and branch, without earlier history, other branches,
  tags, stash or reflog.
- An `origin` remote with any embedded token removed.
- None of your host Git hooks or `.git/config`.

Uncommitted changes arrive as working-tree changes. You can use `git status`,
`git diff` and `git commit`, and run tools such as husky inside the VM. Later
syncs preserve the VM's repository because it may contain new commits. Files in
the copied commit are included even if `exclude` names them.

Each sync records the directory, exactly as `tar` with your `exclude` list
sends it, as a snapshot in a private repository in `~/.devkit/<vm>/sync.git`,
never your own repository and never in the project directory, which gains
nothing; `devkit rm` deletes it with the VM. The VM merges the change
from the last snapshot it took, the way `git checkout` carries local edits
across a branch switch:

- A file changed only on the Mac is updated, or deleted if you deleted it.
- A file changed only in the VM is kept, committed or not, and `sync` lists
  it. So is anything the VM made that the Mac does not have, such as
  `node_modules` or build output.
- A file changed on both sides, or a file the Mac adds where the VM already
  made a different one, stops the sync: nothing is applied and the files are
  listed. `devkit sync --overwrite` takes the Mac's version of exactly those
  files. `devkit up` reports the same and comes up without syncing.

Only what the VM lacks is sent. Bytes are copied as they are on disk: no
`.gitattributes`, filters or line-ending conversion apply, on either side,
and none of your git config or hooks are used. Modes, symlinks and empty
directories follow the Mac. Unchanged files are not rewritten; a changed file
gets the time of the sync. Named pipes and device files are not copied and
are reported. The project's own repository in the VM is a separate matter:
the sync never touches it, so after a sync it sees the Mac's changes as
uncommitted changes.

### Cloning a repository

`devkit clone https://github.com/org/repo` creates a `repo/` directory with
`devkit.yaml` and a bare, one-commit clone in `.devkit/repo.git`. The shorthand
`devkit github.com/org/repo` does the same thing.

Cloning uses your Mac's Git credentials, so private repositories work. No
project files are checked out on the Mac: devkit detects languages from Git
objects, and the VM checks out the files on `devkit up`.

Only HTTPS and SSH are accepted for clones and redirects. `git://` URLs are
rewritten to `https://`. For a project created with `devkit clone`, `devkit
sync` fetches upstream commits on the Mac and passes them into the VM; the VM
does not need to contact the remote.

### Pushing from the VM

Use `devkit push` to publish work without giving the VM your credentials:

1. The VM writes a Git bundle of the branch.
2. Git on your Mac checks every object and rejects malformed data, such as a
   tree containing a `.git` entry.
3. devkit stores the branch under `refs/devkit/<project>/<branch>`, outside
   your local branches and working tree.
4. The review shows commits, authors, a diffstat and changed files that may
   run outside the VM: CI workflows, hooks, editor tasks, `.envrc`,
   `package.json` scripts and task runners.
5. After confirmation, your Mac pushes with your normal credentials.
   `--yes` skips the confirmation prompt.

No Git hooks run on the Mac during the push. A pre-push hook such as husky's
would execute project code there; hooks belong inside the VM.

Pushes do not force by default. `--force-with-lease` replaces the remote branch
only if it has not changed since your review. VM commits are unsigned; branches
that require signatures need those commits re-signed on the Mac. See [Git review
and credentials](SECURITY.md#git-review-and-credentials) for the risks of
publishing or checking out code written in the VM.

### Network modes

| `mode` | Outbound traffic | Use |
|---|---|---|
| `allowlist` | Only hosts in `allow`, via the audited proxy; the firewall rejects everything else | Default |
| `open` | Any host, via the audited proxy; the firewall still rejects direct connections | Trusted code, want the log |
| `none` | Nothing, not even DNS | Air-gap after dependencies are installed: `devkit up --network none` |

Allowed hosts are hostnames: `example.com` exact, `*.example.com` one level,
`**.example.com` any depth. An entry allows the web ports, 80 and 443, and
nothing else on that host; `host:port` allows exactly one other port. Anything
else is rejected at validation. By default only the proxy may resolve names: it
looks up allowed hosts itself, and the sandbox cannot send a DNS query at all,
so a query name cannot carry data out. `dns: resolvers` reopens DNS to the whole
VM for tools that resolve a name before they use the proxy.

Lima forwards only the ports listed in `network.forward`. An IDE may also create
its own SSH tunnels, independently of this setting. A page served from the
sandbox and opened in your browser would run with the browser's unrestricted
network, so forwarding is opt-in per port.

With `allow_host: true`, project code can reach the Mac directly at
`host.lima.internal`, bypassing the proxy and its log. This also opens a path to
host services in `none` mode, including any DNS resolver on the host.

### Kernel updates and restrictions

The guest applies Ubuntu's security updates on every boot, before the firewall
comes up, so a VM does not stay at its image's patch level. Expect the cost on
the first boot after a kernel update lands: `devkit up` took about a minute
longer than usual the day one did (1 m 45 s against 46 s). Later boots only
check for updates and take seconds. The new kernel is installed to disk and runs
from the next boot. `devkit up` does not reboot a VM whose configuration is
unchanged, so run `devkit down && devkit up` to boot into a new kernel; the boot
that installed it says so. `vm.security_updates: false` turns the step off;
`devkit up --no-security-updates` writes that for you, so the next boots are
quick again and the VM says so in its policy stamp.

Two additional controls reduce the kernel features available to project code.
Unprivileged user namespaces are refused outright
(`kernel.unprivileged_userns_clone = 0`), including to the programs Ubuntu's
AppArmor profiles exempt, such as `rootlesskit` or `podman` installed from
`tools.packages`; root is unaffected. `containers: true` leaves them open, under
AppArmor's restriction alone, because rootless containerd needs them. Kernel
module loading is locked, for root too, as the last step of provisioning, after
the firewall is up and what the configuration needs is loaded; every boot locks
it again. A tool that needs a module nothing loaded beforehand then fails; set
`vm.lock_modules: false` for that project.

### Trust and image audits

The VM trusts what Ubuntu's `ca-certificates` package trusts, refreshed by root
on every boot, so a VM created before a CA was removed upstream catches up on
its next start. `network.distrust` names roots to remove on top of that, for the
cases where the distro lags the browsers. Runtimes that bring their own root
list (Node, Python's certifi, pip, curl) are pointed at the system bundle
instead, so both the distro's updates and your `distrust` list apply to them.
`devkit up` ends with a short trust audit; `devkit audit --deep` scans every
file. See the [audit details](SECURITY.md#tls-trust-and-certificate-audits) for
its limits.

The audit also lists container images the project does not pin by digest. It
reads every `image:` in the compose files (`compose.yaml`,
`docker-compose.*.yml` and the like, with their `.env`) and every `FROM` and
`COPY --from` in Dockerfiles and Containerfiles, so it needs no Docker. A
reference counts as pinned only with `@sha256:` and a 64-character digest; a tag
or a bare name is unpinned, because the same tag can be different code tomorrow.
A reference whose variable has no value devkit can see, such as `${IMAGE:?}` or
a build `ARG` without a default, is reported as unresolved rather than assumed
fine. This part is a report: unpinned or unresolved images do not change `devkit
audit`'s exit status.

### Dependencies

Dependencies are installed using the detected lockfile: `npm ci`, `pnpm install
--frozen-lockfile`, `yarn install --frozen-lockfile`, `go mod download`, `cargo
fetch --locked`, `uv sync --frozen`, `bundle install`, and so on. Set `install:`
when the guess is wrong. A Node project without a lockfile gets `npm install`
and a reminder to commit the result.

### Services

Services run databases inside the VM without a container engine and without
anything on your Mac. `services: [postgres]` gives Ubuntu's PostgreSQL 16 with a
role and database `dev`, password `dev`, on port 5432:
`postgres://dev:dev@127.0.0.1:5432/dev`. Set any of them per project:

```yaml
services:
  postgres:
    port: 5433
    user: vaults
    password: password
    database: vaults
```

Root installs the package at provisioning and tells Ubuntu not to create a
cluster of its own. The cluster belongs to the sandbox user, lives in
`~/.local/share/devkit/postgres`, and runs as a systemd user unit that starts at
boot. It listens only on the VM's 127.0.0.1, so nothing outside the VM can reach
it unless you add the port to `network.forward`, and it makes no connections of
its own. The sandbox user administers it over a local socket (`psql -h
$XDG_RUNTIME_DIR -p 5433 -d postgres`); the app logs in over TCP as the role
above. The password is for development inside the VM: the only thing that can
reach the port is the sandbox itself. Remove the service from `devkit.yaml` and
the next `devkit up` stops it and keeps the data.

### Containers

Containers are opt-in. With `containers: true` the VM gets rootless containerd
and `nerdctl` for databases and services. It also leaves unprivileged user
namespaces open, which rootless containerd needs, and loads the bridge, overlay
and netfilter modules containers use before module loading is locked.

## Toolchains

`tools.manager` decides how language toolchains get into the VM. `devkit init`
picks `mise` unless `--toolchain` or `DEVKIT_TOOLCHAIN` says otherwise, and
seeds versions from the files it finds: `.nvmrc`, `engines.node`, `go.mod`,
`rust-toolchain.toml`, `.python-version`, `.ruby-version`, `.java-version`. A
Bun project, one with `bun.lock`, `.bun-version`, `bunfig.toml` or
`packageManager: "bun@..."`, gets Bun, beside Node when it has a `package.json`,
and its dependencies install with `bun install --frozen-lockfile`. An `engines`
range seeds its lower bound only when that bound is inclusive, otherwise the
default.

| Feature | `mise` | `nix` | `none` |
|---|---|---|---|
| What you edit | `tools.versions` in `devkit.yaml` | `flake.nix` in the repo | `tools.packages` |
| Languages | Node, Go, Python, Ruby, Rust, Java, Zig, Bun, Deno, and CLIs from the aqua registry | Everything in nixpkgs | Whatever Ubuntu 24.04 ships |
| Pinning | `mise.lock` inside the VM, written on the first `up` | `flake.lock`, commit it | Ubuntu release |
| Download verification | Upstream checksums and signatures where published; GitHub attestations for Python and Ruby builds; `rustup-init` is unverified | Every store path checked against the cache's signing key; every input hashed in `flake.lock` | apt signatures |
| Disk per VM | A 30 MB binary plus each toolchain | A few hundred MB for Nix plus each toolchain's own closure | Nothing extra |
| Learning curve | None | You will edit `flake.nix` eventually | None |

### mise

Root installs a pinned, hash-checked mise release at boot and locks its settings
in `/etc/mise/config.toml`: plugin backends (asdf, vfox) are disabled because
they are unreviewed shell scripts, provenance is checked on every install, and
releases younger than three days are skipped. The sandbox user then installs
`tools.versions` through the audited proxy. The first `devkit up` records every
download's URL and checksum in the VM's `mise.lock`; every later `up` installs
with `--locked` and refuses anything else. Change a version and run `devkit up
--relock`. The lock lives and dies with the VM, because devkit does not export
it to your Mac. A `mise.toml` or `.nvmrc` in the repository layers on top, as
mise normally does.

### Nix

Root installs a pinned, hash-checked multi-user Nix once; the daemon fetches
through the proxy, so `devkit logs` shows it. `devkit init --toolchain nix`
writes a `flake.nix` with a dev shell for the toolchains it detected, unless the
repo already has one. `devkit up` evaluates it, and `devkit shell` drops you
into `nix develop`. Commit a `flake.lock` from the host (`nix flake lock`) when
you want the inputs pinned for everyone; the one the VM writes stays in the VM.
IDE terminals over SSH are not inside the dev shell; run `nix develop` there.

### System packages (`none`)

Only `tools.packages` from apt. Right for C and C++ projects, where
`build-essential`, `cmake` and `clang` from Ubuntu are usually what you want,
and for anything else you would rather install by hand with `install:`.

Rust is the weak spot in every column: `rustup-init` is fetched without a
signature check by mise, and nixpkgs' `rustc` is fine but `rustup` is not there.
Java through mise checks a catalogue checksum only; prefer `packages:
[openjdk-21-jdk]` under `none` or `mise` when that matters. Solidity tooling is
covered by npm (Hardhat) and by `binaries.soliditylang.org` for solc, which both
Hardhat and Foundry verify; install Foundry with `install:` and pin its version.

## Commands

| Command | Description |
|---|---|
| `devkit clone <url> [dir]`, `devkit <url>` | New project from a repository, without checking it out on the Mac. `git://` becomes `https://`. Flags: `--branch`, `--name`, `--toolchain`, `--node`, `--network` |
| `devkit init [repo-url]` | Write `devkit.yaml`. Flags: `--name`, `--toolchain`, `--node`, `--network`, `--force` |
| `devkit up` | Create or start the VM, sync source, install toolchains and dependencies. Flags: `--network`, `--no-sync`, `--no-install`, `--relock`, `--no-security-updates` |
| `devkit shell [cmd]` | Shell in the VM, or run a command |
| `devkit sync` | Bring the Mac's changes in and keep the VM's; stops if a file changed on both sides (`--overwrite` takes the Mac's). For a cloned project, fetch upstream on the Mac and fast-forward the VM |
| `devkit push [branch]` | Review commits made in the VM and push them from your Mac with your own credentials. Flags: `--remote`, `--to`, `--yes`, `--force-with-lease` |
| `devkit logs [-f] [-n N]` | Egress audit log; under `network.enforce: host`, the host proxy's log on the Mac |
| `devkit connect` | IDE connection instructions |
| `devkit down [name]` | Stop the VM, keep its disk |
| `devkit rm [-f] [name]` | Delete the VM. Without a name, the current project's; completion lists the devkit VMs |
| `devkit ls` | List devkit VMs |
| `devkit doctor` | Check the host |
| `devkit audit [--deep]` | Report roots the VM, its runtimes or the project trust that Mozilla no longer does, container images not pinned by digest, and the guest kernel's crash reports. `--ack-crashes` acknowledges those |

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
  except permitted proxy traffic, DNS according to `network.dns`, and
  host traffic when `allow_host` is set. In `none` mode it rejects outbound
  traffic except explicitly allowed host access.
- Under `network.enforce: host` the proxy's user may reach only the host
  proxy at `192.168.5.2:<port>`, there is no DNS for anyone, and
  `limactl start` runs under the profile in `~/.devkit/<vm>/network.sb`. The
  host proxy's port, pid, allowlist and log live in the same directory. With
  a `LIMA_HOME` other than `~/.lima` it is `~/.devkit/<vm>-<hash>/`, the hash
  taken from that Lima home, so VMs of the same name under two Lima homes
  keep separate proxies.

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
internal/gitx         git on the Mac: bare clones, bundles from the VM, the push review
internal/lima         limactl wrapper and instance config rendering
internal/provision    scripts that run inside the VM (the security policy)
internal/egressproxy  proxy implementation
internal/hostenforce  the macOS sandbox profile for network.enforce: host
internal/embedded     embedded proxy binary
internal/fakelima     a stand-in limactl for unit tests
tests/e2e             creates a real VM and checks the guarantees
examples/hostile-project   a project that tries to break out and reports each attempt
docs/walkthrough.md   from a checkout or a URL to a pull request, step by step
docs/escape-tests.md  the escape attempts and the tests that check them
```

## Roadmap

- `devkit cp vm:path dest`: an explicit, user-initiated way to pull a file
  out of the VM, such as a build artefact or a test report. Today the only
  thing that leaves is git commits through `devkit push`; this would add
  files, still only when you ask, treated as untrusted data, with both paths
  named by you.
- Escape tests for `source: mount`, including a read-only mount refusing
  writes, in a VM of their own.
- `nix develop` for IDE terminals over SSH, probably through direnv.
- Rust toolchain verification: pin `rustup-init` by hash in devkit until mise
  verifies it.
- Foundry as a first-class, hash-pinned install for Solidity projects.
- An opt-in inner sandbox (gVisor) that runs project processes behind a
  userspace kernel, so a guest kernel exploit meets it before the real kernel.
  Defence in depth against the one case the VM boundary does not cover, a
  privilege escalation reaching the host's loopback; see SECURITY.md for the
  trade-offs.

## Licence

MIT
