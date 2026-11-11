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
If provisioning fails (a package that does not exist, a mirror that cannot be
reached), `up` names the step that failed, stops the VM rather than leave it
running without its firewall, and exits non-zero; fix the cause and run it
again. `devkit shell` and `devkit sync` refuse a VM in that state.

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

Three things make this hold. The VM has no shared folders and no sudo, so the
code sees an empty Ubuntu machine. A firewall written by root at boot lets
only the proxy's own user open connections, so a program that ignores the
proxy settings is rejected rather than let out; on every restart, until that
firewall is in place, a boot hold stops the sandbox opening any connection at
all, loopback included. And the proxy decides by
hostname and logs every attempt, which is what `devkit logs` shows. It does
not inspect content; TLS passes through untouched. Names are the proxy's job
too: by default the sandbox cannot send a DNS query at all, so a query name
cannot carry data out. `dns: resolvers` reopens DNS to the whole VM, for tools
that resolve a name before they use the proxy, and that channel with it.
`none` mode rejects everything, DNS included.

To see this for yourself rather than take it on trust, `examples/hostile-project`
is a project whose code tries to break out and reports, line by line, whether
each attempt was stopped. Run it, then loosen `devkit.yaml` and watch the
boundary give way exactly where you told it to.

## How escapes are stopped

Every arrow is something a malicious dependency or a misbehaving agent can try
from inside the VM, as the sandbox user. It travels right, towards your Mac and
the internet, until the first component that refuses it. One arrow gets
through: the audited path to an allowed host.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/escape-map-dark.svg">
  <img alt="Ten escape attempts, each stopped at the layer that blocks it, and the one allowed path: HTTPS to an allowed host on port 443, logged" src="docs/escape-map-light.svg">
</picture>

Each stop is asserted by a test, most of them written red first: the escape
succeeded, then the design changed until it failed. The end-to-end suite
checks them on a real VM; the firewall rows are also checked in about a second
by `TestNetnsFirewall`, which loads the real rules into Linux network
namespaces, and the proxy rows by the proxy's unit tests. The third column is the part that matters when you read this as an
attacker: what it would still take to get through. Almost every answer is one
of four things, root in the guest, a loosening you chose in `devkit.yaml`, an
allowed host the attacker already controls, or a hypervisor escape.

| Attack vector | Stopped by | Still possible only if | Proven by |
|---|---|---|---|
| Direct connection to the internet | Firewall: only uid `devkit-proxy` may egress | Root in the guest flushes the firewall, or you set `sudo: true` | `direct connections bypassing the proxy are rejected`; `TestNetnsFirewall` |
| Proxy to another host, or to port 22 | Proxy: allowlist, ports 80 and 443 only | You list the host or port in `network.allow` or use `open` mode; or the attacker controls an allowed host, which the policy trusts by design | `allowed hosts are reachable on web ports only`; `TestProxyRefusesConnectToNonWebPort`, `TestHTTPAllowsOnlyWebPortsWithoutAPortEntry` |
| DNS query with data in the name | Firewall: port 53 only for the proxy's account; resolver stub off | You set `dns: resolvers`; or root in the guest; an allowed host the attacker controls makes DNS unnecessary anyway | `DNS is not a side channel`; `TestNetnsFirewall` |
| Send from a source port the proxy just used, riding its tracked DNS flow | Firewall: connection state is trusted only for root and the proxy; every other account may only reply on connections made to it | Root in the guest, or `sudo: true` | `DNS cannot ride another account's tracked connections`; `TestNetnsFirewall` |
| Connect to your Mac | Firewall: host rejected for every account, the proxy included | You set `allow_host: true`; or root in the guest, the one case the suite leaves red | `host is unreachable under every address form`; `TestNetnsFirewall` |
| Code planted in a login file (`~/.bashrc`, `~/.ssh/rc`) that runs during the next boot, before the firewall exists | Boot hold: until the firewall is applied, no new connection from the sandbox user or its container UIDs, loopback included, and no upstream DNS from systemd-resolved | Root in the guest, or `sudo: true` | `TestBootWindowIsClosed`; `TestNetnsFirewall` |
| Listen for your Mac to connect | Lima: forward nothing unless listed in `network.forward` | You list the port; or your IDE's own SSH tunnelling forwards it for you, which Lima never sees | `guest listeners are not forwarded to the Mac unless configured` |
| Read or write your files | Lima: `mounts: []`; devkit never copies out of the VM on its own | You use `source: mount` with `mount_writable: true`, approve a `devkit push` and then merge its commits into your checkout, or pull output across yourself; or a hypervisor escape | `nothing from the VM lands on the host` |
| Get code onto your remote, and from there into CI or your checkout | `devkit push` only: the VM holds no credentials; you review the commits, the changed files that run outside the VM are flagged, and nothing is pushed until you say yes | You approve it; the review is the gate, see "What git in the VM changes" below | `TestPushReviewsThenPushesWithHostCredentialsAndNoHooks`, `TestReviewShowsEveryCommitWhateverItsText`, `TestReviewShowsWhatAForcedPushRemoves` |
| Exploit git on your Mac with a crafted bundle | devkit parses the header itself; `git index-pack --strict` checks every object; size capped at 512 MiB; no hooks run | A bug in git's own pack parsing, the code every `git fetch` from an untrusted remote runs | `TestImportRejectsAMaliciousTree`, `TestImportChecksObjectsEvenWhenTheRepoDisablesFsck` |
| Rewrite the policy or swap the proxy | Root-only policy files; proxy installed only if its SHA-256 matches | Root in the guest; or the devkit binary or devkit.yaml on your Mac is tampered with, which is outside the sandbox entirely | `policy files are root-only` |
| Become root | No sudo; io_uring, unprivileged BPF and `AF_ALG` off; unprivileged user namespaces refused (unless `containers: true`; with `containers: docker`, open to Docker's own account only); module loading locked after provisioning; security pocket at boot | A kernel bug in a subsystem still reachable and not yet in the security pocket, or `sudo: true` | `unprivileged kernel attack surface is reduced`, `security updates are applied`, `TestKernelLockdown` |
| Root reaches your Mac's loopback services | Nothing inside the guest | The row above; your files still need a hypervisor escape on top | `TestRootInGuestReachesHost`, kept red on purpose |

### Enforcement on the Mac: `network.enforce: host`

Every control in the table above lives inside the guest, so root in the guest
can remove it. `network.enforce: host` (opt-in; the default is `guest`) adds
a layer root in the guest cannot reach. All of the VM's traffic leaves through
Lima's host agent, a process on your Mac. devkit starts the VM with
`limactl start` under a macOS sandbox profile (`sandbox-exec`), which the host
agent inherits: it may open connections to Lima's own sockets and, over TCP
only, to the VM's SSH forward and one devkit proxy on the Mac's loopback, and
to nothing else. That
proxy, `devkit hostproxy`, runs the same allowlist code, resolves names, and
keeps its log on the Mac, where `devkit logs` reads it. In the guest, root's
downloads and the in-guest proxy go through it; the in-guest firewall and
proxy stay as the inner layer, and nothing in the guest may send a DNS query.
It needs no root on the Mac.

What that buys, with root in the guest and the firewall flushed and the
in-guest proxy stopped, as `TestHostEnforcement` checks with raw sockets:

| Attack vector, as root in the guest | Under `enforce: host` | Still possible only if |
|---|---|---|
| Direct connection to the internet, any port, IPv4 or IPv6 | Refused on the Mac: the host agent may not dial it | A host the host proxy allows (below) |
| DNS query with data in the name, to any resolver or to Lima's own | No answer: the Mac's resolver socket is out of the host agent's reach | An allowed host the attacker controls makes DNS unnecessary anyway |
| Connect to your Mac's loopback services | Refused on the Mac, except the host proxy and the VM's own SSH forward, which leads back into the guest | A gap in the profile or in Lima; the host proxy itself refuses addresses of the Mac: loopback, link-local and any address on one of its interfaces, such as its LAN address, by IP or by a name that resolves to one |
| Rewrite the in-guest policy or swap the in-guest proxy | Possible, and no longer enough: the host proxy's allowlist is outside the guest | You change `devkit.yaml` on the Mac |
| Through the host proxy to another host or port | Refused by the host proxy, ports 80 and 443 only unless listed | The host is in `network.allow` or is one root's provisioning needs: Ubuntu's archive, ports and security hosts and the toolchain manager's download hosts; or `open` mode |

The other rows of the escape table, and the in-guest layer for code without
root, are unchanged.

Limits, stated plainly:

- **It is opt-in and new.** The default stays `guest` until host mode has
  more use behind it.
- **`sandbox-exec` is deprecated by Apple.** It works on current macOS. If it
  disappears, `devkit up` refuses to start the VM rather than run it
  unprotected; it never falls back to guest mode silently. The same goes for
  any host that is not macOS.
- **An outbound firewall on the Mac** such as LuLu must be told to allow the
  `devkit` binary, which is the host proxy; until it is, downloads hang.
- **A VM started by hand** (`limactl start`) runs without the profile and is
  unprotected. devkit records Lima's host agent at each start it makes, and
  `up`, `shell`, `sync`, `logs` and `audit` warn loudly when the running one
  is not it. `devkit down`, then `devkit up`, fixes it.
- **Not attacked:** the vsock channel between Lima's guest agent and host
  agent. The profile confines what the host agent dials, not what it does
  when asked over that channel.
- **ICMP** cannot leave the Mac: a process under the profile is refused when
  it tries to send one, which a test checks on the Mac itself. Inside the
  guest a ping either gets no reply or is answered by Lima's own network
  stack, depending on the environment; neither means it reached anything.
- **Not combinable** with `allow_host: true`, `dns: resolvers` or
  `mode: none`; devkit refuses those at validation. The first two need the
  VM to reach something on the Mac other than the proxy; `none` would leave
  the first boot no way to install its base packages.
- **Logs.** The host log records every request that leaves, root's
  included. A request the in-guest proxy refuses never reaches it; those
  stay in the VM's own log, which `devkit up` still summarises.

### What git in the VM changes

Git in the VM, `devkit push` and `devkit clone` widen the attack surface in
one deliberate place and narrow it in another. Before them, nothing the VM
wrote could leave except to an allowed host.

**Wider, by design.**
- **Commits the VM wrote can reach your remote.** That is the point of `devkit
  push`, and its only gate is your review. A malicious dependency can change
  files that an agent then commits, and rely on a long diff to hide it. The
  review lists every commit, the diffstat, the commits a forced push would
  remove, and the changed files that run outside the VM. It cannot judge the
  code for you.
- **Authorship from the VM proves nothing.** The VM commits as you: it gets
  your `user.name` and `user.email`, and can write any author it likes, so
  the review's "other author" note catches only the careless case.
- **Pushed commits run elsewhere.** CI runs them, with whatever secrets your
  workflows expose to that branch. If you bring them into your checkout on
  the Mac (`git merge refs/devkit/...`), your husky hooks, direnv, editor tasks
  and npm scripts there run code the VM wrote. That is the risk of checking
  out any untrusted pull request, and the one place where devkit's rule that
  project code never runs on the Mac depends on you.

**New on the Mac, and narrow.**
- **Parsing untrusted bytes.** A bundle from the VM is read by devkit's
  header parser and `git index-pack --strict`, the same code as any `git
  fetch` from an untrusted remote, capped at 512 MiB. Text from the VM is
  stripped of control characters and bidi overrides before it is shown.
- **devkit runs git on your Mac.** In a copied project's directory (to build
  the snapshot), and against your remotes (clone, sync, `ls-remote`, push),
  with your own git config and credentials, as when you run git there
  yourself, but with hooks disabled.

**Narrower.**
- **Cloning** is safer than `git clone`: bare, so no project file is written
  out on the Mac; https and ssh only; no submodules, hooks or templates.
- **Credentials stay out of the VM.** Without `devkit push`, the way to push
  from the VM was a token or an agent inside it, usable by every dependency.

**To keep the gate meaningful:** push to a feature branch and merge through a
pull request with branch protection; don't expose CI secrets to branches from
the VM; read the flagged files; and don't merge `refs/devkit/...` into your
Mac's checkout and then run the project's tooling there unless you have read
what it changes.

### Kernel crashes, seen from the Mac

A failed attempt at a kernel exploit often crashes the guest kernel before
one succeeds. devkit points the guest kernel's console at the serial port
Lima records on the Mac (`~/.lima/<vm>/serialv.log`) and reads the crash
reports there, on the Mac: nothing runs in the guest to find them, and the
sandbox user can neither write to that console nor stop the kernel from
writing to it.

- **From the first restart.** The kernel setting is written on the first
  boot and takes effect on the next one; `devkit up` says so. Until then a
  VM cannot report crashes, and `devkit audit` says that rather than "none".
- **What you see.** `up`, `shell`, `sync`, `logs` and `audit` warn about
  every crash report you have not acknowledged and show its first lines; a
  VM whose kernel has panicked, which Lima still lists as Running, is named
  as such (`devkit ls` too), and `devkit down` forces it off. `devkit
  audit` counts an unacknowledged report as a finding (exit 1), with the VM
  stopped too.
- **What to do.** A crash can be a failed attempt to break out, or simply a
  kernel bug. If you cannot explain it, discard the VM with `devkit rm`;
  otherwise acknowledge it with `devkit audit --ack-crashes`.
- **The limit.** This catches the noisy attempt, not the clean one. An
  exploit that works first time crashes nothing, and once it has root it
  can silence the console. A report is a reason to act; no report proves
  nothing.

Where the picture ends, and the risks that remain, are in [SECURITY.md](SECURITY.md).

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
  containers: false     # true: rootless containerd + nerdctl; docker: rootless Docker
  # container_runtime: runc  # with docker: gvisor | gvisor-hostnet, see Docker
  packages: [pkg-config]  # extra apt packages

# install: make deps    # replaces the lockfile-based install devkit picks
# services: [postgres]  # PostgreSQL 16 in the VM, no Docker; see Services

vm:
  cpus: 4
  memory_gb: 8
  disk_gb: 50
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

**Source methods**

| `source` | What happens | Notes |
|---|---|---|
| `copy` | The directory is copied into the VM on `up` and `sync` | Default. Host is never touched again. A git checkout gets a `.git` like a fresh clone's, see below. |
| `git` | Made by `devkit clone <url>`: your Mac clones bare, the VM checks out | Private repos work with your own credentials; the files are never written out on the Mac. `sync` fetches on the Mac and fast-forwards the VM. A `devkit.yaml` from `devkit init <url>` has no Mac-side clone; the VM then clones a public repo through the proxy. |
| `mount` | The directory is mounted read-only | Opt in. `mount_writable: true` lets the sandbox edit your files. |

**Git in a copied project.** Your `.git` is never copied. When the directory
is the top of a git checkout, the VM instead gets the `.git` a fresh clone
would have: your current commit and branch, with `origin` pointing at your
remote with any token stripped, and nothing else. No history, so a secret
deleted in an earlier commit stays on the Mac; no other branches, tags, stash
or reflog; no hooks; none of your `.git/config`. Uncommitted changes arrive as
changes, so `git status`, `git diff`, `git commit` and tools such as husky
work inside. A repository already in the VM is kept on later `sync`s, since it
may hold commits the Mac has never seen. Files in that one commit arrive even
if `exclude` names them.

**Cloning.** `devkit clone https://github.com/org/repo` (or just `devkit
github.com/org/repo`) makes `repo/` holding `devkit.yaml` and a bare,
one-commit clone in `.devkit/repo.git`, fetched with your own git credentials
so private repositories work. Bare means none of the project's files are
written out on your Mac, which rules out the class of git bugs that run code
on checkout; the VM checks out on `devkit up`. Languages are detected from
marker files read out of git objects. Only https and ssh are accepted, for the
clone and any redirect; `git://`, which GitHub no longer serves, is rewritten
to `https://`. `devkit sync` fetches new upstream commits on the Mac and
hands them to the VM, which never talks to the remote itself.

**Pushing from the VM.** The VM holds no credentials, and should not: a token
or SSH agent inside is usable by every dependency that runs there. `devkit
push` brings the work out instead. The VM writes a git bundle of the branch.
Your Mac has git check every object in it (malformed trees such as one with a
`.git` entry are refused), stores the branch as `refs/devkit/<project>/<branch>`,
outside your branches and work tree, and shows the commits, their authors,
the diffstat and any changed file that runs outside the VM: CI workflows, git
and editor hooks, `.envrc`, `package.json` scripts, task runners. After you
say yes it pushes with your normal git credentials. No git hooks run on the
Mac: a pre-push hook such as husky's would run the project's own code there,
and it already ran in the VM. The push never forces; `--force-with-lease`
replaces the remote branch only if it is still where it was when you reviewed.
Commits from the VM are unsigned; a branch that requires signatures needs
them re-signed on the Mac.

**Network modes**

| `mode` | Outbound traffic | Use |
|---|---|---|
| `allowlist` | Only hosts in `allow`, via the audited proxy; the firewall rejects everything else | Default |
| `open` | Any host, via the audited proxy; the firewall still rejects direct connections | Trusted code, want the log |
| `none` | Nothing, not even DNS | Air-gap after dependencies are installed: `devkit up --network none` |

Allowed hosts are hostnames: `example.com` exact, `*.example.com` one
level, `**.example.com` any depth. An entry allows the web ports, 80 and 443,
and nothing else on that host; `host:port` allows exactly one other port.
Anything else is rejected at validation. By default only the proxy may resolve
names: it looks up allowed hosts itself, and the sandbox cannot send a DNS
query at all, so a query name cannot carry data out. `dns: resolvers` reopens
DNS to the whole VM for tools that resolve a name before they use the proxy.

Nothing the sandbox listens on is reachable from your Mac unless its port is in
`forward`. A page served from the sandbox and opened in your browser would run
with the browser's unrestricted network, so forwarding is opt-in per port.

The guest applies Ubuntu's security pocket on every boot, before the firewall
comes up, so a VM does not stay at its image's patch level. Expect the cost on
the first boot after a kernel update lands: `devkit up` took about a minute
longer than usual the day one did (1 m 45 s against 46 s). Later boots only
check the pocket and take seconds. The new kernel is installed to disk and runs
from the next boot. `devkit up` does not reboot a VM whose configuration is
unchanged, so run `devkit down && devkit up` to boot into a new kernel; the
boot that installed it says so. `vm.security_updates: false` turns the step off;
`devkit up --no-security-updates` writes that for you, so the next boots are
quick again and the VM says so in its policy stamp.

Two more kernel controls. Unprivileged user namespaces are refused outright
(`kernel.unprivileged_userns_clone = 0`), including to the programs Ubuntu's
AppArmor profiles exempt, such as `rootlesskit` or `podman` installed from
`tools.packages`; root is unaffected. `containers: true` leaves them open,
under AppArmor's restriction alone, because rootless containerd needs them.
`containers: docker` leaves them on in the kernel but closes them, through
AppArmor, to every account except Docker's own (see Docker, below).
Kernel module loading is locked, for root too, as the last step of
provisioning, after the firewall is up and what the configuration needs is
loaded; every boot locks it again. A tool that needs a module nothing loaded
beforehand then fails; set `vm.lock_modules: false` for that project.

**Trust store.** The VM trusts what Ubuntu's `ca-certificates` package
trusts, refreshed by root on every boot, so a VM created before a CA was
removed upstream catches up on its next start. `network.distrust` names roots
to remove on top of that, for the cases where the distro lags the browsers.
Runtimes that bring their own root list (Node, Python's certifi, pip, curl)
are pointed at the system bundle instead, so both the distro's updates and
your `distrust` list apply to them. `devkit up` ends with a short trust audit;
`devkit audit --deep` scans every file. See SECURITY.md for what it catches.

The audit also lists container images the project does not pin by digest. It
reads every `image:` in the compose files (`compose.yaml`,
`docker-compose.*.yml` and the like, with their `.env`) and every `FROM` and
`COPY --from` in Dockerfiles and Containerfiles, so it needs no Docker. A
reference counts as pinned only with `@sha256:` and a 64-character digest; a
tag or a bare name is unpinned, because the same tag can be different code
tomorrow. A reference whose variable has no value devkit can see, such as
`${IMAGE:?}` or a build `ARG` without a default, is reported as unresolved
rather than assumed fine. This part is a report: unpinned or unresolved
images do not change `devkit audit`'s exit status.

The sandbox cannot reach your Mac in any mode unless `allow_host` is true. With
`allow_host: true` the VM reaches the host directly at `host.lima.internal`,
bypassing the proxy and its log.

**Dependencies** are installed from whichever lockfile is present and from
nothing else: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install
--frozen-lockfile`, `go mod download`, `cargo fetch --locked`, `uv sync
--frozen`, `bundle install`, and so on. Set `install:` when the guess is wrong.
A Node project without a lockfile gets `npm install` and a reminder to commit
the result.

**Services** run databases inside the VM without a container engine and
without anything on your Mac. `services: [postgres]` gives Ubuntu's
PostgreSQL 16 with a role and database `dev`, password `dev`, on port 5432:
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
`~/.local/share/devkit/postgres`, and runs as a systemd user unit that starts
at boot. It listens only on the VM's 127.0.0.1, so nothing outside the VM can
reach it unless you add the port to `network.forward`, and it makes no
connections of its own. The sandbox user administers it over a local socket
(`psql -h $XDG_RUNTIME_DIR -p 5433 -d postgres`); the app logs in over TCP as
the role above. The password is for development inside the VM: the only
thing that can reach the port is the sandbox itself. Remove the service from
`devkit.yaml` and the next `devkit up` stops it and keeps the data.

**Containers** are opt-in. With `containers: true` the VM gets rootless
containerd and `nerdctl` for databases and services. It also leaves
unprivileged user namespaces open, which rootless containerd needs, and loads
the bridge, overlay and netfilter modules containers use before module
loading is locked. `containers: docker` gives Docker instead, described next.

**Docker.** With `containers: docker` the VM gets Docker, Compose and buildx,
run rootless under an account of its own, `devkit-docker`, never as root and
never as the sandbox user. The reason is user namespaces: rootless Docker
needs them with capabilities inside, and only that account gets them. Ubuntu's
AppArmor profiles exempt `rootlesskit`, `runc` and `slirp4netns` by path; devkit
makes those three executable by the account only, and disables every other
stock profile that exempts a program, so for the sandbox user user namespaces
stay as closed as without containers. The sandbox user reaches Docker with
no setup: `DOCKER_HOST` points every session at devkit's API filter (below),
never at the daemon's own socket, which only the filter can reach. The
rootful `docker.service` is masked and never runs.

Containers have the network the rest of the VM has. Their traffic leaves
through `slirp4netns`, under the account's UID, which the firewall rejects
everywhere except the VM's loopback (and what `allow_host` or `dns: resolvers`
open to the whole VM), so the only way out is the egress proxy,
with its allowlist and its log. The daemon reaches the proxy at 10.0.2.2,
which is the VM's loopback as seen from a container; that also means a
container can reach anything else listening on the VM's 127.0.0.1, such as
`services: [postgres]`. On every boot the account is held off the network
like the sandbox user, and the daemon starts only after the firewall, so a
container with `--restart always` gets nothing before it.

The workspace is shared with the daemon, and nothing else is. The daemon mounts
`~/workspace` over itself with your IDs mapped to the account's, in its own
mount namespace, so container root is you on disk: what a container writes in
a bind mount of the workspace belongs to you, and what you or `devkit sync`
write is writable from the container. A bind mount of anything else in your
home, such as `~/.ssh`, fails: the account may only pass through your home
directory, not read it. `source: mount` cannot be combined with
`containers: docker`: virtiofs, which carries the mount, does not support
ID-mapped mounts on the VM's kernel. Use `source: copy` or `git`.

devkit writes the proxy into the Docker client's `~/.docker/config.json`, and
Docker passes it to every container and build as `http_proxy` and the like.
`no_proxy` names `localhost`, the loopback addresses, and the services and
`container_name`s of the Compose files at the workspace root and one directory
below, so one service reaches another by name. A name that is not a plain
name is left out. Run `devkit up` again after adding a Compose service. Some
clients ignore `no_proxy`, busybox `wget` among them; tell those to skip the
proxy for service names (`wget -Y off`).

Docker Hub is not allowed by default: allowing a registry is your decision. A
pull from it needs these hosts in `network.allow`:

```yaml
    - registry-1.docker.io
    - auth.docker.io
    - production.cloudflare.docker.com
    - production.cloudfront.docker.com
    - "**.r2.cloudflarestorage.com"
```

**What Docker may be asked for.** Anyone who can use the daemon's socket can
ask it for anything the account may do: privileged containers, extra
capabilities, the VM's namespaces, bind mounts of whatever the account can
read. So the sandbox user never gets that socket. It gets devkit's API
filter, `devkit-dockerfilter`, a small proxy on `/run/devkit/docker.sock`
that runs under an account of its own (not root), and forwards a call only
when the call is in its table and its settings are ones it knows to be
harmless. Everything else is refused, including what it does not recognise:
an unknown endpoint, query parameter or field is a refusal, not a pass. A
refusal looks like this:

```
Error response from daemon: devkit: refused: POST /containers/create: HostConfig.Privileged is not allowed
```

and is logged, one line with the method, path and reason, never a request
body, in the filter's journal (`journalctl -u devkit-dockerfilter`, with
`sudo: true`).

Refused, because each widens the VM kernel's surface or reaches past the
container: `--privileged`; devices and device rules; sysctls; the VM's
PID, IPC, UTS, cgroup or user namespace and `--network host`; security
options other than `no-new-privileges` (no seccomp, AppArmor or system-path
changes); a cgroup parent, a volume driver, storage options, a negative OOM
score, real-time CPU and block I/O device settings. Capabilities: Docker's
default set, which a container may add back after `--cap-drop ALL`, plus
`IPC_LOCK` and `NET_BIND_SERVICE`; nothing else, and never `ALL`. `NET_RAW`
is dropped from every container, so raw sockets and `ping` inside a
container do not work. Published ports bind to the VM's loopback only
(`127.0.0.1` or `::1`). The runtime is fixed by `tools.container_runtime`:
asking for another by name, `runc` included, is refused. Logs stay in the
VM (`json-file`, `local` or `none`). Bind mounts must come from the
workspace: a bind of `/etc`, your home, `~/.ssh` or Docker's own files is
refused, by its path as written and by where its symlinks lead; named
volumes use the `local` driver with no options, so a volume cannot bind a
path either. `docker exec --privileged`, `docker update`, plugins, swarm,
services, secrets and configs are unavailable. Builds work, as do
`docker compose`, `docker cp`, `attach`, `exec` and the rest of everyday
use.

The filter checks the request, but the daemon resolves a bind's path later,
when the container starts, and the workspace is yours to rearrange in
between: a directory that passed can be a symlink to the daemon's sockets
by then. So with `runc`, every container runs through a second check,
`devkit-runc-guard`, registered as Docker's default runtime: it lets `runc`
set the container up, reads the mounts actually made before the container's
first process starts, and deletes the container unless each one comes from
the workspace, a Docker volume or Docker's own per-container files. The
error then reads `devkit: refused: a mount comes from outside the
workspace`.

What this does not cover. BuildKit's own stream (`docker build` with
buildx, and Compose builds) is passed through unparsed; BuildKit runs build
steps with its own `runc`, not through the guard, and takes no host paths,
and the daemon refuses the `security.insecure` entitlement. Under gVisor
the mount check is the filter's alone: the guard is not in front of
`runsc` (which does not pass the VM's Unix sockets into a container). The
Docker account is the trust boundary for containers: container root is that
account, so what the account may read or write, a container may too, inside
the workspace and outside it. A container made before the filter existed is
started through it only if its runtime and privileges are ones it would
allow today; one with a restart policy is restarted by the daemon itself at
boot, unchecked, so remove containers made by an earlier devkit (`docker
rm -f`) after upgrading. Turning `containers: docker` off stops the daemon and the
filter and puts back what devkit changed in AppArmor and file modes; the
accounts and the images are kept.

**gVisor.** `tools.container_runtime` chooses what runs Docker's containers.
`runc`, the default, runs them on the VM's kernel, as Docker normally does.
`gvisor` makes gVisor's `runsc` the daemon's default runtime: a container's
system calls reach gVisor's kernel, which runs in user space, and only a small
filtered set of calls reaches the VM's kernel. It needs `containers: docker`.

```yaml
tools:
  containers: docker
  container_runtime: gvisor   # runc | gvisor | gvisor-hostnet
```

With `gvisor` a container also gets gVisor's own network stack. Docker's
built-in DNS does not answer there, so Compose services cannot reach one
another by name. `gvisor-hostnet` runs `runsc` with `--network=host`: socket
calls go to the VM kernel's network stack, inside the container's own network
namespace, so service names work, while file, process and memory calls stay
behind gVisor. What it gives up is gVisor's network stack: the VM kernel's
networking code is within a container's reach again. In both modes a container still has
only the network described above: the firewall and the proxy apply as they do
to `runc`. `--cap-add NET_ADMIN` configures gVisor's network stack, not the
VM's.

What it costs, from one run of each on an arm64 Mac, without KVM: starting
and stopping a container, and file I/O, took about as long as under `runc`;
spawning processes was about 3.5 times slower. `runsc` runs with
`--ignore-cgroups`, so memory and CPU limits set on a container are not
enforced under gVisor. Builds are not covered: `docker build` runs its `RUN`
steps with BuildKit, which has its own `runc` worker.

The runtime is a control, not a default: the API filter allows only the
configured gVisor runtime by name, so `docker run --runtime=runc` (or the
other gVisor mode) is refused. The mount check under gVisor is the filter's
alone (see above). Switching back to `runc` takes gVisor out of the daemon's
configuration and leaves its files installed.

Root installs gVisor at boot from Google's release bucket,
`storage.googleapis.com/gvisor/releases/release/<release>/<arch>/`, one
archive per architecture, with the release and the archive's SHA-512 pinned in
`internal/provision/provision.go`. The archive is checked before it is
unpacked, and it is downloaded again only when the pin changes. The pinned
checksum was taken from the `.sha512` file published beside the archive, at
the same origin, so it pins the bytes devkit was tested with, not who
published them.

## Toolchains

`tools.manager` decides how language toolchains get into the VM. `devkit init`
picks `mise` unless `--toolchain` or `DEVKIT_TOOLCHAIN` says otherwise, and
seeds versions from the files it finds: `.nvmrc`, `engines.node`, `go.mod`,
`rust-toolchain.toml`, `.python-version`, `.ruby-version`, `.java-version`.
A Bun project, one with `bun.lock`, `.bun-version`, `bunfig.toml` or
`packageManager: "bun@..."`, gets Bun, beside Node when it has a
`package.json`, and its dependencies install with `bun install
--frozen-lockfile`. An `engines` range seeds its lower bound only when that
bound is inclusive, otherwise the default.

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
| `devkit clone <url> [dir]`, `devkit <url>` | New project from a repository, without checking it out on the Mac. `git://` becomes `https://`. Flags: `--branch`, `--name`, `--toolchain`, `--node`, `--network` |
| `devkit init [repo-url]` | Write `devkit.yaml`. Flags: `--name`, `--toolchain`, `--node`, `--network`, `--force` |
| `devkit up` | Create or start the VM, sync source, install toolchains and dependencies. Flags: `--network`, `--no-sync`, `--no-install`, `--relock` |
| `devkit shell [cmd]` | Shell in the VM, or run a command |
| `devkit sync` | Copy the directory again; for a cloned project, fetch upstream on the Mac and fast-forward the VM |
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
  except those from the proxy's user, DNS to the configured resolvers, and the
  host when `allow_host` is set. In `none` mode it rejects everything.
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
| gVisor (`container_runtime: gvisor` or `gvisor-hostnet`) | storage.googleapis.com, release pinned in `internal/provision/provision.go` | SHA-512 pinned, taken from the `.sha512` file beside the archive: it pins the bytes, not the publisher |
| Nix packages | cache.nixos.org, flake inputs | Nix verifies the cache's Ed25519 signature; `flake.lock` pins every input by hash |
| apt packages | Ubuntu archives | Ubuntu's signing keys shipped in the image |
| Project dependencies | Whatever the lockfile says, inside the sandbox | Lockfile integrity hashes, enforced by `npm ci` and friends |
| devkit's own Go modules | proxy.golang.org | `go.sum`; `go mod verify` passes |
| Lima | Homebrew | Homebrew's bottle checksums |

Bump the image deliberately: update the release path and both digests together
from the `SHA256SUMS` file for that release. Bump mise and Nix the same way:
verify the upstream signature, then change the version and both hashes.
gVisor's pin has no signature check behind it: change the release and both
SHA-512 pins together, from the `.sha512` files for that release.

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
internal/hostenforce  the macOS sandbox profile for network.enforce: host
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
- An opt-in inner sandbox (gVisor) that runs project processes behind a
  userspace kernel, so a guest kernel exploit meets it before the real kernel.
  Defence in depth against the one case the VM boundary does not cover, a
  privilege escalation reaching the host's loopback; see SECURITY.md for the
  trade-offs.

## License

MIT
