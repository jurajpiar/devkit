# devkit

Disposable sandbox VMs for untrusted code and coding agents, on macOS.

Every project gets its own virtual machine on Apple's hypervisor. The VM cannot
see your files, cannot reach services on your Mac, and can only talk to the
hosts you allow. Every outbound request is logged. When you are done, delete the
machine.

> Work in progress. Expect rough edges; see [SECURITY.md](SECURITY.md) for what
> is and is not guaranteed.

## Why

Running `npm install` on a stranger's pull request, or letting a coding agent
loose on a repository, executes arbitrary code on your laptop with your SSH
keys, cloud credentials and local databases in reach. devkit moves that work
into a machine you can throw away.

## Requirements

- macOS on Apple silicon
- [Lima](https://lima-vm.io/) (`brew install lima`)
- Go 1.23+ to build from source

## Install

```bash
git clone https://github.com/jurajpiar/devkit.git
cd devkit
make install        # builds the egress proxy for the VM and installs devkit
devkit doctor
```

## Use

```bash
cd my-project
devkit init         # writes devkit.yaml (detects Node.js version)
devkit up           # creates the VM, copies the code in, runs npm install
devkit shell        # shell inside the VM, in ~/workspace
devkit logs         # every host the sandbox tried to reach, allowed or blocked
devkit rm           # delete the VM and everything in it
```

The first `devkit up` downloads a 220 MB Ubuntu Minimal image and provisions
the machine, which takes a few minutes. After that, `up` takes seconds.

To work from VS Code or Cursor, use the Remote-SSH extension and connect to
`devkit-<name>`. devkit maintains the entry in `~/.ssh/config`. Ports your app
listens on inside the VM appear on `127.0.0.1` on your Mac automatically.

## Configuration

`devkit init` writes this file. Edit it and run `devkit up` again to apply.

```yaml
name: my-project
source: copy            # copy | git | mount

tools:
  node: "22"            # Node.js major version, or omit
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
| `allowlist` | Only hosts in `allow`, enforced by a firewall, via an audited proxy | Default |
| `open` | Anything, via the audited proxy | Trusted code, want the log |
| `none` | Nothing | Air-gap after dependencies are installed: `devkit up --network none` |

Host patterns: `example.com` exact, `*.example.com` one level, `**.example.com`
any depth. The sandbox cannot reach your Mac in any mode unless `allow_host` is
true.

**Containers** are opt-in. With `containers: true` the VM gets rootless
containerd and `nerdctl` for databases and services.

## Commands

| Command | Description |
|---|---|
| `devkit init [repo-url]` | Write `devkit.yaml` |
| `devkit up` | Create or start the VM, sync source, install dependencies |
| `devkit up --network none` | Change the network mode and apply it |
| `devkit shell [cmd]` | Shell in the VM, or run a command |
| `devkit sync` | Copy the directory again, or `git pull` |
| `devkit logs [-f]` | Egress audit log |
| `devkit connect` | IDE connection instructions |
| `devkit down` | Stop the VM, keep its disk |
| `devkit rm` | Delete the VM |
| `devkit ls` | List devkit VMs |
| `devkit doctor` | Check the host |

## How it works

- One Lima instance per project, `vmType: vz`, no host mounts, no sudo for the
  sandbox user. The guest is the Ubuntu Minimal cloud image (about 220 MB,
  systemd and glibc), pinned by digest and downloaded once.
- A root-only provisioning script, regenerated from `devkit.yaml` on every boot,
  applies the firewall and starts the egress proxy. Code in the VM cannot change
  the policy because it has no root.
- The egress proxy is a small Go HTTP/CONNECT proxy embedded in the `devkit`
  binary. Root inside the VM only installs it if its hash matches the one
  recorded at provisioning time.
- In `allowlist` mode the firewall rejects every outbound packet except those
  from the proxy's user and DNS. In `none` mode it rejects everything.

## Project layout

```
cmd/devkit          CLI entry point
cmd/egressproxy     the proxy that runs inside the VM
internal/app        commands
internal/project    devkit.yaml schema and validation
internal/lima       limactl wrapper and instance config rendering
internal/provision  scripts that run inside the VM (the security policy)
internal/egressproxy  proxy implementation
internal/embedded   embedded proxy binary
tests/e2e           creates a real VM and checks the guarantees
```

## License

MIT
