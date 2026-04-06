# Devkit

> **⚠️ PoC VIBE-CODE WARNING**
> The current code-base is heavily vibe-coded, so use with extreme caution until it get's properly reviewed and lifted from PoC state (if ever).

> **⚠️ WORK IN PROGRESS**
>
> This project is under active development and may contain bugs, incomplete features, or breaking changes. Use at your own risk in production environments.
>
> **Contributions are welcome!** See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Secure local development infrastructure kit that orchestrates rootless containers for isolated development environments.

## Features

- **Multi-Runtime Support**: Choose between Podman (shared VM) or Lima (per-project VMs)
- **Rootless Containers**: No root privileges required on host
- **Host Isolation**: Containers have no access to host filesystem by default
- **Pre-installed Dependencies**: Automatically detects and installs project dependencies
- **IDE Integration**: Built-in SSH server for VS Code and Cursor Remote development
- **Auto Port Forwarding**: Lima automatically forwards ports when services start listening
- **Project Detection**: Auto-detects Node.js projects (more languages coming soon)

## Requirements

- [Podman](https://podman.io/getting-started/installation) (rootless mode) **OR** [Lima](https://lima-vm.io/) (for per-project VM isolation)
- SSH key in `~/.ssh/` (for VS Code connection)
- Go 1.22+ (for building from source)

## Installation

### From Source

```bash
git clone https://github.com/jurajpiar/devkit.git
cd devkit
go build -o devkit ./cmd/devkit
sudo mv devkit /usr/local/bin/
```

## Quick Start

```bash
# Initialize a new project (interactive TUI wizard)
devkit init

# Or initialize with a git repository
devkit init git@github.com:user/my-nodejs-app.git

# Or non-interactive mode
devkit init --no-tui

# Build the container image
devkit build

# Start the development container
devkit start

# Get VS Code connection instructions
devkit connect

# Open a shell in the container
devkit shell

# Stop the container
devkit stop
```

The `devkit init` command launches an interactive TUI wizard that guides you through:
- Project name and type (auto-detected)
- Runtime backend selection (Podman or Lima)
- Source method and port configuration
- Security level settings

Ports are automatically checked for availability.

## Security Modes

```bash
# Standard mode (localhost blocked, all hardening enabled)
devkit start

# Total isolation - dedicated VM per project (hypervisor-level isolation)
# Container escape is still confined to dedicated VM
# No shared kernel between projects
devkit start --total-isolation
devkit start -t  # short flag

# Paranoid mode - for untrusted code
# Two-phase setup: network enabled for clone/install, then air-gapped
devkit start --paranoid

# Total isolation + paranoid = maximum security
devkit start -t --paranoid

# Offline mode - no network at all
devkit start --offline

# Disable debug port only
devkit start --no-debug-port
```

### Egress Proxy (Domain Filtering)

Control which external services your container can reach:

```yaml
# devkit.yaml
security:
  egress_proxy:
    enabled: true
    allowed_hosts:
      - "registry.npmjs.org"
      - "*.github.com"
      - "*.githubusercontent.com"
      - "api.thegraph.com"
    audit_log: true
```

Build and start with egress proxy:

```bash
devkit build --egress-proxy
devkit start
```

**Pattern syntax:**
- `example.com` - exact match
- `*.example.com` - immediate subdomains only
- `**.example.com` - any depth of subdomains
- `*` - allow all (disables filtering)

All HTTP/HTTPS traffic is routed through the proxy. Blocked requests return HTTP 403.

### Runtime Backends

Devkit supports multiple container runtime backends:

| Backend | Description | Use Case |
|---------|-------------|----------|
| `podman` | Default, fast startup, shared VM | Standard development |
| `lima` | Per-project VMs, stronger isolation | Untrusted code, security-focused |

```bash
# Check current runtime status
devkit runtime status

# Switch backend (updates devkit.yaml)
devkit runtime switch lima
devkit runtime switch podman

# Manage VMs directly
devkit vm list
devkit vm start <name>
devkit vm stop <name>
```

Configure in `devkit.yaml`:
```yaml
runtime:
  backend: lima  # or podman
  lima:
    cpus: 4
    memory_gb: 8
    disk_gb: 50
    per_project_vm: true  # Each project gets its own VM
```

### Total Isolation Mode

When `--total-isolation` (or `-t`) is enabled, devkit creates a dedicated Podman machine (VM) for the project:

- **Hypervisor-level isolation**: Even if an attacker escapes the container, they're still confined to a dedicated VM
- **No shared kernel**: Projects cannot affect each other through kernel exploits
- **Complete network isolation**: Each VM has its own network namespace
- **Resource isolation**: CPU/memory limits enforced at VM level

Configure in `devkit.yaml`:
```yaml
security:
  total_isolation: true
```

Cleanup:
```bash
devkit remove                 # Removes container, volumes, AND dedicated machine
devkit remove --keep-machine  # Keeps the dedicated machine for reuse
devkit stop --stop-machine    # Stops container AND dedicated machine
```

## Commands

| Command | Description |
|---------|-------------|
| `devkit init [repo-url]` | Initialize devkit.yaml config (TUI wizard) |
| `devkit build` | Build the container image |
| `devkit start` | Start the development container |
| `devkit stop` | Stop the container |
| `devkit remove` | Remove container and volumes |
| `devkit connect` | Show IDE connection instructions |
| `devkit forward <port>` | Forward ports via SSH tunnel |
| `devkit shell` | Open a shell in the container |
| `devkit list` | List all devkit containers |
| `devkit stats` | Show container performance statistics |
| `devkit logs` | View monitoring logs |
| `devkit monitor` | Manage monitoring daemon |
| `devkit runtime status` | Show current runtime backend status |
| `devkit runtime switch` | Switch between podman/lima backends |
| `devkit runtime doctor` | Diagnose runtime issues |
| `devkit runtime install` | Install a runtime backend |
| `devkit vm list` | List all devkit VMs |
| `devkit vm create` | Create a new VM |
| `devkit vm start/stop` | Start or stop a VM |
| `devkit vm remove` | Remove a VM |
| `devkit machine` | Manage the devkit Podman machine |

## Configuration

Devkit uses a `devkit.yaml` file for configuration:

```yaml
project:
  name: my-app
  type: nodejs

runtime:
  backend: podman       # podman | lima
  lima:
    cpus: 4
    memory_gb: 8
    disk_gb: 50
    per_project_vm: true

source:
  method: git           # git | copy | mount
  repo: git@github.com:user/repo.git
  branch: main

dependencies:
  runtime: node:22-alpine
  install:                    # Global npm packages
    - typescript
    - eslint
  system_packages:            # System packages (has sensible defaults)
    - python3                 # For node-gyp
    - make
    - g++

features:
  allow_copy: false     # Enable 'copy' source method
  allow_mount: false    # Enable 'mount' source method

ssh:
  port: 2222            # SSH port for IDE connection

ports:                  # Application ports to expose
  - 3000
  - 8080

ide_servers:            # IDE server directories (mounted as writable volumes)
  - .vscode-server      # VS Code
  - .cursor-server      # Cursor
  # Add other IDEs as needed (e.g., .fleet, .zed-server)

extra_volumes:          # Additional writable directories in /home/developer
  - .npm                # npm cache
  - .cache              # General cache
  # Add others as needed (e.g., .cargo, .gradle)

copy_exclude:           # Paths to exclude when copying (has sensible defaults)
  # Defaults include: ._*, .DS_Store, .git, node_modules,
  # .next, dist, build, .nuxt, .output, .idea, *.swp, *.log, .cache
  # Add your own or override defaults:
  - .next
  - node_modules
  - my-custom-dir

chown_paths:            # Paths needing explicit ownership fix (relative to workspace)
  - some/path           # If specific paths have permission issues after copy
```

### Source Methods

| Method | Description | Feature Flag |
|--------|-------------|--------------|
| `git` | Clone repo inside container (default, most secure) | None required |
| `copy` | Copy files into container at startup | `allow_copy: true` |
| `mount` | Volume mount project directory (read-only) | `allow_mount: true` |

## IDE Setup (VS Code / Cursor)

Devkit supports both VS Code and Cursor via their Remote-SSH extensions.

### Method 1: Remote-SSH Extension

1. Install the "Remote - SSH" extension in your IDE
2. Run `devkit connect` to see connection details
3. Press `Cmd+Shift+P` and select "Remote-SSH: Connect to Host..."
4. Enter: `ssh://developer@localhost:<port>` (port from `ssh.port` in devkit.yaml, default 2222)
5. Open folder: `/home/developer/workspace`

### Method 2: SSH Config

Add to `~/.ssh/config` (adjust port to match your `devkit.yaml`):

```
Host devkit-myproject
    HostName localhost
    Port 2222          # Must match ssh.port in devkit.yaml
    User developer
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

Or run: `devkit connect --add-to-config`

## Port Forwarding

When running applications in the container (e.g., React dev server on port 3000), you have several options to access them:

### Option 1: IDE Auto-Forward (Recommended)

VS Code and Cursor automatically detect and forward ports when connected via Remote-SSH. Just run your app and the IDE will prompt you.

### Option 2: Lima Auto-Forward (Lima backend only)

With Lima backend, ports are **automatically forwarded** when services start listening on them. No configuration needed - Lima's guest agent detects listening ports and forwards them to your host.

### Option 3: Dynamic SSH Tunnel

```bash
# Forward a single port
devkit forward 3000

# Forward multiple ports
devkit forward 3000 8080

# Forward and save to config for future container starts
devkit forward 3000 --save
```

The tunnel runs in the foreground - press Ctrl+C to stop.

### Option 4: Pre-configured Ports

Add ports to `devkit.yaml` to automatically publish them when the container starts:

```yaml
ports:
  - 3000
  - 8080
```

Then recreate the container:

```bash
devkit start --rebuild
```

**Important:** Ports must be configured in `devkit.yaml` BEFORE the container is created. If you add ports later, use `--rebuild` to recreate the container.

All ports are bound to `127.0.0.1` only for security.

## Debugging

### Node.js

Debug port 9229 is automatically forwarded. Add this to your `.vscode/launch.json`:

```json
{
  "type": "node",
  "request": "attach",
  "name": "Attach to Container",
  "port": 9229,
  "restart": true,
  "localRoot": "${workspaceFolder}",
  "remoteRoot": "/home/developer/workspace"
}
```

## Security Model

Devkit is designed for maximum isolation to protect against supply-chain attacks and 0-day exploits.

### Default Security Measures (Always On)

| Protection | Description |
|------------|-------------|
| **Rootless Containers** | Both Podman and Lima run containers without root privileges |
| **No Host FS Access** | Code is git-cloned inside container, no host mounts |
| **Drop All Capabilities** | `--cap-drop=ALL` removes all Linux capabilities |
| **No New Privileges** | Prevents privilege escalation via setuid binaries |
| **Read-Only Root FS** | `--read-only` prevents persistent malware |
| **Localhost Blocked** | Container cannot access host services (Podman: slirp4netns, Lima: bridge isolation) |
| **Localhost-Only Ports** | SSH/debug ports bind to `127.0.0.1` only |
| **Resource Limits** | Memory (4GB) and process limits (512) prevent DoS |
| **Named Volumes** | Workspace uses container-local volumes, not host paths |
| **Per-Project VMs** | Lima backend provides hypervisor-level isolation between projects |

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `restricted` (default) | Outbound internet allowed, localhost blocked | Normal development |
| `none` | No outbound network (Podman: `--network=none`, Lima: iptables blocking) | Maximum security after deps installed |
| `full` | Full network including localhost (dangerous) | Only if explicitly needed |

**Note:** With Lima backend, `network_mode: none` uses iptables to block outgoing traffic while preserving SSH port forwarding for IDE connections. With Podman, it uses `--network=none` which completely isolates the container.

### Configuration

```yaml
security:
  network_mode: restricted    # none | restricted | full
  memory_limit: 4g
  pids_limit: 512
  read_only_rootfs: true
  drop_all_capabilities: true
  no_new_privileges: true
```

### What This Protects Against

- **Supply-chain attacks**: Malicious npm packages cannot access host filesystem or localhost services
- **Container escape**: Rootless + dropped capabilities + no-new-privileges significantly reduces attack surface
- **Data exfiltration to host**: Container cannot read host files or connect to host databases
- **Lateral movement**: Cannot scan or attack local network services
- **Persistent malware**: Read-only rootfs prevents trojans from persisting

### Limitations

**Both backends:**
- Outbound internet access is allowed by default (for git clone, npm install)
- Default memory limit (4GB) may be insufficient for memory-intensive frameworks like Next.js with Turbopack - increase `memory_limit` in devkit.yaml if you experience OOM kills
- Use `network_mode: none` after initial setup for maximum isolation

**Podman-specific:**
- Kernel-level container escape CVEs may still apply (mitigated by rootless mode)
- All containers share the host kernel

**Lima-specific:**
- Container can access VM's localhost (but VM is isolated from host) - different from Podman's `slirp4netns:allow_host_loopback=false`
- Kernel escape CVEs are contained within the per-project VM (hypervisor isolation)
- Slight performance overhead due to VM layer
- `network_mode: none` uses iptables (outgoing blocked, SSH preserved) instead of complete network isolation
- VM has no access to host filesystem (Lima's default mounts are explicitly disabled)

## Project Structure

```
devkit/
├── cmd/devkit/main.go           # Entry point
├── internal/
│   ├── cli/                     # Cobra commands
│   ├── config/                  # Configuration parsing
│   ├── detector/                # Project type detection
│   ├── builder/                 # Image building
│   ├── container/               # Podman container interaction
│   ├── machine/                 # Podman machine management
│   └── runtime/                 # Multi-runtime abstraction
│       ├── runtime.go           # Runtime interfaces
│       ├── factory.go           # Runtime factory
│       ├── podman/              # Podman implementation
│       └── lima/                # Lima implementation
├── templates/                   # Base Containerfiles
├── go.mod
└── README.md
```

## Roadmap

- [x] Multi-runtime support (Podman and Lima backends)
- [x] TUI init wizard
- [x] Per-project VM isolation with Lima
- [x] Two-phase network setup (paranoid mode)
- [ ] Support for more languages (Python, Go, Rust)
- [ ] GUI using raylib
- [ ] Container persistence options
- [ ] Multi-container setups (databases, services)
- [ ] Custom Containerfile templates
- [ ] Integration with AI coding agents

## License

MIT
