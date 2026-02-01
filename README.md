# Devkit

Secure local development infrastructure kit that orchestrates rootless containers for isolated development environments.

## Features

- **Rootless Containers**: Uses Podman rootless mode - no root privileges required
- **Host Isolation**: Containers have no access to host filesystem by default
- **Pre-installed Dependencies**: Automatically detects and installs project dependencies
- **IDE Integration**: Built-in SSH server for VS Code and Cursor Remote development
- **Project Detection**: Auto-detects Node.js projects (more languages coming soon)

## Requirements

- [Podman](https://podman.io/getting-started/installation) (rootless mode)
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
# Initialize a new project
devkit init git@github.com:user/my-nodejs-app.git

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
# Automatically air-gaps after clone/install
devkit start --paranoid

# Total isolation + paranoid = maximum security
devkit start -t --paranoid

# Offline mode - no network at all
devkit start --offline

# Disable debug port only
devkit start --no-debug-port
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
| `devkit init [repo-url]` | Initialize devkit.yaml config |
| `devkit build` | Build the container image |
| `devkit start` | Start the development container |
| `devkit stop` | Stop the container |
| `devkit remove` | Remove container and volumes |
| `devkit connect` | Show IDE connection instructions |
| `devkit forward <port>` | Forward ports via SSH tunnel |
| `devkit shell` | Open a shell in the container |
| `devkit list` | List all devkit containers |

## Configuration

Devkit uses a `devkit.yaml` file for configuration:

```yaml
project:
  name: my-app
  type: nodejs

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
4. Enter: `ssh://developer@localhost:2222`
5. Open folder: `/home/developer/workspace`

### Method 2: SSH Config

Add to `~/.ssh/config`:

```
Host devkit-myproject
    HostName localhost
    Port 2222
    User developer
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

Or run: `devkit connect --add-to-config`

## Port Forwarding

When running applications in the container (e.g., React dev server on port 3000), you have several options to access them:

### Option 1: IDE Auto-Forward (Recommended)

VS Code and Cursor automatically detect and forward ports when connected via Remote-SSH. Just run your app and the IDE will prompt you.

### Option 2: Dynamic SSH Tunnel

```bash
# Forward a single port
devkit forward 3000

# Forward multiple ports
devkit forward 3000 8080

# Forward and save to config for future container starts
devkit forward 3000 --save
```

The tunnel runs in the foreground - press Ctrl+C to stop.

### Option 3: Pre-configured Ports

Add ports to `devkit.yaml` to automatically publish them when the container starts:

```yaml
ports:
  - 3000
  - 8080
```

Then recreate the container:

```bash
devkit remove
devkit start
```

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
| **Rootless Podman** | Containers run without root privileges on host |
| **No Host FS Access** | Code is git-cloned inside container, no host mounts |
| **Drop All Capabilities** | `--cap-drop=ALL` removes all Linux capabilities |
| **No New Privileges** | `--security-opt=no-new-privileges` prevents privilege escalation |
| **Read-Only Root FS** | `--read-only` prevents persistent malware |
| **Localhost Blocked** | `slirp4netns:allow_host_loopback=false` blocks access to host services |
| **Localhost-Only Ports** | SSH/debug ports bind to `127.0.0.1` only |
| **Resource Limits** | Memory (4GB) and process limits (512) prevent DoS |
| **Named Volumes** | Workspace uses container-local volumes, not host paths |

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `restricted` (default) | Outbound internet allowed, localhost blocked | Normal development |
| `none` | No network access at all | Maximum security after deps installed |
| `full` | Full network including localhost (dangerous) | Only if explicitly needed |

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

- Outbound internet access is allowed by default (for git clone, npm install)
- Kernel-level container escape CVEs may still apply (mitigated by rootless)
- Use `network_mode: none` after initial setup for maximum isolation

## Project Structure

```
devkit/
├── cmd/devkit/main.go           # Entry point
├── internal/
│   ├── cli/                     # Cobra commands
│   ├── config/                  # Configuration parsing
│   ├── detector/                # Project type detection
│   ├── builder/                 # Image building
│   └── container/               # Podman interaction
├── templates/                   # Base Containerfiles
├── go.mod
└── README.md
```

## Roadmap

- [ ] Support for more languages (Python, Go, Rust)
- [ ] GUI using raylib
- [ ] Container persistence options
- [ ] Multi-container setups (databases, services)
- [ ] Custom Containerfile templates
- [ ] Integration with AI coding agents

## License

MIT
