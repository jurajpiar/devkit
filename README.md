# Devkit

Secure local development infrastructure kit that orchestrates rootless containers for isolated development environments.

## Features

- **Rootless Containers**: Uses Podman rootless mode - no root privileges required
- **Host Isolation**: Containers have no access to host filesystem by default
- **Pre-installed Dependencies**: Automatically detects and installs project dependencies
- **VS Code Integration**: Built-in SSH server for VS Code Remote development
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

## Commands

| Command | Description |
|---------|-------------|
| `devkit init [repo-url]` | Initialize devkit.yaml config |
| `devkit build` | Build the container image |
| `devkit start` | Start the development container |
| `devkit connect` | Show VS Code connection instructions |
| `devkit shell` | Open a shell in the container |
| `devkit stop` | Stop the container |
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
  install:
    - typescript
    - eslint

features:
  allow_copy: false     # Enable 'copy' source method
  allow_mount: false    # Enable 'mount' source method

ssh:
  port: 2222            # SSH port for VS Code
```

### Source Methods

| Method | Description | Feature Flag |
|--------|-------------|--------------|
| `git` | Clone repo inside container (default, most secure) | None required |
| `copy` | Copy files into container at startup | `allow_copy: true` |
| `mount` | Volume mount project directory (read-only) | `allow_mount: true` |

## VS Code Setup

### Method 1: Remote-SSH Extension

1. Install the "Remote - SSH" extension in VS Code
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
