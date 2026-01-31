# Node.js Example for Devkit

A simple Express.js TODO API demonstrating devkit's secure container development workflow.

## Quick Start

```bash
# From this directory
cd examples/nodejs-app

# Initialize devkit configuration
devkit init

# Build the secure container image
devkit build

# Start the development container
devkit start

# Connect with VS Code
devkit connect
```

## What This Example Demonstrates

1. **Automatic Detection** - Devkit detects Node.js from `package.json` and version from `.nvmrc`
2. **Secure Defaults** - Container runs with dropped capabilities, read-only rootfs, and network isolation
3. **VS Code Integration** - Seamless remote development via SSH
4. **Debug Support** - Node.js inspector with optional debug proxy for security

## Project Structure

```
nodejs-app/
├── package.json      # Node.js dependencies
├── .nvmrc            # Node version specification
├── src/
│   ├── index.js      # Express server
│   └── index.test.js # Tests
└── README.md
```

## Security Configuration

After running `devkit init`, you can customize `devkit.yaml`:

```yaml
security:
  # Strict mode (default for new projects)
  drop_all_capabilities: true
  no_new_privileges: true
  read_only_rootfs: true
  
  # Network isolation options
  network_mode: "restricted"  # or "none" for air-gapped
  
  # Debug proxy (for secure debugging)
  debug_proxy:
    enabled: true
    filter_level: "filtered"  # strict, filtered, audit, passthrough
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API documentation |
| GET | `/health` | Health check |
| GET | `/todos` | List all todos |
| GET | `/todos/:id` | Get a todo |
| POST | `/todos` | Create a todo |
| PUT | `/todos/:id` | Update a todo |
| DELETE | `/todos/:id` | Delete a todo |

## Testing in Container

```bash
# SSH into the container
devkit connect

# Inside container
npm test
npm run dev  # Start with debugger
```

## Debugging

With the debug proxy enabled, you can safely debug in VS Code:

1. Start the container: `devkit start`
2. Connect VS Code: `devkit connect`
3. Run with inspector: `npm run dev`
4. Attach VS Code debugger to port 9229

The debug proxy filters dangerous CDP commands while allowing normal debugging.
