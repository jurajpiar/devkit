package provision

// AuditScript is installed by root at /usr/local/bin/devkit-audit and run as
// the sandbox user by "devkit audit" and, shallowly, by "devkit up".
//
// It reports stale trust without any list maintained in devkit: the
// reference is Mozilla's current root store, fetched through the proxy and
// cached for a day, with the system bundle as the fallback. Anything a
// runtime or the project trusts that Mozilla no longer trusts for TLS is
// reported, as is anything the system bundle still trusts that Mozilla has
// distrusted, with the name to put in network.distrust.
const AuditScript = auditHead + ImageScanScript + auditBody

const auditHead = `#!/usr/bin/env python3
"""devkit trust audit: what does this VM trust that it should not?"""
import hashlib, os, re, ssl, subprocess, sys, time, urllib.request

DEEP = "--deep" in sys.argv
START = time.monotonic()
HOME = os.path.expanduser("~")
WORKSPACE = os.path.join(HOME, "workspace")
PRUNE = {".git", "node_modules", "target", ".venv", "venv", "vendor", "dist", "build", ".cache", "__pycache__", ".next"}
CERTDATA_URL = "https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt"
CACHE = os.path.join(HOME, ".cache", "devkit", "certdata.txt")
CACHE_FRESH, CACHE_MAX = 86400, 7 * 86400
stale = 0
ref_note = ""

def _crash(t, v, tb):
    # A crash is not a finding: exit 3 means stale trust, 2 means no verdict.
    # 1 is left to the shell wrapper (a Nix dev shell that fails to start).
    print(f"audit failed: {t.__name__}: {v}", flush=True)
    os._exit(2)
sys.excepthook = _crash

def say(line):
    print(line, flush=True)

def flag(line):
    global stale
    stale += 1
    say("  ! " + line)

def fingerprints(pem_text):
    """SHA-256 fingerprints of every certificate in a PEM blob."""
    out = []
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_text, re.S):
        try:
            der = ssl.PEM_cert_to_DER_cert(m.group(0))
        except Exception:
            continue
        out.append((hashlib.sha256(der).hexdigest().upper(), m.group(0)))
    return out

def subject(pem):
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-nameopt", "oneline"],
                           input=pem, capture_output=True, text=True, timeout=5)
        s = r.stdout.strip().removeprefix("subject=")
        m = re.search(r"CN = ([^,]+)", s)
        return m.group(1).strip() if m else s[:80]
    except Exception:
        return "?"

def self_signed(pem):
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer"],
                           input=pem, capture_output=True, text=True, timeout=5)
        lines = r.stdout.splitlines()
        return len(lines) == 2 and lines[0].split("=", 1)[1] == lines[1].split("=", 1)[1]
    except Exception:
        return False

def mozilla_store():
    """Returns (trusted_for_tls, distrusted_for_tls) as {fingerprint: label},
    or (None, None) if certdata.txt could not be fetched or read."""
    global ref_note
    text = None
    age = time.time() - os.path.getmtime(CACHE) if os.path.exists(CACHE) else None
    if age is not None and age < CACHE_FRESH:
        text = open(CACHE, encoding="utf-8", errors="replace").read()
    else:
        try:
            with urllib.request.urlopen(CERTDATA_URL, timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
            os.makedirs(os.path.dirname(CACHE), exist_ok=True)
            open(CACHE, "w").write(text)
        except Exception as e:
            # A stale reference would keep trusting a root Mozilla has since
            # pulled, so an old cache is not reused for long: past CACHE_MAX
            # the system bundle, refreshed every boot, is the better reference.
            if age is not None and age < CACHE_MAX:
                text = open(CACHE, encoding="utf-8", errors="replace").read()
                ref_note = f" (refresh failed, cached {age / 86400:.1f} days ago)"
            else:
                ref_note = f" (refresh failed: {e}" + (f"; cache is {age / 86400:.0f} days old)" if age is not None else ")")
    if not text:
        return None, None
    certs, trust = {}, {}
    block, in_octal, octal = {}, None, []
    def flush():
        # The distrust-after dates sit on the certificate object; the trust
        # bits sit on the separate trust object with the same label.
        if block.get("CKA_CLASS") == "CKO_CERTIFICATE" and "CKA_VALUE" in block:
            certs[block.get("CKA_LABEL", "?")] = (hashlib.sha256(block["CKA_VALUE"]).hexdigest().upper(), block)
        elif block.get("CKA_CLASS") == "CKO_NSS_TRUST":
            trust[block.get("CKA_LABEL", "?")] = block
    for line in text.splitlines():
        if in_octal is not None:
            if line.strip() == "END":
                block[in_octal] = bytes(int(o, 8) for o in re.findall(r"\\([0-7]{3})", "".join(octal)))
                in_octal = None
            else:
                octal.append(line)
            continue
        if not line.strip() or line.startswith("#"):
            if not line.strip() and block:
                flush(); block = {}
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[1] == "MULTILINE_OCTAL":
            in_octal, octal = parts[0], []
        elif len(parts) == 3:
            block[parts[0]] = parts[2].strip().strip('"')
    if block:
        flush()
    now = time.strftime("%y%m%d%H%M%SZ", time.gmtime())
    trusted, distrusted = {}, {}
    for label, (fp, cert) in certs.items():
        t = trust.get(label)
        if not t:
            continue
        server = t.get("CKA_TRUST_SERVER_AUTH", "") == "CKT_NSS_TRUSTED_DELEGATOR"
        after = cert.get("CKA_NSS_SERVER_DISTRUST_AFTER")
        if isinstance(after, bytes):
            after = after.decode("ascii", "replace")
        if server and not (isinstance(after, str) and after <= now):
            trusted[fp] = label
        elif server:
            distrusted[fp] = label
    return trusted, distrusted

def report_set(name, pairs, reference, counts=True):
    """Reports certificates in pairs that the reference does not trust. With
    counts=False the list is informational: the store is not in use."""
    unknown = [(fp, pem) for fp, pem in pairs if fp not in reference]
    say(f"  {name}: {len(pairs)} roots, {len(unknown)} not trusted by the reference")
    for fp, pem in unknown[:12]:
        if counts:
            flag(f"{subject(pem)}  {fp[:16]}")
        else:
            say(f"    - {subject(pem)}  {fp[:16]}")

`

const auditBody = `
say("Trust audit" + (" (deep)" if DEEP else ""))
trusted, distrusted = mozilla_store()
if trusted:
    say(f"  reference: Mozilla root store, {len(trusted)} roots trusted for TLS, {len(distrusted)} distrusted{ref_note}")
sys_pem = open("/etc/ssl/certs/ca-certificates.crt", encoding="utf-8", errors="replace").read()
system = fingerprints(sys_pem)
system_set = {fp for fp, _ in system}
if not trusted:
    say("  reference: the system bundle, Mozilla's store is unavailable" + ref_note)
    trusted, distrusted = system_set, {}
try:
    ver = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "ca-certificates"], capture_output=True, text=True).stdout.strip()
except Exception:
    ver = "?"
applied = []
try:
    applied = [l.strip() for l in open("/var/lib/devkit/.distrust") if l.strip()]
except Exception:
    pass
lagging = [(fp, pem) for fp, pem in system if fp not in trusted] if trusted is not system_set else []
say(f"  system bundle: {len(system)} roots (ca-certificates {ver}), {len(lagging)} no longer trusted by Mozilla for TLS, {len(applied)} distrusted by devkit.yaml")
# A distro bundle always trails Mozilla by a few retirements. These are
# listed so you can put the ones you care about in network.distrust; they
# are not counted as findings.
for fp, pem in (lagging if DEEP else lagging[:8]):
    say(f"    - {subject(pem)}  {fp[:16]}" + ("  (also distrusted-after by Mozilla)" if fp in distrusted else ""))
if not DEEP and len(lagging) > 8:
    say(f"    ... {len(lagging) - 8} more; devkit audit --deep lists all")

if subprocess.run(["sh", "-c", "command -v node"], capture_output=True).returncode == 0:
    r = subprocess.run(["node", "-e", "console.log(require('tls').rootCertificates.join('\\n'))"],
                       capture_output=True, text=True, timeout=20, env={**os.environ, "NODE_OPTIONS": ""})
    pairs = fingerprints(r.stdout)
    uses_system = "--use-openssl-ca" in os.environ.get("NODE_OPTIONS", "")
    report_set("node bundled roots" + (" (unused: NODE_OPTIONS=--use-openssl-ca)" if uses_system else ""), pairs, trusted, counts=not uses_system)

if subprocess.run(["sh", "-c", "command -v keytool"], capture_output=True).returncode == 0:
    r = subprocess.run(["keytool", "-list", "-rfc", "-cacerts", "-storepass", "changeit"],
                       capture_output=True, text=True, timeout=30)
    report_set("java cacerts", fingerprints(r.stdout), trusted)

def walk(root, prune):
    for dirpath, dirnames, filenames in os.walk(root):
        if prune:
            dirnames[:] = [d for d in dirnames if d not in PRUNE or d in (".venv", "venv")]
        for f in filenames:
            path = os.path.join(dirpath, f)
            # Regular files only: a FIFO or a device named root.crt would
            # block the read, and with it devkit up.
            if os.path.isfile(path):
                yield path

bundles, pems = [], []
roots = [WORKSPACE, os.path.join(HOME, ".local", "share", "mise", "installs")]
for root in roots:
    if not os.path.isdir(root):
        continue
    # Virtualenvs are where certifi lives, so they are never pruned.
    for path in walk(root, prune=not DEEP):
        base = os.path.basename(path)
        if base == "cacert.pem" and os.path.basename(os.path.dirname(path)) == "certifi":
            bundles.append(path)
        elif root == WORKSPACE and base.lower().endswith((".pem", ".crt", ".cer")):
            pems.append(path)
for path in bundles:
    try:
        pairs = fingerprints(open(path, encoding="utf-8", errors="replace").read())
    except Exception:
        continue
    report_set("certifi " + os.path.relpath(path, HOME), pairs, trusted)
found = 0
for path in pems:
    try:
        if os.path.getsize(path) > 1_000_000:
            continue
        data = open(path, "rb").read()
        if b"-----BEGIN" not in data:
            # .cer and .crt are often DER; convert so a stale root is seen.
            r = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                               input=data, capture_output=True, timeout=5)
            data = r.stdout if r.returncode == 0 else b""
        pairs = fingerprints(data.decode("utf-8", "replace"))
    except Exception:
        continue
    for fp, pem in pairs:
        if fp not in trusted and self_signed(pem):
            found += 1
            if found <= 12:
                flag(f"{printable(os.path.relpath(path, WORKSPACE))}: root {subject(pem)} not in the reference store (stale, or a private CA)  {fp[:16]}")
say(f"  project files: {len(pems)} certificate files scanned, {found} untrusted roots")
# Reported, never counted: an unpinned image is common and not stale trust.
for line in image_report(image_scan(WORKSPACE, DEEP), DEEP):
    say(line)
say(f"  {time.monotonic() - START:.1f}s" + ("" if DEEP else ", shallow; devkit audit --deep scans everything"))
if stale:
    say(f"{stale} finding(s). A root the reference no longer trusts is stale: update the bundle or runtime that carries it.")
    sys.exit(3)
say("Nothing stale.")
`
