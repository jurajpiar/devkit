package provision

// ImageScanScript is the part of the trust audit that reports container
// images the project names without a digest. It is static: it reads compose
// files and Dockerfiles in the workspace and needs no Docker, because an
// image list cannot say how an image was requested (after a pull it carries
// both tag and digest either way). Anything it cannot resolve is reported as
// unresolved, never as fine. It reports; it never counts towards the audit's
// exit status.
//
// It is kept separate so the tests can run it with the host's python3. It
// must stay valid for the guest's Python 3.12 and older: no backquotes (Go
// literal) and no heredoc terminator.
const ImageScanScript = `
import os, re, stat, unicodedata
try:
    import yaml as _yaml
except Exception:
    _yaml = None

# Dependency and cache trees hold other projects' Dockerfiles. Unlike the
# certificate scan, build/ is read: it is a common home for a Dockerfile.
IMAGE_PRUNE = {".git", "node_modules", "target", ".venv", "venv", "vendor", "dist", ".cache", "__pycache__", ".next"}
IMAGE_MAX_BYTES = 256 * 1024
IMAGE_MAX_WALK = 200000
IMAGE_MAX_FILES = 500
_COMPOSE_NAME = re.compile(r"(docker-)?compose(\..*)?\.ya?ml")
_VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PINNED = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
_UNKNOWN = object()

def printable(s, limit=200):
    """Project text made safe for the terminal: control, format (bidi) and
    unencodable characters become '?', and long text is cut."""
    s = "".join("?" if unicodedata.category(c)[0] == "C" else c for c in str(s))
    return s if len(s) <= limit else s[:limit] + "..."

def _image_file_kind(name):
    if _COMPOSE_NAME.fullmatch(name):
        return "compose"
    low = name.lower()
    if low.endswith(".dockerignore"):
        return None
    if low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile.")) or low.endswith(".dockerfile"):
        return "dockerfile"
    return None

def _read_bounded(path):
    """(text, None) or (None, why). Non-blocking and fstat-checked, so a FIFO
    or device named like a compose file cannot hang the audit."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None, "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_size > IMAGE_MAX_BYTES:
            return None, "over 256 KB"
        chunks, size = [], 0
        while size <= IMAGE_MAX_BYTES:
            b = os.read(fd, IMAGE_MAX_BYTES + 1 - size)
            if not b:
                break
            chunks.append(b)
            size += len(b)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > IMAGE_MAX_BYTES:
        return None, "over 256 KB"
    if b"\0" in data:
        return None, "binary"
    return data.decode("utf-8", "replace"), None

class _Unresolved(Exception):
    pass

def _interpolate(s, env, compose):
    """Substitutes $VAR, ${VAR} and the ${VAR:-x} family from env, where a
    missing name is unset. Raises _Unresolved when the value cannot be
    known without the environment the build or compose would run in."""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c != "$":
            out.append(c)
            i += 1
            continue
        if compose and s[i + 1:i + 2] == "$":
            out.append("$")
            i += 2
            continue
        if s[i + 1:i + 2] == "{":
            depth, j = 1, i + 2
            while j < n and depth:
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                j += 1
            if depth:
                raise _Unresolved()
            out.append(_expand(s[i + 2:j - 1], env, compose))
            i = j
            continue
        m = _VAR_NAME.match(s, i + 1)
        if not m:
            raise _Unresolved()
        out.append(_value(env, m.group(0)))
        i = m.end()
    return "".join(out)

def _value(env, name):
    v = env.get(name)
    if v is None or v is _UNKNOWN:
        raise _Unresolved()
    return v

def _expand(body, env, compose):
    m = _VAR_NAME.match(body)
    if not m:
        raise _Unresolved()
    name, rest = m.group(0), body[m.end():]
    if not rest:
        return _value(env, name)
    for op in (":-", ":?", ":+", "-", "?", "+"):
        if rest.startswith(op):
            word = rest[len(op):]
            break
    else:
        raise _Unresolved()  # ${VAR#pattern} and other forms
    val = env.get(name)
    present = val is not None and (val != "" or not op.startswith(":"))
    if op.endswith("+"):
        return _interpolate(word, env, compose) if present else ""
    if not present:
        if op.endswith("?"):
            raise _Unresolved()  # compose or the build would fail here
        return _interpolate(word, env, compose)
    if val is _UNKNOWN:
        raise _Unresolved()
    return val

def _dotenv(path):
    """The .env beside a compose file. Values that interpolate are not
    guessed: they are unknown, so what uses them is unresolved."""
    text, _ = _read_bounded(path)
    env = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        k, sep, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if not sep or not _VAR_NAME.fullmatch(k):
            continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            q, v = v[0], v[1:-1]
            env[k] = _UNKNOWN if q == '"' and "$" in v else v
        else:
            v = re.split(r"\s#", v, maxsplit=1)[0].strip()
            env[k] = _UNKNOWN if "$" in v else v
    return env

def _resolve(raw, known, env, compose):
    """(shown, status) for one reference."""
    if not known:
        return raw, "unresolved"
    try:
        val = _interpolate(raw, env, compose)
    except _Unresolved:
        return raw, "unresolved"
    shown = raw if val == raw else raw + " (= " + val + ")"
    val = val.strip()
    if not val:
        return shown, "unresolved"
    return shown, "pinned" if _PINNED.fullmatch(val) else "unpinned"

def _compose_yaml(text):
    """[(raw, known)] for every service's image, and the files that include:
    and extends: name. Raises on anything PyYAML rejects."""
    loader = getattr(_yaml, "CSafeLoader", None) or _yaml.SafeLoader
    doc = _yaml.load(text, Loader=loader)
    refs, more = [], []
    if not isinstance(doc, dict):
        return refs, more
    services = doc.get("services")
    for svc in (services.values() if isinstance(services, dict) else []):
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        if isinstance(image, (dict, list)):
            refs.append(("(not a string)", False))
        elif image is not None:
            refs.append((str(image), True))
        ext = svc.get("extends")
        if isinstance(ext, dict) and isinstance(ext.get("file"), str):
            more.append(ext["file"])
    include = doc.get("include")
    for entry in (include if isinstance(include, list) else []):
        path = entry.get("path") if isinstance(entry, dict) else entry
        for p in (path if isinstance(path, list) else [path]):
            if isinstance(p, str):
                more.append(p)
    return refs, more

def _yaml_uncomment(v):
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[:end + 1] if end > 0 else v
    return re.split(r"\s#", v, maxsplit=1)[0]

def _compose_lines(text):
    """The approximate reading without a YAML parser: every image: line.
    Aliases, block scalars, flow values and tags cannot be followed, so they
    are unresolved; image: keys outside services are read too."""
    refs = []
    for line in text.splitlines():
        m = re.match(r"\s*(?:-\s+)?image\s*:(?:\s+(.*))?$", line)
        if not m:
            continue
        v = _yaml_uncomment((m.group(1) or "").strip()).strip()
        if v.startswith("&"):
            v = (v.split(None, 1) + [""])[1]
        if not v or v[0] in "*|>{[!":
            refs.append((v or "(value on the next lines)", False))
            continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        refs.append((v, True))
    return refs

def _dockerfile_refs(text):
    """[(shown, status)] for every FROM and COPY --from that names an
    image. Earlier stages and scratch are not images. Variables resolve from
    the ARGs declared before the first FROM, as in a build."""
    lines = text.splitlines()
    esc = "\\"
    for line in lines:  # parser directives sit at the very top
        m = re.match(r"\s*#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$", line)
        if not m:
            break
        if m.group(1).lower() == "escape" and m.group(2) in ("\\", "\x60"):
            esc = m.group(2)
    instrs, cur, heredocs = [], None, []
    for line in lines:
        if heredocs:
            term, strip_tabs = heredocs[0]
            if (line.lstrip("\t") if strip_tabs else line) == term:
                heredocs.pop(0)
            continue
        s = line.strip()
        if not s or s.startswith("#"):
            continue  # comments and blank lines, also inside a continuation
        if s.endswith(esc):
            cur = (cur or "") + line.rstrip()[:-1]
            continue
        full = ((cur or "") + line).strip()
        cur = None
        instrs.append(full)
        if full.split(None, 1)[0].upper() in ("RUN", "COPY", "ADD"):
            for m in re.finditer(r"<<(-?)([\"']?)([A-Za-z_][A-Za-z0-9_]*)\2", full):
                heredocs.append((m.group(3), m.group(1) == "-"))
    if cur:
        instrs.append(cur.strip())
    args, stages, seen_from, out = {}, set(), False, []
    for ins in instrs:
        parts = ins.split(None, 1)
        kw, rest = parts[0].upper(), (parts[1] if len(parts) > 1 else "")
        if kw == "ARG" and not seen_from:
            for tok in rest.split():
                name, sep, val = tok.partition("=")
                if not _VAR_NAME.fullmatch(name):
                    continue
                if not sep:
                    args[name] = None
                    continue
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                    val = val[1:-1]
                try:
                    args[name] = _interpolate(val, args, False)
                except _Unresolved:
                    args[name] = _UNKNOWN
        elif kw == "FROM":
            seen_from = True
            toks = [t for t in rest.split() if not t.startswith("--")]
            if not toks:
                out.append(("(empty FROM)", "unresolved"))
                continue
            shown, status = _resolve(toks[0], True, args, False)
            try:
                name = _interpolate(toks[0], args, False).strip().lower()
            except _Unresolved:
                name = None
            if name != "scratch" and name not in stages:
                out.append((shown, status))
            if len(toks) >= 3 and toks[1].lower() == "as":
                stages.add(toks[2].lower())
        elif kw == "COPY":
            for tok in rest.split():
                if tok.lower().startswith("--from="):
                    src = tok[7:]
                    if src.isdigit() or src.lower() in stages:
                        continue
                    out.append(_resolve(src, True, args, False))
    return out

def image_scan(root, deep=False):
    """Every image reference in the compose files and Dockerfiles under
    root: {"files", "items": [(file, shown, status)], "unread": [(file,
    why)], "approximate", "truncated"}."""
    res = {"files": 0, "items": [], "unread": [], "approximate": False, "truncated": False}
    if not os.path.isdir(root):
        return res
    root = os.path.realpath(root)
    found, visited = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        if not deep:
            dirnames[:] = [d for d in dirnames if d not in IMAGE_PRUNE]
        dirnames.sort()
        for f in sorted(filenames):
            visited += 1
            kind = _image_file_kind(f)
            path = os.path.join(dirpath, f)
            if kind and not os.path.islink(path):
                found.append((kind, path))
        if visited > IMAGE_MAX_WALK or len(found) > IMAGE_MAX_FILES:
            res["truncated"] = True
            break
    found = found[:IMAGE_MAX_FILES]
    seen = {p for _, p in found}
    while found:
        kind, path = found.pop(0)
        rel = os.path.relpath(path, root)
        res["files"] += 1
        text, why = _read_bounded(path)
        if text is None:
            res["unread"].append((rel, why))
            continue
        if kind == "dockerfile":
            res["items"].extend((rel, s, st) for s, st in _dockerfile_refs(text))
            continue
        env = _dotenv(os.path.join(os.path.dirname(path), ".env"))
        refs, more = None, []
        if _yaml is not None:
            try:
                refs, more = _compose_yaml(text)
            except Exception:
                refs = None
        if refs is None:
            res["approximate"] = True
            refs = _compose_lines(text)
        res["items"].extend((rel,) + _resolve(raw, known, env, True) for raw, known in refs)
        # Files named by include: and extends:, inside the workspace only.
        for m in more:
            try:
                m = _interpolate(m, env, True)
            except _Unresolved:
                continue
            q = os.path.realpath(os.path.join(os.path.dirname(path), m))
            if q.startswith(root + os.sep) and q not in seen and os.path.isfile(q) and len(seen) < IMAGE_MAX_FILES:
                seen.add(q)
                found.append(("compose", q))
    return res

def _count(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")

def image_report(res, deep=False):
    """The audit's lines: a summary, then what is not pinned."""
    if not res["files"]:
        return ["  container images: no compose files or Dockerfiles"]
    items = res["items"]
    n = {k: sum(1 for i in items if i[2] == k) for k in ("pinned", "unpinned", "unresolved")}
    line = (f"  container images: {_count(len(items), 'reference')} in {_count(res['files'], 'file')}, "
            f"{n['pinned']} pinned by digest, {n['unpinned']} unpinned, {n['unresolved']} unresolved")
    if res["unread"]:
        line += f", {_count(len(res['unread']), 'file')} not read"
    if res["approximate"]:
        line += " (compose read without a YAML parser: approximate)"
    if res["truncated"]:
        line += f" (stopped after {IMAGE_MAX_FILES} files or {IMAGE_MAX_WALK} entries)"
    out = [line]
    bad = [f"{printable(f)}: {printable(s)}  ({st})" for f, s, st in items if st != "pinned"]
    bad += [f"{printable(f)}: not read ({why})" for f, why in res["unread"]]
    cap = 200 if deep else 12
    out += ["    - " + b for b in bad[:cap]]
    if len(bad) > cap:
        out.append(f"    ... {len(bad) - cap} more" + ("" if deep else "; devkit audit --deep lists up to 200"))
    if bad:
        out.append("    a tag can name different code tomorrow: pin with name:tag@sha256:<digest>")
    return out
`
