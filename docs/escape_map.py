"""Generates the devkit escape map SVG from one row list, in three colourings:
the page (CSS variables, follows the viewer's theme), and static light and
dark files for the README. Edit ROWS, then:

    python3 docs/escape_map.py light > docs/escape-map-light.svg
    python3 docs/escape_map.py dark  > docs/escape-map-dark.svg

Keep ROWS in step with the table under "How escapes are stopped" in README.md."""
import sys

W, X0 = 1180, 312                       # canvas width, where arrows start
COLS = {                                # centre x and band of each layer
    "guest": 405, "fw": 545, "proxy": 690, "lima": 840, "out": 1065,
}
BAND = 116
HYP = 935                               # the hypervisor boundary
TOP, STEP = 132, 70

HEAD = [("Sandbox user process", "no sudo, no CAP_NET_ADMIN", 150),
        ("Guest policy", "root-only files", COLS["guest"]),
        ("Firewall", "iptables OUTPUT", COLS["fw"]),
        ("Egress proxy", "uid devkit-proxy", COLS["proxy"]),
        ("Lima / hypervisor", "vz, no mounts", COLS["lima"]),
        ("Outside", "internet / your Mac", COLS["out"])]

# (label, stop column or None, stop text lines, grey note lines)
ROWS = [
    ("HTTPS to an allowed host, port 443", None, [], []),
    ("Direct connection to the internet", "fw", ["not the proxy's uid:", "REJECT"], []),
    ("Via the proxy to another host, or port 22", "proxy", ["allowlist, web ports", "only: 403"], []),
    ("DNS query with data in the name", "fw", ["port 53 only for the", "proxy; stub off"], ["(the proxy resolves names itself)"]),
    ("Reuse the proxy's DNS source port", "fw", ["state trusted only for", "root and the proxy"], []),
    ("Connect to your Mac (host.lima.internal)", "fw", ["host rejected, for", "the proxy too"], ["(CONNECT to the host: 403 or 502)"]),
    ("Code planted to run at the next boot", "fw", ["boot hold: no network", "until the firewall"], []),
    ("Listen for your Mac to connect", "lima", ["no port forwarded", "unless listed"], []),
    ("Read or write your files", "lima", ["nothing mounted;", "nothing copied back"], []),
    ("Rewrite the policy or swap the proxy", "guest", ["root-only files;", "proxy SHA-checked"], []),
    ("Become root: sudo, or a kernel bug", "guest", ["no sudo; io_uring, BPF,", "userns, AF_ALG off;", "patched at boot"], []),
]

def svg(c):
    """c maps fg, muted, bg, band, stop, allow to colour strings."""
    H = TOP + STEP * (len(ROWS) - 1) + 100
    o = []
    a = o.append
    a(f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Ten escape attempts, each stopped at the layer that blocks it: the guest policy files, the firewall with its boot hold, the egress proxy, or Lima and the hypervisor; and the one allowed path, HTTPS to an allowed host on port 443, logged.">')
    a('<defs>')
    for mid, col in (("arrow", c["fg"]), ("arrow-allow", c["allow"])):
        a(f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
    a('</defs>')
    a(f'<g fill="{c["band"]}">')
    for k in ("guest", "fw", "proxy", "lima", "out"):
        w = BAND + (40 if k == "out" else 0)
        a(f'<rect x="{COLS[k]-w//2}" y="48" width="{w}" height="{H-78}" rx="4"/>')
    a('</g>')
    for title, sub, x in HEAD:
        a(f'<text x="{x}" y="70" font-size="12.5" font-weight="600" fill="{c["fg"]}" text-anchor="middle">{title}</text>')
        a(f'<text x="{x}" y="86" font-size="10.5" fill="{c["muted"]}" text-anchor="middle">{sub}</text>')
    a(f'<line x1="{HYP}" y1="48" x2="{HYP}" y2="{H-30}" stroke="{c["fg"]}" stroke-width="2" stroke-dasharray="6 4"/>')
    a(f'<text x="{HYP-6}" y="{H-38}" font-size="10.5" fill="{c["muted"]}" text-anchor="end">Virtualization.framework boundary</text>')

    def cross(x, y):
        a(f'<circle cx="{x}" cy="{y}" r="9" fill="{c["bg"]}" stroke="{c["stop"]}" stroke-width="2"/>')
        a(f'<path d="M{x-5},{y-5} L{x+5},{y+5} M{x+5},{y-5} L{x-5},{y+5}" stroke="{c["stop"]}" stroke-width="2"/>')

    def lines(x, y, texts, colour):
        for i, t in enumerate(texts):
            a(f'<text x="{x}" y="{y+i*13}" font-size="10.5" fill="{colour}" text-anchor="middle">{esc(t)}</text>')

    for i, (label, stop, stoptext, notes) in enumerate(ROWS):
        y = TOP + i * STEP
        a(f'<text x="20" y="{y+4}" font-size="12.5" fill="{c["fg"]}">{esc(label)}</text>')
        if stop is None:  # the allowed path
            a(f'<line x1="{X0}" y1="{y}" x2="{COLS["out"]-70}" y2="{y}" stroke="{c["allow"]}" stroke-width="2" marker-end="url(#arrow-allow)"/>')
            lines(COLS["fw"], y + 20, ["proxy's uid:", "accepted"], c["allow"])
            lines(COLS["proxy"], y + 20, ["allowed host and", "port, logged"], c["allow"])
            lines(COLS["out"], y + 20, ["internet"], c["allow"])
            continue
        x = COLS[stop]
        a(f'<line x1="{X0}" y1="{y}" x2="{x-14}" y2="{y}" stroke="{c["fg"]}" stroke-width="1.5" marker-end="url(#arrow)"/>')
        cross(x, y)
        lines(x, y + 24, stoptext, c["stop"])
        lines(x, y + 24 + 13 * len(stoptext), notes, c["muted"])
        if label.startswith("Become root"):
            # What a kernel exploit that still works would reach.
            a(f'<line x1="{x+12}" y1="{y}" x2="{HYP-14}" y2="{y}" stroke="{c["fg"]}" stroke-width="1.5" stroke-dasharray="5 4" marker-end="url(#arrow)"/>')
            a(f'<text x="{(x+HYP)//2+20}" y="{y-8}" font-size="10.5" fill="{c["muted"]}" text-anchor="middle">a working kernel exploit: firewall gone, Mac\'s loopback reachable</text>')
            cross(HYP, y)
            lines(COLS["out"], y + 4, ["your files stay", "out of reach"], c["muted"])
    a('</svg>')
    return "\n".join(o)

def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

PAGE = dict(fg="currentColor", muted="var(--muted)", bg="var(--bg)", band="var(--band)", stop="var(--stop)", allow="var(--allow)")
LIGHT = dict(fg="#1c2230", muted="#5b6577", bg="#ffffff", band="rgba(28,34,48,0.045)", stop="#b8321f", allow="#1f7a4d")
DARK = dict(fg="#e4e8ee", muted="#9aa5b6", bg="#0d1117", band="rgba(228,232,238,0.06)", stop="#e8604a", allow="#4fc08a")

def standalone(c):
    s = svg(c).replace("<svg ", f'<svg xmlns="http://www.w3.org/2000/svg" style="background:{c["bg"]};font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Helvetica,Arial,sans-serif" ', 1)
    return s.replace("<defs>", f'<rect width="{W}" height="100%" fill="{c["bg"]}"/><defs>', 1) + "\n"

if __name__ == "__main__":
    which = sys.argv[1]
    print({"page": lambda: svg(PAGE), "light": lambda: standalone(LIGHT), "dark": lambda: standalone(DARK)}[which]())
