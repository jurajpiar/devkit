package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// framingHarness loads the functions of testdata/guest-root-probe.py
// without running its checks, points its port-53 connections at a local
// server, and asks dns_tcp about four replies, each sent in several writes:
// the length prefix alone first, as one recv may return it.
const framingHarness = `import ast, socket, struct, sys, threading, time
src = open(sys.argv[1]).read()
tree = ast.parse(src)
tree.body = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
ns = {}
exec(compile(tree, sys.argv[1], "exec"), ns)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(4)
PORT = srv.getsockname()[1]

class Redirect(socket.socket):
    def connect(self, addr):
        host, port = addr
        return super().connect(("127.0.0.1", PORT) if port == 53 else addr)
ns["socket"].socket = Redirect

def recv_exact(c, n):
    b = b""
    while len(b) < n:
        b += c.recv(n - len(b))
    return b

def reply(q, answers):
    head = q[:2] + b"\x81\x80" + struct.pack(">HHHH", 1, answers, 0, 0)
    rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 215, 14])
    return head + q[12:] + rr * answers

def serve(chunks_of):
    c, _ = srv.accept()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    n = struct.unpack(">H", recv_exact(c, 2))[0]
    q = recv_exact(c, n)
    try:
        for chunk in chunks_of(q):
            c.sendall(chunk)
            time.sleep(0.2)
    except OSError:
        pass  # the probe gave up and closed: its verdict is what counts
    c.close()

def framed(answers, split):
    def chunks(q):
        body = reply(q, answers)
        msg = struct.pack(">H", len(body)) + body
        cuts = [0] + split + [len(msg)]
        return [msg[a:b] for a, b in zip(cuts, cuts[1:])]
    return chunks

cases = [
    ("answer, prefix sent alone", framed(1, [2])),
    ("answer, prefix and header in pieces", framed(1, [1, 2, 7])),
    ("no answer, prefix sent alone", framed(0, [2])),
    ("prefix only, then closed", lambda q: [struct.pack(">H", 40)]),
]
for name, chunks in cases:
    t = threading.Thread(target=serve, args=(chunks,))
    t.start()
    ok, detail = ns["dns_tcp"]("192.0.2.53")
    t.join()
    print(f"{name}: {ok} ({detail})")
`

// The probe's DNS-over-TCP check must read the whole framed reply: a
// working resolver whose length prefix arrives on its own must not be
// reported as blocked, which would let the enforcement test pass wrongly.
// Runs with the host's python3; no VM.
func TestRootProbeReadsFramedDNSReplies(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	probe, err := filepath.Abs(filepath.Join("testdata", "guest-root-probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, "-I", "-B", "-c", framingHarness, probe)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	t.Logf("\n%s", out)
	for _, want := range []string{
		"answer, prefix sent alone: True",
		"answer, prefix and header in pieces: True",
		"no answer, prefix sent alone: False",
		"prefix only, then closed: False",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("want %q", want)
		}
	}
}

// echoHarness loads the probe's functions as framingHarness does and asks
// icmp_is_echo_reply about packets as a raw IPv4 ICMP socket on Linux
// delivers them: IP header first, of the length its IHL field gives.
const echoHarness = `import ast, socket, struct, sys
src = open(sys.argv[1]).read()
tree = ast.parse(src)
tree.body = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
ns = {}
exec(compile(tree, sys.argv[1], "exec"), ns)
check = ns["icmp_is_echo_reply"]
TARGET = "203.0.113.1"

def ip(src, body, options=b""):
    ihl = (20 + len(options)) // 4
    head = struct.pack(">BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(options) + len(body), 0, 0, 64, 1, 0,
                       socket.inet_aton(src), socket.inet_aton("192.168.5.15"))
    return head + options + body

def icmp(typ, code, ident, seq, payload):
    return struct.pack(">BBHHH", typ, code, 0, ident, seq) + payload

request = ns["icmp_echo_request"](0x1234, 1, b"devkit")
cases = [
    ("matching reply", ip(TARGET, icmp(0, 0, 0x1234, 1, b"devkit"))),
    ("matching reply, IP options", ip(TARGET, icmp(0, 0, 0x1234, 1, b"devkit"), options=b"\x01\x01\x01\x00")),
    ("destination unreachable from a router", ip("192.168.5.2", icmp(3, 1, 0, 0, ip("192.168.5.15", request)[:28]))),
    ("destination unreachable from the target", ip(TARGET, icmp(3, 1, 0, 0, ip("192.168.5.15", request)[:28]))),
    ("reply from another source", ip("192.168.5.2", icmp(0, 0, 0x1234, 1, b"devkit"))),
    ("reply with another identifier", ip(TARGET, icmp(0, 0, 0x4321, 1, b"devkit"))),
    ("reply with another sequence", ip(TARGET, icmp(0, 0, 0x1234, 2, b"devkit"))),
    ("reply with another payload", ip(TARGET, icmp(0, 0, 0x1234, 1, b"devkiT"))),
    ("our own echo request", ip(TARGET, request)),
    ("truncated reply", ip(TARGET, icmp(0, 0, 0x1234, 1, b"devkit"))[:26]),
    ("not IPv4", b"\x60" + ip(TARGET, icmp(0, 0, 0x1234, 1, b"devkit"))[1:]),
]
for name, pkt in cases:
    print(f"{name}: {check(pkt, TARGET, 0x1234, 1, b'devkit')}")
# The request the probe sends carries a valid checksum.
s = 0
for i in range(0, len(request), 2):
    s += (request[i] << 8) + (request[i + 1] if i + 1 < len(request) else 0)
s = (s >> 16) + (s & 0xFFFF)
print("request checksum valid:", (s + (s >> 16)) & 0xFFFF == 0xFFFF)
`

// The probe's ICMP check shows Lima's network stack answers echoes itself.
// It must count only the echo reply to its own request: if enforcement
// regressed and the packet were forwarded, a router's Destination
// Unreachable must not pass for the local answer. Runs with the host's
// python3; no VM.
func TestRootProbeAcceptsOnlyItsOwnEchoReply(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	probe, err := filepath.Abs(filepath.Join("testdata", "guest-root-probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, "-I", "-B", "-c", echoHarness, probe).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	t.Logf("\n%s", out)
	for _, want := range []string{
		"matching reply: True",
		"matching reply, IP options: True",
		"destination unreachable from a router: False",
		"destination unreachable from the target: False",
		"reply from another source: False",
		"reply with another identifier: False",
		"reply with another sequence: False",
		"reply with another payload: False",
		"our own echo request: False",
		"truncated reply: False",
		"not IPv4: False",
		"request checksum valid: True",
	} {
		if !strings.Contains(string(out), want+"\n") {
			t.Errorf("want %q", want)
		}
	}
}
