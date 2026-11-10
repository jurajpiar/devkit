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
