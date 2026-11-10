package egressproxy

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// lanAddress is an IPv4 address assigned to one of this machine's interfaces
// that is neither loopback nor link-local: the Mac's own LAN address, as the
// guest would see it. Skips the test when the machine has none.
func lanAddress(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || refusedAddress(ip) || ip.IsMulticast() {
			continue
		}
		return ip
	}
	t.Skip("this machine has no non-loopback IPv4 interface address")
	return nil
}

// listenOn starts an echo listener and an HTTP server on ip, counting what
// reaches each, and returns their ports.
func listenOn(t *testing.T, ip net.IP) (echoPort, httpPort string, echoHits, httpHits *atomic.Int64) {
	t.Helper()
	echoHits, httpHits = &atomic.Int64{}, &atomic.Int64{}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			echoHits.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	hl, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpHits.Add(1)
		io.WriteString(w, "mac service")
	}))
	srv.Listener.Close()
	srv.Listener = hl
	srv.Start()
	t.Cleanup(srv.Close)
	_, echoPort, _ = net.SplitHostPort(ln.Addr().String())
	_, httpPort, _ = net.SplitHostPort(hl.Addr().String())
	return echoPort, httpPort, echoHits, httpHits
}

// reachable reports whether this process can connect to ip:port at all.
// Some Macs (local network privacy, a firewall) let a process listen on its
// LAN address but not connect to it; a refusal test still holds there, as a
// 403 and not a 502, but a positive control cannot.
func reachable(ip net.IP, port string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// as4 is ip as the 4-byte array miniDNSAnsweringAll takes.
func as4(ip net.IP) [4]byte {
	var b [4]byte
	copy(b[:], ip.To4())
	return b
}

// checkRefused asserts that a CONNECT to target and a plain-HTTP GET of
// httpTarget through proxyAddr are both refused as policy, like the loopback
// refusal, and that the refusal is logged.
func checkRefused(t *testing.T, what, proxyAddr, target, httpTarget string, logs *syncLog) {
	t.Helper()
	if status, _, _ := connect(t, proxyAddr, target); !strings.HasPrefix(status, "403") {
		t.Errorf("%s: CONNECT %s: want 403, got %s", what, target, status)
	}
	resp, err := clientVia(proxyAddr).Get("http://" + httpTarget + "/")
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(refusalHeader) != "blocked" {
		t.Errorf("%s: GET %s: want a 403 policy refusal, got %d %q", what, httpTarget, resp.StatusCode, resp.Header.Get(refusalHeader))
	}
	if !strings.Contains(logs.String(), "ERROR "+target) || !strings.Contains(logs.String(), errRefusedAddress.Error()) {
		t.Errorf("%s: the refusal must be logged:\n%s", what, logs)
	}
}

// Under host enforcement the guest must not reach the Mac through the Mac's
// own LAN address either: not by IP literal (open mode), not by a name that
// resolves to it, and not by a name that resolves to an outside address as
// well, whichever the resolver puts first. Without the option, as in the
// guest's own proxy, the same listener stays reachable.
func TestRefuseLocalBlocksTheMacsOwnLANAddress(t *testing.T) {
	lan := lanAddress(t)
	echoPort, httpPort, echoHits, httpHits := listenOn(t, lan)
	outside := [4]byte{198, 51, 100, 7}
	allow := []string{
		lan.String() + ":" + echoPort, lan.String() + ":" + httpPort,
		"mac.test:" + echoPort, "mac.test:" + httpPort,
	}
	for _, c := range []struct {
		what string
		ips  [][4]byte
	}{
		{"name resolving to the LAN address", [][4]byte{as4(lan)}},
		{"name resolving to outside then LAN", [][4]byte{outside, as4(lan)}},
		{"name resolving to LAN then outside", [][4]byte{as4(lan), outside}},
	} {
		dns, stop := miniDNSAnsweringAll(t, c.ips...)
		logs := &syncLog{}
		p := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(logs, "", 0), Resolvers: []string{dns}, RefuseLocal: true}))
		checkRefused(t, c.what, p, "mac.test:"+echoPort, "mac.test:"+httpPort, logs)
		stop()
	}
	logs := &syncLog{}
	p := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(logs, "", 0), RefuseLocal: true}))
	checkRefused(t, "IP literal", p, lan.String()+":"+echoPort, lan.String()+":"+httpPort, logs)
	if echoHits.Load() != 0 || httpHits.Load() != 0 {
		t.Fatalf("a refused request reached the Mac's listener: %d connections, %d requests", echoHits.Load(), httpHits.Load())
	}

	// Control: the guest-side proxy, without the option, reaches it.
	if !reachable(lan, echoPort) {
		t.Skipf("this machine cannot connect to its own address %s, so the positive control cannot run", lan)
	}
	dns, stop := miniDNSAnswering(t, as4(lan))
	defer stop()
	q := serve(t, NewProxy(ProxyConfig{AllowedHosts: allow, Logger: log.New(io.Discard, "", 0), Resolvers: []string{dns}}))
	for _, target := range []string{lan.String() + ":" + echoPort, "mac.test:" + echoPort} {
		if status, _, _ := connect(t, q, target); !strings.HasPrefix(status, "200") {
			t.Errorf("control: CONNECT %s should work without RefuseLocal, got %s", target, status)
		}
	}
	for _, target := range []string{lan.String() + ":" + httpPort, "mac.test:" + httpPort} {
		resp, err := clientVia(q).Get("http://" + target + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("control: GET %s should work without RefuseLocal, got %d", target, resp.StatusCode)
		}
	}
}

// A redirect is dialled through the same check: an allowed origin on the
// LAN (not local by the fake list) redirecting to an address the fake list
// calls local is refused, and nothing is dialled there.
func TestRefuseLocalAppliesToRedirects(t *testing.T) {
	lan := lanAddress(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(lan.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", lan, err)
	}
	srv := httptest.NewUnstartedServer(http.RedirectHandler("http://192.0.2.10/", http.StatusFound))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	origin := strings.TrimPrefix(srv.URL, "http://")
	if _, port, _ := net.SplitHostPort(origin); !reachable(lan, port) {
		t.Skipf("this machine cannot connect to its own address %s, so there is no origin to redirect", lan)
	}

	logs := &syncLog{}
	p := NewProxy(ProxyConfig{AllowedHosts: []string{origin, "192.0.2.10"}, AuditLog: true, Logger: log.New(logs, "", 0), RefuseLocal: true})
	p.localAddrs = func() ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.10")}, nil }
	addr := serve(t, p)
	resp, err := clientVia(addr).Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(refusalHeader) != "blocked" {
		t.Errorf("a redirect to a local address must be refused as policy, got %d\n%s", resp.StatusCode, logs)
	}
}

// With fixed fake addresses for "this machine", on any machine: an address
// on the list is refused by IP literal and by name, also when the name
// resolves to an outside address too, in either order. The addresses are
// TEST-NET, and refusal comes before any dial, so nothing leaves.
func TestRefuseLocalWithFakeAddresses(t *testing.T) {
	local := [4]byte{192, 0, 2, 10}
	outside := [4]byte{198, 51, 100, 7}
	allow := []string{"192.0.2.10:443", "192.0.2.10:80", "mac.test"}
	for _, c := range []struct {
		what string
		ips  [][4]byte
	}{
		{"local only", [][4]byte{local}},
		{"outside then local", [][4]byte{outside, local}},
		{"local then outside", [][4]byte{local, outside}},
	} {
		dns, stop := miniDNSAnsweringAll(t, c.ips...)
		logs := &syncLog{}
		p := NewProxy(ProxyConfig{AllowedHosts: allow, AuditLog: true, Logger: log.New(logs, "", 0), Resolvers: []string{dns}, RefuseLocal: true})
		p.localAddrs = func() ([]net.IP, error) { return []net.IP{net.IPv4(192, 0, 2, 10)}, nil }
		addr := serve(t, p)
		checkRefused(t, c.what, addr, "mac.test:443", "mac.test:80", logs)
		checkRefused(t, c.what+" (literal)", addr, "192.0.2.10:443", "192.0.2.10:80", logs)
		stop()
	}
}

func TestRefusedHereChecksTheCurrentInterfaceAddresses(t *testing.T) {
	var list []net.IP
	var fail error
	calls := 0
	p := NewProxy(ProxyConfig{RefuseLocal: true})
	p.localAddrs = func() ([]net.IP, error) { calls++; return list, fail }

	list = []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::5")}
	for addr, want := range map[string]bool{
		"192.0.2.10": true, "::ffff:192.0.2.10": true, "2001:db8::5": true,
		"192.0.2.11": false, "2001:db8::6": false, "198.51.100.7": false,
		"127.0.0.1": true, "fe80::1": true, "::ffff:127.0.0.1": true,
	} {
		if got := p.refusedHere(net.ParseIP(addr)); got != want {
			t.Errorf("refusedHere(%s) = %v, want %v", addr, got, want)
		}
	}
	// A 16-byte IPv4-mapped interface address matches the plain IPv4 form.
	list = []net.IP{net.ParseIP("::ffff:192.0.2.20")}
	if !p.refusedHere(net.ParseIP("192.0.2.20")) {
		t.Error("an IPv4-mapped interface address must match its IPv4 form")
	}
	// The list is read anew: an address dropped from it is no longer refused.
	before := calls
	list = nil
	if p.refusedHere(net.ParseIP("192.0.2.10")) {
		t.Error("an address no longer assigned must not stay refused")
	}
	if calls == before {
		t.Error("the interface addresses must be read at each check, not cached")
	}
	// Unknown is refused: failing closed.
	fail = errors.New("no interfaces")
	if !p.refusedHere(net.ParseIP("198.51.100.7")) {
		t.Error("when the interface addresses cannot be read, every address must be refused")
	}
}

// The default list is this machine's: its loopback address is on it.
func TestInterfaceIPsListsThisMachine(t *testing.T) {
	ips, err := interfaceIPs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return
		}
	}
	t.Errorf("interfaceIPs should include a loopback address, got %v", ips)
}
