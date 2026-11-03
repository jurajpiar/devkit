package egressproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// An allowed host must not be a tunnel to every port on it: CONNECT is for
// 443 and plain HTTP for 80 unless the allow entry names a port.
func TestAllowedHostWebPortsOnly(t *testing.T) {
	f := NewFilter([]string{"github.com", "**.github.com", "internal.example:8443"})
	cases := []struct {
		host string
		want bool
	}{
		{"github.com:443", true},
		{"api.github.com:443", true},
		{"github.com:22", false},
		{"github.com:8080", false},
		{"internal.example:8443", true},
		{"internal.example:443", false},
	}
	for _, c := range cases {
		if got := f.IsAllowed(c.host); got != c.want {
			t.Errorf("IsAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	// Open mode allows any host, still on web ports only.
	open := NewFilter([]string{"*"})
	if open.IsAllowed("example.com:22") {
		t.Error("open mode must not tunnel to port 22")
	}
	if !open.IsAllowed("example.com:443") {
		t.Error("open mode should allow 443")
	}
}

// End to end through the proxy: a listener on a non-web port of an allowed
// host must not be reachable by CONNECT.
func TestProxyRefusesConnectToNonWebPort(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-banner\r\n"))
			c.Close()
		}
	}()
	tport := target.Addr().(*net.TCPAddr).Port

	p := NewProxy(ProxyConfig{ListenAddr: "127.0.0.1:0", AllowedHosts: []string{"127.0.0.1"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.handleRequest)}
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", tport, tport)
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(status, " 403 ") {
		t.Errorf("CONNECT to an allowed host on port %d should be 403, got %q", tport, strings.TrimSpace(status))
	}
}
