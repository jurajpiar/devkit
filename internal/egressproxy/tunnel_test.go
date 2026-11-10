package egressproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A client may send its first tunnel bytes (a TLS ClientHello) right behind
// the CONNECT request without waiting for the 200. The proxy's HTTP server
// then reads them into its buffer along with the request, and the tunnel
// must forward them from there: complete, in order, after the 200.

// pipelinedConnect sends the CONNECT request and payload in one write and
// returns what came back through the tunnel, up to len(payload) bytes.
func pipelinedConnect(t *testing.T, proxyAddr, target string, payload []byte) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write(append([]byte(req), payload...))
		wrote <- err
	}()
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %s", resp.Status)
	}
	got := make([]byte, len(payload))
	n, err := io.ReadFull(br, got)
	if err != nil {
		t.Errorf("tunnel returned %d of %d bytes: %v", n, len(payload), err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	return got[:n]
}

func payloads() map[string][]byte {
	large := make([]byte, 1<<20)
	rand.New(rand.NewSource(1)).Read(large)
	return map[string][]byte{"small": []byte("ping\n"), "large": large}
}

func checkEchoed(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	if len(want) < 64 {
		t.Fatalf("tunnel must carry the pipelined bytes intact: got %q, want %q", got, want)
	}
	i := 0
	for i < len(got) && got[i] == want[i] {
		i++
	}
	t.Fatalf("tunnel must carry the pipelined bytes intact: got %d of %d bytes, first difference at %d", len(got), len(want), i)
}

func TestConnectForwardsBytesSentWithTheRequest(t *testing.T) {
	echo := echoServer(t)
	_, _, _, proxyAddr := startProxy(t, echo)
	for name, payload := range payloads() {
		t.Run(name, func(t *testing.T) {
			checkEchoed(t, pipelinedConnect(t, proxyAddr, echo, payload), payload)
		})
	}
}

func TestUpstreamForwardsBytesSentWithTheRequest(t *testing.T) {
	echo := echoServer(t)
	parent := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo}, Logger: log.New(io.Discard, "", 0)}))
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{echo}, Logger: log.New(io.Discard, "", 0), Upstream: parent}))
	for name, payload := range payloads() {
		t.Run(name, func(t *testing.T) {
			checkEchoed(t, pipelinedConnect(t, child, echo, payload), payload)
		})
	}
}

// fakeParent is a parent proxy that answers every CONNECT with its 200 and
// banner in one write, then echoes.
func fakeParent(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"+banner)
				io.Copy(c, br)
			}()
		}
	}()
	return ln.Addr().String()
}

// Bytes the parent sends right behind its 200 belong to the tunnel and must
// reach the client after the child's own 200.
func TestUpstreamForwardsBytesSentWithTheParentsAnswer(t *testing.T) {
	parent := fakeParent(t, "banner\n")
	child := serve(t, NewProxy(ProxyConfig{AllowedHosts: []string{"server-first.test:443"}, Logger: log.New(io.Discard, "", 0), Upstream: parent}))
	status, conn, br := connect(t, child, "server-first.test:443")
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("want 200, got %s", status)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := br.ReadString('\n'); err != nil || got != "banner\n" {
		t.Fatalf("bytes behind the parent's 200 must come through: got %q, %v", got, err)
	}
	io.WriteString(conn, "ping\n")
	if got, err := br.ReadString('\n'); err != nil || got != "ping\n" {
		t.Fatalf("the tunnel should carry bytes both ways: got %q, %v", got, err)
	}
}

// A target that speaks first (SSH, SMTP) must not get its bytes to the
// client ahead of the 200.
func TestConnectSendsThe200BeforeTheTargetsFirstBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.WriteString(c, "banner\n"); io.Copy(c, c) }()
		}
	}()
	target := ln.Addr().String()
	_, _, _, proxyAddr := startProxy(t, target)
	status, conn, br := connect(t, proxyAddr, target)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("want 200, got %s", status)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := br.ReadString('\n'); err != nil || got != "banner\n" {
		t.Fatalf("the target's first bytes must follow the 200: got %q, %v", got, err)
	}
}
