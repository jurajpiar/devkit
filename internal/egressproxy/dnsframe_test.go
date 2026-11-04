package egressproxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// miniDNS answers any A query for any name with 10.1.2.3, over UDP. It exists
// to prove the failover conn frames queries as UDP datagrams (no TCP length
// prefix) and that a real resolver roundtrip works through it.
func miniDNS(t *testing.T) (addr string, stop func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 12 {
				continue
			}
			// Reply: copy ID, set QR+RA, QDCOUNT=1, ANCOUNT=1, echo the
			// question, then one A record for 10.1.2.3.
			resp := make([]byte, 0, 64)
			resp = append(resp, q[0], q[1]) // ID
			resp = append(resp, 0x81, 0x80) // QR=1, RD=1, RA=1
			resp = append(resp, 0x00, 0x01) // QDCOUNT
			resp = append(resp, 0x00, 0x01) // ANCOUNT
			resp = append(resp, 0x00, 0x00) // NSCOUNT
			resp = append(resp, 0x00, 0x00) // ARCOUNT
			// question section: from byte 12 up to and including QTYPE/QCLASS
			qend := 12
			for qend < n && q[qend] != 0 {
				qend += int(q[qend]) + 1
			}
			qend++    // null label
			qend += 4 // QTYPE + QCLASS
			if qend > n {
				qend = n
			}
			resp = append(resp, q[12:qend]...)
			// answer: name pointer to 0x0c, type A, class IN, TTL 60, rdlen 4
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 1, 2, 3)
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), func() { pc.Close() }
}

func TestFailoverResolvesWithUDPFraming(t *testing.T) {
	live, stop := miniDNS(t)
	defer stop()
	bh, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bh.Close() // black hole: reads nothing, never replies

	for _, addrs := range [][]string{
		{live},                          // single upstream: must use UDP framing
		{bh.LocalAddr().String(), live}, // failover: skip the silent one
	} {
		addrs := addrs
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return newFailoverConn(ctx, "udp", addrs, 400*time.Millisecond)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupHost(ctx, "anything.test")
		cancel()
		if err != nil {
			t.Fatalf("addrs=%v: lookup failed (TCP framing would do this): %v", addrs, err)
		}
		found := false
		for _, ip := range ips {
			if ip == "10.1.2.3" {
				found = true
			}
		}
		if !found {
			t.Errorf("addrs=%v: got %v, want 10.1.2.3", addrs, ips)
		}
	}
}

// miniDNSTruncating answers UDP queries with the TC (truncated) bit set and
// no answer, and serves the full A record over TCP (length-prefixed). It
// proves the resolver falls back to TCP through the failover dialer.
func miniDNSTruncating(t *testing.T) (addr string, stop func()) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	answer := func(q []byte, tc bool) []byte {
		resp := []byte{q[0], q[1]}
		// Header byte 2: QR=1 (0x80), RD=1 (0x01), TC=0x02 when truncated.
		// Header byte 3: RA=1 (0x80). TC lives in byte 2, not byte 3.
		flags1 := byte(0x81)
		if tc {
			flags1 |= 0x02
		}
		resp = append(resp, flags1, 0x80, 0x00, 0x01)
		if tc {
			resp = append(resp, 0x00, 0x00) // ANCOUNT 0 when truncated
		} else {
			resp = append(resp, 0x00, 0x01)
		}
		resp = append(resp, 0x00, 0x00, 0x00, 0x00)
		qend := 12
		for qend < len(q) && q[qend] != 0 {
			qend += int(q[qend]) + 1
		}
		qend += 5
		if qend > len(q) {
			qend = len(q)
		}
		resp = append(resp, q[12:qend]...)
		if !tc {
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 9, 8, 7)
		}
		return resp
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 12 {
				_, _ = udp.WriteTo(answer(buf[:n], true), from)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var l [2]byte
				if _, err := conn.Read(l[:]); err != nil {
					return
				}
				msg := make([]byte, int(l[0])<<8|int(l[1]))
				if _, err := conn.Read(msg); err != nil {
					return
				}
				resp := answer(msg, false)
				conn.Write([]byte{byte(len(resp) >> 8), byte(len(resp))})
				conn.Write(resp)
			}()
		}
	}()
	return udp.LocalAddr().String(), func() { udp.Close(); tcp.Close() }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestFailoverFallsBackToTCPOnTruncation(t *testing.T) {
	live, stop := miniDNSTruncating(t)
	defer stop()
	addrs := []string{live}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return newFailoverConn(ctx, network, addrs, 400*time.Millisecond)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "big.test")
	if err != nil {
		t.Fatalf("truncated UDP answer should retry over TCP: %v", err)
	}
	found := false
	for _, ip := range ips {
		if ip == "10.9.8.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("got %v, want 10.9.8.7 from the TCP answer", ips)
	}
}

// miniDNSStalling truncates over UDP like miniDNSTruncating, but over TCP it
// sends only the two-byte length prefix and then stalls: the case where a
// naive failover would splice a healthy upstream's prefix into the payload.
func miniDNSStalling(t *testing.T) (addr string, stop func()) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 12 {
				resp := append([]byte{buf[0], buf[1], 0x83, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, buf[12:n]...)
				_, _ = udp.WriteTo(resp, from)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				var l [2]byte
				if _, err := conn.Read(l[:]); err != nil {
					conn.Close()
					return
				}
				_, _ = conn.Write([]byte{0x00, 0x40}) // a prefix, then silence
				// hold the connection open without answering
				time.Sleep(10 * time.Second)
				conn.Close()
			}()
		}
	}()
	return udp.LocalAddr().String(), func() { udp.Close(); tcp.Close() }
}

// A primary that refuses the connection (dial error) must not end the query
// while a secondary remains, on the TCP retry as well as the UDP attempt.
func TestFailoverPastRefusingPrimary(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := ln.Addr().String()
	ln.Close() // now nothing listens there, TCP or UDP
	live, stop := miniDNSTruncating(t)
	defer stop()
	addrs := []string{refused, live}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return newFailoverConn(ctx, network, addrs, 400*time.Millisecond)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "big.test")
	if err != nil {
		t.Fatalf("a refusing primary should be skipped for the live secondary: %v", err)
	}
	if len(ips) == 0 || ips[0] != "10.9.8.7" {
		t.Errorf("got %v, want 10.9.8.7 from the secondary's TCP answer", ips)
	}
}

// A TCP primary that sends a length prefix and then stalls must not corrupt
// the answer: the whole frame is acquired from one upstream before any of it
// reaches the resolver, so failover replays the query on the secondary and
// serves its frame intact.
func TestFailoverTCPFrameAtomic(t *testing.T) {
	stalling, stop1 := miniDNSStalling(t)
	defer stop1()
	live, stop2 := miniDNSTruncating(t)
	defer stop2()
	addrs := []string{stalling, live}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return newFailoverConn(ctx, network, addrs, 300*time.Millisecond)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "big.test")
	if err != nil {
		t.Fatalf("a stalling TCP primary should fail over cleanly: %v", err)
	}
	if len(ips) == 0 || ips[0] != "10.9.8.7" {
		t.Errorf("got %v, want 10.9.8.7 intact from the secondary", ips)
	}
}
