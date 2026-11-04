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
			qend++        // null label
			qend += 4     // QTYPE + QCLASS
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
		{live},                     // single upstream: must use UDP framing
		{bh.LocalAddr().String(), live}, // failover: skip the silent one
	} {
		addrs := addrs
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return newFailoverConn(ctx, addrs, 400*time.Millisecond)
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
