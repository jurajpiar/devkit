package egressproxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// A silent first upstream must not stop the resolver: the failover conn
// resends to the next upstream and returns its answer. The test works at the
// datagram level (no DNS wire format): the "query" is an opaque payload and
// the live upstream echoes it back.
func TestFailoverConnSkipsSilentUpstream(t *testing.T) {
	// A black hole: a bound UDP socket that reads and never replies.
	blackHole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blackHole.Close()

	// A live upstream that echoes whatever it receives.
	live, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := live.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = live.WriteToUDP(buf[:n], from)
		}
	}()

	addrs := []string{blackHole.LocalAddr().String(), live.LocalAddr().String()}
	c, err := newFailoverConn(context.Background(), addrs, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("query-payload")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("failover should have reached the live upstream: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("got %q, want the echoed %q", buf[:n], msg)
	}
	if c.idx != 1 {
		t.Errorf("should have advanced to the second upstream, idx=%d", c.idx)
	}
}

// With every upstream silent, Read returns a timeout error rather than
// hanging past the overall deadline.
func TestFailoverConnAllSilentTimesOut(t *testing.T) {
	var addrs []string
	for i := 0; i < 2; i++ {
		bh, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer bh.Close()
		addrs = append(addrs, bh.LocalAddr().String())
	}
	c, err := newFailoverConn(context.Background(), addrs, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := 1500 * time.Millisecond
	c.SetDeadline(time.Now().Add(deadline))
	if _, err := c.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Read(make([]byte, 512)); err == nil {
		t.Fatal("expected a timeout with all upstreams silent")
	}
	// It must give up at the overall deadline, not hang past it, and not far
	// before it (the last upstream gets the remaining time, not a short cap).
	if elapsed := time.Since(start); elapsed > deadline+500*time.Millisecond {
		t.Errorf("read should give up at the deadline, took %s", elapsed)
	}
}

var _ net.PacketConn = (*failoverConn)(nil)
