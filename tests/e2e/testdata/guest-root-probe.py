#!/usr/bin/env python3
"""Invalidation test for host-side egress enforcement.

Run as root in the guest, after the in-guest controls are gone (see
guest-root-probe.sh). Raw sockets only: no curl, no proxy variables, no
missing tools, so a refusal is the network's and not the probe's.

usage: guest-root-probe.py <allowed-port> <canary-port>
"""
import socket, struct, sys, os, time

ALLOWED, CANARY = int(sys.argv[1]), int(sys.argv[2])
GW = "192.168.5.2"
results = []

def report(name, expect, got, detail=""):
    verdict = "PASS" if expect == got else "FAIL"
    results.append(verdict)
    print(f"{verdict} {name:<58} [expect {expect}, got {got}] {detail}"[:200])

def tcp(host, port, payload=None, family=socket.AF_INET, timeout=6):
    """Returns (ok, detail). ok means connected and, with a payload, answered."""
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if payload is None:
            s.close()
            return True, "connected"
        s.sendall(payload)
        data = s.recv(200)
        s.close()
        return (len(data) > 0), repr(data[:60])
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def dns_query(name):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)

def dns_udp(server, name="example.com", timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(dns_query(name), (server, 53))
        data, _ = s.recvfrom(512)
        ancount = struct.unpack(">H", data[6:8])[0]
        rcode = data[3] & 0x0F
        # The names asked for exist. An answer means the query went upstream.
        # NXDOMAIN for a name that exists means the lookup failed on the Mac
        # (Lima's resolver cannot reach the Mac's): nothing left.
        return (ancount > 0), f"rcode={rcode} answers={ancount}"
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def recv_exact(s, n):
    """Exactly n bytes from stream socket s; one recv may return fewer."""
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise EOFError(f"closed after {len(data)} of {n} bytes")
        data += chunk
    return data

def dns_tcp(server, name="example.com", timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 53))
        q = dns_query(name)
        s.sendall(struct.pack(">H", len(q)) + q)
        # The reply is framed: a two-byte length, then that many bytes. Read
        # both fully before looking at the header, or a reply whose prefix
        # arrives on its own reads as no answer and a working resolver as
        # blocked.
        length = struct.unpack(">H", recv_exact(s, 2))[0]
        data = recv_exact(s, length)
        s.close()
        if len(data) < 12:
            return False, f"short reply ({len(data)} bytes)"
        ancount = struct.unpack(">H", data[6:8])[0]
        rcode = data[3] & 0x0F
        return (ancount > 0), f"bytes={len(data)} rcode={rcode} answers={ancount}"
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def udp_ntp(server, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x1b" + 47 * b"\0", (server, 123))
        data, _ = s.recvfrom(64)
        return True, f"{len(data)} bytes"
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def udp_answer(host, port, timeout=4):
    """ok means a datagram to host:port was answered."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"devkit-udp-probe", (host, port))
        data, _ = s.recvfrom(200)
        return True, repr(data[:60])
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def icmp_echo_request(ident, seq, payload):
    """An ICMP echo request (type 8) with a valid checksum."""
    body = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + payload
    csum = 0
    for i in range(0, len(body), 2):
        csum += (body[i] << 8) + (body[i + 1] if i + 1 < len(body) else 0)
    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = ~(csum + (csum >> 16)) & 0xFFFF
    return struct.pack(">BBHHH", 8, 0, csum, ident, seq) + payload

def icmp_is_echo_reply(packet, src, ident, seq, payload):
    """True when packet, as a raw IPv4 ICMP socket on Linux delivers it (the
    IP header first, its length in the IHL field), is the echo reply to our
    request: type 0 code 0, from src, with our identifier, sequence and
    payload. Anything else, such as a router's Destination Unreachable for a
    forwarded request, is not."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return False
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8 or packet[9] != socket.IPPROTO_ICMP:
        return False
    if packet[12:16] != socket.inet_aton(src):
        return False
    typ, code, _, rid, rseq = struct.unpack(">BBHHH", packet[ihl:ihl + 8])
    return (typ, code, rid, rseq) == (0, 0, ident, seq) and packet[ihl + 8:] == payload

def icmp(host, timeout=4, ident=0x1234, seq=1, payload=b"devkit"):
    """ok means host answered our echo request with its echo reply; every
    other packet the raw socket sees until the timeout is ignored."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.sendto(icmp_echo_request(ident, seq, payload), (host, 0))
        deadline = time.monotonic() + timeout
        ignored = 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return False, f"no echo reply from {host}; {ignored} other packets ignored"
            s.settimeout(left)
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            if icmp_is_echo_reply(data, host, ident, seq, payload):
                return True, f"echo reply, {len(data)} bytes; {ignored} other packets ignored"
            ignored += 1
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e)

def yes(b):
    return "ok" if b else "fail"

GET = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"

print("== positive control: the one allowed path")
ok, d = tcp(GW, ALLOWED, GET)
report(f"host proxy port on the Mac ({GW}:{ALLOWED})", "ok", yes(ok), d)

print("== routes to the internet")
for host, port in [("1.1.1.1", 80), ("1.1.1.1", 443), ("93.184.215.14", 80), ("35.180.139.74", 8080), ("140.82.121.3", 22)]:
    ok, d = tcp(host, port)
    report(f"TCP to {host}:{port}", "fail", yes(ok), d)
ok, d = tcp("2606:4700:4700::1111", 80, family=socket.AF_INET6)
report("TCP over IPv6 to 2606:4700:4700::1111:80", "fail", yes(ok), d)
for srv in ["8.8.8.8", "1.1.1.1"]:
    ok, d = dns_udp(srv)
    report(f"DNS over UDP to {srv}", "fail", yes(ok), d)
ok, d = dns_tcp("8.8.8.8")
report("DNS over TCP to 8.8.8.8", "fail", yes(ok), d)
ok, d = udp_ntp("185.125.190.57")
report("UDP (NTP) to 185.125.190.57:123", "fail", yes(ok), d)
# ICMP is reported, not judged. From in here a ping the Mac refused and one
# it forwarded look the same: no reply. And when a reply does come it is
# Lima's own network stack answering (0 ms, TTL 64, for unroutable addresses
# too), which varies with the environment: the same code got one all
# morning and none in the afternoon. What can be checked is checked on the
# Mac: TestProfileBlocksICMP shows a process under the profile cannot send
# ICMP at all.
ok, d = icmp("203.0.113.1")
print(f"NOTE ICMP echo to an unroutable address: {'answered locally' if ok else 'no reply'} ({d})")

print("== Lima's own resolver (a DNS exfiltration channel if it answers)")
# A name that does not exist cannot tell a leak from a local failure (both
# give NXDOMAIN), so only existing names are asked for.
for srv in [GW, "192.168.5.3"]:
    ok, d = dns_udp(srv)
    report(f"DNS over UDP through Lima at {srv}", "fail", yes(ok), d)
    ok, d = dns_tcp(srv)
    report(f"DNS over TCP through Lima at {srv}", "fail", yes(ok), d)

print("== the Mac's loopback")
ok, d = tcp(GW, CANARY, GET)
report(f"canary listener on the Mac ({GW}:{CANARY})", "fail", yes(ok), d)
# The profile allows the host proxy's port over TCP only. The test runs a UDP
# listener on the Mac at the same port number that answers every datagram.
ok, d = udp_answer(GW, ALLOWED)
report(f"UDP to the host proxy's port number ({GW}:{ALLOWED})", "fail", yes(ok), d)
open_ports = []
for p in list(range(1, 1025)) + list(range(3000, 9001, 50)) + [5432, 5433, 6379, 8080, 8443, 27017, CANARY]:
    if p == ALLOWED:
        continue
    ok, _ = tcp(GW, p, timeout=1)
    if ok:
        open_ports.append(p)
# 53 is Lima's in-process DNS listener, not a Mac service; whether it can
# resolve is tested above.
open_ports = [p for p in open_ports if p != 53]
report("port sweep of the Mac via the gateway finds nothing", "ok", yes(not open_ports), f"open: {open_ports}")
for other in ["192.168.5.1", "192.168.5.3", "192.168.5.254"]:
    ok, d = tcp(other, CANARY, timeout=3)
    report(f"canary via another usernet address {other}", "fail", yes(ok), d)

print()
print("SUMMARY:", results.count("PASS"), "pass,", results.count("FAIL"), "fail")
