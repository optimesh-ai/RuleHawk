"""Kernel-oracle capture: only the probe itself counts as "accepted".

Found by the nightly oracle (seed 10, ruleset 142): a self-addressed ICMP echo
(src == dst) hit `-j REJECT --reject-with icmp-port-unreachable` in INPUT. The
kernel answered with an ICMP type-3 error from that address to that address,
quoting the probe, tag included. The error's outer (proto, src, dst) equals
the probe's, so `find_tag` took the quoted tag for the probe and the oracle
read "accept" while the kernel had rejected it (and RuleHawk said deny).

These tests drive `find_tag` with hand-built frames, no Docker needed. The
kernel-level counterparts live in tests/test_oracle_kernel.py (opt-in, CI).
Addresses are RFC 5737 documentation space.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.oracle import kernel_probe as kp  # noqa: E402

HOST = "192.0.2.130"        # INPUT mode: every address is local
PEER = "198.51.100.7"
FAR = "203.0.113.9"
ETH = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"

PROBES = {
    "tcp": {"proto": "tcp", "src": PEER, "dst": FAR, "sport": 40000, "dport": 443},
    "udp": {"proto": "udp", "src": PEER, "dst": FAR, "sport": 40001, "dport": 53},
    "icmp": {"proto": "icmp", "src": PEER, "dst": FAR, "icmp_type": 8, "icmp_code": 0},
    "gre": {"proto": "gre", "src": PEER, "dst": FAR},
}


def _arm(packets):
    """Build each probe the way main() does and register what was sent."""
    kp.EXPECT.clear()
    frames = []
    for i, p in enumerate(packets):
        b, _ = kp.build(p, i)
        kp.expect(i, b)
        frames.append(b)
    return frames


def _ip(proto, src, dst, payload, ident=0x4242, ttl=64):
    import socket
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, ttl,
                    proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", kp.csum(h)) + h[12:] + payload


def _icmp_error(orig, src, dst, typ=3, code=3):
    """What Linux's icmp_send emits: outer IPv4, ICMP header, then as much of
    the offending datagram as fits in 576 bytes (here, all of it)."""
    body = struct.pack("!BBHI", typ, code, 0, 0) + orig
    body = body[:2] + struct.pack("!H", kp.csum(body)) + body[4:]
    return _ip(1, src, dst, body)


def _tcp_rst(orig):
    """REJECT --reject-with tcp-reset: a bare RST back to the sender."""
    import socket
    src, dst = orig[16:20], orig[12:16]
    sport, dport = struct.unpack("!HH", orig[22:24] + orig[20:22])
    seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 1001, 5 << 4, 0x14, 0, 0, 0)
    return _ip(6, socket.inet_ntoa(src), socket.inet_ntoa(dst), seg)


def _forwarded(b):
    """The probe as seen leaving vr1: TTL decremented, IP checksum redone."""
    ip = bytearray(b)
    ip[8] -= 1
    ip[10:12] = b"\0\0"
    ip[10:12] = struct.pack("!H", kp.csum(bytes(ip[:20])))
    return ETH + bytes(ip)


def _verdicts(captured, n, l2):
    seen = {kp.find_tag(f, l2) for f in captured} - {None}
    return ["accept" if i in seen else "drop" for i in range(n)]


# --- a true ACCEPT still reads accept (the oracle must not go blind) --------

@pytest.mark.parametrize("proto", sorted(PROBES))
def test_accepted_probe_reads_accept_in_input_mode(proto):
    [b] = _arm([PROBES[proto]])
    assert kp.find_tag(b, False) == 0
    assert _verdicts([b], 1, False) == ["accept"]


@pytest.mark.parametrize("proto", sorted(PROBES))
def test_forwarded_probe_reads_accept_in_forward_mode(proto):
    [b] = _arm([PROBES[proto]])
    assert kp.find_tag(_forwarded(b), True) == 0
    assert _verdicts([_forwarded(b)], 1, True) == ["accept"]


def test_self_addressed_probe_accepted_reads_accept():
    p = {"proto": "icmp", "src": HOST, "dst": HOST, "icmp_type": 8, "icmp_code": 0}
    [b] = _arm([p])
    assert _verdicts([b], 1, False) == ["accept"]


def test_accepted_probe_alongside_its_error_still_reads_accept():
    """Two probes, one accepted, one rejected: each keeps its own verdict."""
    ok = {"proto": "icmp", "src": HOST, "dst": HOST, "icmp_type": 8, "icmp_code": 0}
    bad = dict(ok)
    a, r = _arm([ok, bad])
    assert _verdicts([a, _icmp_error(r, HOST, HOST)], 2, False) == ["accept", "drop"]


# --- a REJECT reply is not the probe -----------------------------------------

@pytest.mark.parametrize("code", [0, 1, 3, 9, 10, 13])
@pytest.mark.parametrize("icmp_type", [8, 13, 0])
def test_self_addressed_reject_error_reads_deny(icmp_type, code):
    """The seed-10 misreading: same outer (proto, src, dst) as the probe."""
    p = {"proto": "icmp", "src": HOST, "dst": HOST, "icmp_type": icmp_type,
         "icmp_code": 0}
    [b] = _arm([p])
    err = _icmp_error(b, HOST, HOST, code=code)
    assert kp.find_tag(err, False) is None
    assert _verdicts([err], 1, False) == ["drop"]


@pytest.mark.parametrize("proto", ["tcp", "udp", "gre"])
def test_self_addressed_reject_error_for_other_protocols_reads_deny(proto):
    p = dict(PROBES[proto], src=HOST, dst=HOST)
    [b] = _arm([p])
    err = _icmp_error(b, HOST, HOST, code=2 if proto == "gre" else 3)
    assert _verdicts([err], 1, False) == ["drop"]


def test_self_addressed_tcp_reset_reads_deny():
    p = dict(PROBES["tcp"], src=HOST, dst=HOST)
    [b] = _arm([p])
    assert _verdicts([_tcp_rst(b)], 1, False) == ["drop"]


def test_reject_error_with_non_local_source_reads_deny():
    """INPUT mode: the error comes back from the probe's destination."""
    [b] = _arm([dict(PROBES["icmp"], dst=HOST)])
    err = _icmp_error(b, HOST, PEER)
    assert _verdicts([err], 1, False) == ["drop"]


def test_forwarded_reject_error_from_the_router_reads_deny():
    """FORWARD mode: the error is sourced from the router, whatever leaks to vr1."""
    [b] = _arm([PROBES["icmp"]])
    err = _icmp_error(b, kp.ROUTER_V0, PEER)
    assert _verdicts([ETH + err], 1, True) == ["drop"]


def test_error_spoofing_the_probe_header_reads_deny():
    """Even an error forged to carry the probe's outer (proto, src, dst) and
    IP ID quotes the tag deeper than the probe carries it."""
    [b] = _arm([PROBES["icmp"]])
    body = struct.pack("!BBHI", 3, 3, 0, 0) + b
    body = body[:2] + struct.pack("!H", kp.csum(body)) + body[4:]
    err = _ip(1, PEER, FAR, body, ident=0)
    assert _verdicts([err], 1, False) == ["drop"]


# --- DROP reads drop ---------------------------------------------------------

def test_drop_with_nothing_captured_reads_drop():
    _arm([PROBES["icmp"]])
    assert _verdicts([], 1, False) == ["drop"]


def test_drop_with_other_traffic_captured_reads_drop():
    """A capture of a different probe never marks this one accepted."""
    a, _ = _arm([PROBES["tcp"], PROBES["udp"]])
    assert _verdicts([a], 2, False) == ["accept", "drop"]


def test_unregistered_tag_reads_drop():
    kp.EXPECT.clear()
    b, _ = kp.build(PROBES["icmp"], 7)
    assert kp.find_tag(b, False) is None


# --- L2: the tag is read at the probe's own offset ---------------------------

@pytest.mark.parametrize("proto", sorted(PROBES))
def test_magic_bytes_in_the_header_do_not_hide_a_real_accept(proto):
    """82.72.79.82 is b"RHOR": the first MAGIC in the packet is then the
    source address, not the tag. The probe must still read accept."""
    p = dict(PROBES[proto], src="82.72.79.82")
    [b] = _arm([p])
    assert b[12:16] == kp.MAGIC
    assert kp.find_tag(b, False) == 0
    assert kp.find_tag(_forwarded(b), True) == 0


def test_magic_bytes_in_both_addresses_do_not_hide_a_real_accept():
    p = dict(PROBES["icmp"], src="82.72.79.82", dst="82.72.79.82")
    [b] = _arm([p])
    assert _verdicts([b], 1, False) == ["accept"]
    assert _verdicts([_icmp_error(b, p["dst"], p["src"])], 1, False) == ["drop"]


# --- L1: only the filter table may be loaded ---------------------------------
# NAT and mangle rewrite the bytes find_tag compares, so a real accept would
# read as drop. load() refuses them before touching iptables.

_NAT_SAVE = ("*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
             "-A POSTROUTING -j MASQUERADE\nCOMMIT\n"
             "*filter\n:FORWARD ACCEPT [0:0]\nCOMMIT\n")


@pytest.mark.parametrize("ruleset", [
    _NAT_SAVE,
    "*mangle\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j TTL --ttl-set 9\nCOMMIT\n",
    "*raw\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n",
    "iptables -t mangle -A FORWARD -j TTL --ttl-set 9\n",
    "iptables -A FORWARD -j ACCEPT\niptables -t nat -A POSTROUTING -j MASQUERADE\n",
    "iptables --table nat -A POSTROUTING -j MASQUERADE\n",
    "iptables --table=nat -A POSTROUTING -j MASQUERADE\n",
    "iptables -tnat -A POSTROUTING -j MASQUERADE\n",
    "iptables -t filter -A FORWARD -j ACCEPT\n",
])
def test_non_filter_table_is_a_load_error(ruleset, monkeypatch):
    def no_iptables(*a, **k):
        raise AssertionError("load() ran iptables on a refused ruleset")
    monkeypatch.setattr(kp.subprocess, "run", no_iptables)
    err = kp.load(ruleset)
    assert err and "table" in err


def test_filter_only_ruleset_still_loads(monkeypatch):
    calls = []

    class R:
        returncode, stderr = 0, ""

    monkeypatch.setattr(kp.subprocess, "run", lambda *a, **k: calls.append(a) or R())
    assert kp.load("*filter\n:FORWARD DROP [0:0]\n-A FORWARD -s 192.0.2.0/24 -j ACCEPT\n"
                   "COMMIT\n") is None
    assert kp.load("iptables -A FORWARD -s 192.0.2.0/24 -j ACCEPT\n") is None
    assert len(calls) == 2
