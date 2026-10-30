#!/usr/bin/env python3
"""Ask the real Linux kernel what an iptables ruleset does with crafted packets.

Runs INSIDE a privileged Linux container (stdlib only; needs iproute2 and
iptables). The container's own network namespace is the "router" whose filter
table holds the ruleset under test. Two helper namespaces hang off it:

    gen  --veth-- [router: vr0]   [router: vr1] --veth-- sink

Packets are built byte-for-byte here (IPv4 + TCP SYN / UDP / ICMP / raw proto,
valid checksums, a unique tag in the payload), injected from `gen` with an
AF_PACKET socket, and observed AFTER the filter table decided them:

  * mode "forward": the default route points out vr1, so every packet is
    forwarded and traverses FORWARD. A packet captured leaving vr1 was accepted.
  * mode "input": `local 0.0.0.0/0` makes every address local, so every packet
    is delivered up the stack and traverses INPUT. A raw socket (which sees a
    packet only after the INPUT hooks) captures the accepted ones.

Per-rule attribution (`--attribute`): packets are sent one at a time with the
counters zeroed before each, and `iptables-save -c` reports which rules and
chain policies counted it.

Input (stdin, JSON): {"ruleset": str, "mode": "forward"|"input",
                      "packets": [{"proto","src","dst","sport","dport",
                                   "icmp_type","icmp_code"}], "attribute": bool}
Output (stdout, JSON): {"load_error": str|null, "verdicts": ["accept"|"drop"],
                        "hits": [[[chain, index] ...] ...] (attribute only)}
"""

import json
import os
import re
import select
import shlex
import socket
import struct
import subprocess
import sys
import time

MAGIC = b"RHOR"
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51,
             "sctp": 132, "ospf": 89, "pim": 103, "vrrp": 112, "igmp": 2}
ROUTER_V0 = "198.18.255.1"
ROUTER_V1 = "198.18.255.5"
SINK_GW = "198.18.255.6"


def sh(*args, check=True, ns=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r


def sysctl(k, v):
    with open("/proc/sys/" + k.replace(".", "/"), "w") as fh:
        fh.write(str(v))


def setup(mode):
    if not os.path.exists("/run/netns/gen"):
        sh("ip", "netns", "add", "gen")
        sh("ip", "netns", "add", "sink")
        sh("ip", "link", "add", "vr0", "type", "veth", "peer", "name", "vgen")
        sh("ip", "link", "set", "vgen", "netns", "gen")
        sh("ip", "link", "add", "vr1", "type", "veth", "peer", "name", "vsink")
        sh("ip", "link", "set", "vsink", "netns", "sink")
        sh("ip", "addr", "add", ROUTER_V0 + "/32", "dev", "vr0")
        sh("ip", "addr", "add", ROUTER_V1 + "/32", "dev", "vr1")
        for d in ("vr0", "vr1"):
            sh("ip", "link", "set", d, "up")
        sh("ip", "link", "set", "vgen", "up", ns="gen")
        sh("ip", "link", "set", "vsink", "up", ns="sink")
        sink_mac = open("/sys/class/net/vr1/address").read().strip()  # any MAC
        sh("ip", "neigh", "replace", SINK_GW, "lladdr", sink_mac, "dev", "vr1",
           "nud", "permanent")
        for k, v in (("net.ipv4.ip_forward", 1), ("net.ipv4.conf.all.rp_filter", 0),
                     ("net.ipv4.conf.default.rp_filter", 0),
                     ("net.ipv4.conf.vr0.rp_filter", 0),
                     ("net.ipv4.conf.vr0.accept_local", 1),
                     ("net.ipv4.conf.all.accept_local", 1)):
            sysctl(k, v)
    sh("ip", "route", "del", "default", check=False)
    sh("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "local",
       check=False)
    if mode == "forward":
        sh("ip", "route", "add", "default", "via", SINK_GW, "dev", "vr1", "onlink")
    else:
        sh("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "local")


def flush():
    for t in ("filter", "nat", "mangle", "raw", "security"):
        sh("iptables", "-t", t, "-F", check=False)
        sh("iptables", "-t", t, "-X", check=False)
    for c in ("INPUT", "FORWARD", "OUTPUT"):
        sh("iptables", "-P", c, "ACCEPT", check=False)
    sh("conntrack", "-F", check=False)


def load(ruleset: str):
    """iptables-save text -> iptables-restore; command form -> one argv per
    `iptables ...` line (no shell, so a corpus file can't run anything else)."""
    if re.search(r"(?m)^\s*\*(filter|nat|mangle|raw|security)\b", ruleset):
        r = subprocess.run(["iptables-restore"], input=ruleset, capture_output=True,
                           text=True)
        return r.stderr.strip() or None if r.returncode else None
    errs = []
    for ln in ruleset.splitlines():
        s = ln.strip()
        if not s.startswith("iptables ") and not s.startswith("iptables\t"):
            continue
        try:
            argv = shlex.split(s, comments=True)
        except ValueError as e:
            errs.append(f"{s}: {e}")
            continue
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode:
            errs.append(f"{s}: {r.stderr.strip()}")
    return "; ".join(errs) or None


def csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build(p, idx):
    tag = MAGIC + struct.pack("!I", idx)
    src, dst = socket.inet_aton(p["src"]), socket.inet_aton(p["dst"])
    proto = p["proto"]
    pn = PROTO_NUM.get(proto, None) if not str(proto).isdigit() else int(proto)
    if proto == "tcp":
        hdr = struct.pack("!HHIIBBHHH", p["sport"], p["dport"], 1000 + idx, 0,
                          5 << 4, p.get("flags", 0x02), 64240, 0, 0)
        l4 = hdr + tag
        ph = src + dst + struct.pack("!BBH", 0, 6, len(l4))
        c = csum(ph + l4)
        l4 = l4[:16] + struct.pack("!H", c) + l4[18:]
    elif proto == "udp":
        l4 = struct.pack("!HHHH", p["sport"], p["dport"], 8 + len(tag), 0) + tag
        ph = src + dst + struct.pack("!BBH", 0, 17, len(l4))
        c = csum(ph + l4) or 0xFFFF
        l4 = l4[:6] + struct.pack("!H", c) + l4[8:]
    elif proto == "icmp":
        body = struct.pack("!BBHHH", p.get("icmp_type") or 0, p.get("icmp_code") or 0,
                           0, idx & 0xFFFF, 1) + tag
        c = csum(body)
        l4 = body[:2] + struct.pack("!H", c) + body[4:]
    else:
        l4 = tag + b"\0" * 8
    tot = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, idx & 0xFFFF, 0, 64, pn, 0,
                     src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + l4, pn


def find_tag(frame: bytes, l2: bool):
    """The probe index carried by a captured packet, or None. The OUTER IPv4
    header must be the probe itself: a REJECT reply (ICMP unreachable / RST)
    quotes the probe's header and tag inside its own payload, so a tag found
    under a different outer (src, dst, proto) is a reply, not the probe."""
    ip = frame[14:] if l2 else frame
    if l2 and frame[12:14] != b"\x08\x00":
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    k = ip.find(MAGIC)
    if k < 0 or k + 8 > len(ip):
        return None
    idx = struct.unpack("!I", ip[k + 4:k + 8])[0]
    want = EXPECT.get(idx)
    if want is None or (ip[9], ip[12:16], ip[16:20]) != want:
        return None
    return idx


EXPECT = {}


SENDER = r"""
import socket, sys, json, time
d = json.load(sys.stdin)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("vgen", 0))
own = open("/sys/class/net/vgen/address").read().strip()
dmac = bytes.fromhex(d["dmac"].replace(":", ""))
smac = bytes.fromhex(own.replace(":", ""))
for h in d["frames"]:
    s.send(dmac + smac + b"\x08\x00" + bytes.fromhex(h))
    time.sleep(d.get("gap", 0.0005))
"""


def send(frames, gap=0.0005):
    dmac = open("/sys/class/net/vr0/address").read().strip()
    r = subprocess.run(["ip", "netns", "exec", "gen", sys.executable, "-c", SENDER],
                       input=json.dumps({"dmac": dmac, "frames": [f.hex() for f in frames],
                                         "gap": gap}),
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("sender: " + r.stderr)


def open_capture(mode, pnums):
    if mode == "forward":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind(("vr1", 0))
        return [s]
    socks = []
    for pn in sorted(set(pnums)):
        socks.append(socket.socket(socket.AF_INET, socket.SOCK_RAW, pn))
    return socks


def collect(socks, seen, until):
    while True:
        left = until - time.time()
        if left <= 0:
            return
        rd, _, _ = select.select(socks, [], [], left)
        for s in rd:
            try:
                data = s.recv(65535)
            except OSError:
                continue
            t = find_tag(data, s.family == socket.AF_PACKET)
            if t is not None:
                seen.add(t)


def counters():
    """{(chain, index): pkts} for filter rules, plus (chain, 'policy')."""
    out = {}
    txt = sh("iptables-save", "-c", "-t", "filter").stdout
    idx = {}
    for ln in txt.splitlines():
        m = re.match(r"^:(\S+) (\S+) \[(\d+):\d+\]", ln)
        if m:
            out[(m.group(1), "policy")] = int(m.group(3))
            continue
        m = re.match(r"^\[(\d+):\d+\] -A (\S+)", ln)
        if m:
            ch = m.group(2)
            idx[ch] = idx.get(ch, 0) + 1
            out[(ch, idx[ch])] = int(m.group(1))
    return out


def main():
    req = json.load(sys.stdin)
    mode = req.get("mode", "forward")
    setup(mode)
    flush()
    err = load(req["ruleset"])
    res = {"load_error": err, "verdicts": [], "hits": []}
    pk = req["packets"]
    built = [build(p, i) for i, p in enumerate(pk)]
    frames = [b for b, _ in built]
    for i, (b, pn) in enumerate(built):
        EXPECT[i] = (b[9], b[12:16], b[16:20])
    socks = open_capture(mode, [pn for _, pn in built])
    if req.get("attribute"):
        for i, f in enumerate(frames):
            sh("iptables", "-Z")
            seen = set()
            send([f], gap=0)
            collect(socks, seen, time.time() + 0.15)
            res["verdicts"].append("accept" if i in seen else "drop")
            c = counters()
            res["hits"].append([[k[0], k[1]] for k, v in c.items() if v > 0])
    else:
        seen = set()
        # send in chunks while draining so socket buffers can't overflow
        for k in range(0, len(frames), 200):
            send(frames[k:k + 200])
            collect(socks, seen, time.time() + 0.05)
        collect(socks, seen, time.time() + 0.6)
        res["verdicts"] = ["accept" if i in seen else "drop" for i in range(len(frames))]
        # Per-rule counters after the whole batch: a rule RuleHawk calls DEAD
        # must show 0 packets (any count refutes the claim).
        res["counters"] = [[k[0], k[1], v] for k, v in counters().items()]
    for s in socks:
        s.close()
    json.dump(res, sys.stdout)


if __name__ == "__main__":
    main()
