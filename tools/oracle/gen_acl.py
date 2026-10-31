"""Random ACLs rendered into five vendor syntaxes (IOS, ASA, EOS, NX-OS, Junos).

One abstract rule list is drawn from small, collision-prone pools (as in
gen_iptables) and rendered per vendor, so the same policy is checked through
every frontend against Batfish."""

from __future__ import annotations

import ipaddress
import random

NETS = ["10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/26", "10.0.0.64/26",
        "10.0.0.5/32", "10.0.0.130/32", "10.0.1.0/24", "10.0.0.0/16", "10.0.0.0/8",
        "192.168.1.0/24", "192.168.1.10/32", "172.16.0.0/12", "any"]
PORTS = [("eq", 22), ("eq", 53), ("eq", 80), ("eq", 443), ("range", 1000, 2000),
         ("range", 1500, 1600), ("lt", 1024), ("gt", 1023), ("eq", 3389),
         ("range", 0, 100), ("gt", 8000), ("eq", 65535), ("neq", 80)]
NAMED = {22: "ssh", 53: "domain", 80: "www", 443: "443"}
ICMP = [(8, None), (0, None), (3, None), (3, 1), (11, None)]
ICMP_IOS = {8: "echo", 0: "echo-reply", 3: "unreachable", 11: "time-exceeded"}
ICMP_JUNOS = {8: "echo-request", 0: "echo-reply", 3: "unreachable", 11: "time-exceeded"}


def random_acl(rng: random.Random, n=(4, 14)):
    rules = []
    for _ in range(rng.randint(*n)):
        r = {"action": rng.choices(["permit", "deny"], [55, 45])[0],
             "proto": rng.choices(["ip", "tcp", "udp", "icmp", "gre"], [20, 35, 25, 15, 5])[0],
             "src": rng.choice(NETS) if rng.random() < 0.7 else "any",
             "dst": rng.choice(NETS) if rng.random() < 0.7 else "any",
             "sport": None, "dport": None, "icmp": None, "est": False}
        if r["proto"] in ("tcp", "udp"):
            if rng.random() < 0.65:
                r["dport"] = rng.choice(PORTS)
            if rng.random() < 0.12:
                r["sport"] = rng.choice(PORTS)
            if r["proto"] == "tcp" and rng.random() < 0.06:
                r["est"] = True
        if r["proto"] == "icmp" and rng.random() < 0.6:
            r["icmp"] = rng.choice(ICMP)
        rules.append(r)
    return rules


def _wild(net: str, style: str) -> str:
    if net == "any":
        return "any"
    n = ipaddress.ip_network(net)
    if n.prefixlen == 32:
        return f"host {n.network_address}" if style != "prefix" else f"{n.network_address}/32"
    if style == "wildcard":
        return f"{n.network_address} {n.hostmask}"
    if style == "netmask":
        return f"{n.network_address} {n.netmask}"
    return str(n)


def _port(p, named=False):
    if p is None:
        return ""
    if p[0] == "range":
        return f" range {p[1]} {p[2]}"
    v = NAMED.get(p[1], p[1]) if named and p[0] == "eq" else p[1]
    return f" {p[0]} {v}"


def _cisco_line(r, style, named):
    s = f"{r['action']} {r['proto']} {_wild(r['src'], style)}{_port(r['sport'], named)}" \
        f" {_wild(r['dst'], style)}{_port(r['dport'], named)}"
    if r["icmp"]:
        t, c = r["icmp"]
        s += f" {ICMP_IOS[t]}" if c is None else f" {t} {c}"
    if r["est"]:
        s += " established"
    return s


def render(rules, vendor: str, name: str, host: str) -> str:
    if vendor == "ios":
        body = "\n".join(" " + _cisco_line(r, "wildcard", True) for r in rules)
        return f"hostname {host}\n!\nip access-list extended {name}\n{body}\n!\nend\n"
    if vendor == "asa":
        body = "\n".join(f"access-list {name} extended " + _cisco_line(r, "netmask", False)
                         for r in rules if not r["est"])
        return f": Saved\nASA Version 9.8(4)\n!\nhostname {host}\n{body}\n"
    if vendor == "eos":
        body = "\n".join(f"   {10 * (i + 1)} " + _cisco_line(r, "prefix", False)
                         for i, r in enumerate(rules))
        return f"! device: {host} (DCS-7050, EOS-4.27)\nhostname {host}\n!\nip access-list {name}\n{body}\n!\nend\n"
    if vendor == "nxos":
        body = "\n".join(f"  {10 * (i + 1)} " + _cisco_line(r, "prefix", False)
                         for i, r in enumerate(rules))
        return f"!Command: show running-config\nversion 9.3(5)\nhostname {host}\n!\nip access-list {name}\n{body}\n"
    if vendor in ("junosx", "junosset"):
        return _render_junos_ext(rules, name, host, set_form=vendor == "junosset")
    if vendor == "junos":
        terms = []
        for i, r in enumerate(rules):
            fr = []
            if r["src"] != "any":
                fr.append(f"source-address {{ {r['src']}; }}")
            if r["dst"] != "any":
                fr.append(f"destination-address {{ {r['dst']}; }}")
            if r["proto"] != "ip":
                fr.append(f"protocol {r['proto']};")
            for key, p in (("source-port", r["sport"]), ("destination-port", r["dport"])):
                if p is None:
                    continue
                if p[0] == "eq":
                    fr.append(f"{key} {p[1]};")
                elif p[0] == "range":
                    fr.append(f"{key} {p[1]}-{p[2]};")
                elif p[0] == "lt":
                    fr.append(f"{key} 0-{p[1] - 1};")
                elif p[0] == "gt":
                    fr.append(f"{key} {p[1] + 1}-65535;")
                elif p[0] == "neq":
                    fr.append(f"{key}-except {p[1]};")
            if r["icmp"]:
                t, c = r["icmp"]
                fr.append(f"icmp-type {ICMP_JUNOS[t]};")
                if c is not None:
                    fr.append(f"icmp-code {c};")
            if r["est"]:
                fr.append("tcp-established;")
            then = "accept" if r["action"] == "permit" else "discard"
            frm = f"from {{ {' '.join(fr)} }} " if fr else ""
            terms.append(f"            term t{i} {{ {frm}then {then}; }}")
        return ("system { host-name %s; }\nfirewall {\n    family inet {\n        filter %s {\n%s\n        }\n    }\n}\n"
                % (host, name, "\n".join(terms)))
    raise ValueError(vendor)


def _junos_port(p):
    if p[0] == "eq":
        return [str(p[1])]
    if p[0] == "range":
        return [f"{p[1]}-{p[2]}"]
    if p[0] == "lt":
        return [f"0-{p[1] - 1}"]
    if p[0] == "gt":
        return [f"{p[1] + 1}-65535"]
    return None


def _render_junos_ext(rules, name, host, set_form=False):
    """Junos with the constructs the corpus showed: prefix-lists (with a v6
    entry the inet filter must ignore), direction-agnostic `port`, terms with
    only nonterminating actions (implicit accept). Brace or `set` form."""
    pls = {}
    terms = []
    for i, r in enumerate(rules):
        fr = []                                   # (key, [values])
        if r["src"] != "any":
            if i % 3 == 0:
                pls[f"PL{i}"] = [r["src"], "2001:db8::/32"]
                fr.append(("source-prefix-list", [f"PL{i}"]))
            else:
                fr.append(("source-address", [r["src"]]))
        if r["dst"] != "any":
            if i % 3 == 1:
                pls[f"PLD{i}"] = [r["dst"]]
                fr.append(("destination-prefix-list", [f"PLD{i}"]))
            else:
                fr.append(("destination-address", [r["dst"]]))
        if r["proto"] != "ip":
            fr.append(("protocol", [r["proto"]]))
        for key, p in (("source-port", r["sport"]), ("destination-port", r["dport"])):
            if p is None:
                continue
            v = _junos_port(p)
            if v is None:
                fr.append((key + "-except", [str(p[1])]))
            elif key == "destination-port" and r["sport"] is None and i % 2 == 0:
                fr.append(("port", v))
            else:
                fr.append((key, v))
        if r["icmp"]:
            t, c = r["icmp"]
            fr.append(("icmp-type", [ICMP_JUNOS[t]]))
            if c is not None:
                fr.append(("icmp-code", [str(c)]))
        if r["est"]:
            fr.append(("tcp-established", []))
        if r["action"] == "permit" and i % 4 == 1:
            then = [f"count c{i}"]
        else:
            then = ["accept" if r["action"] == "permit" else "discard"]
        terms.append((f"t{i}", fr, then))
    if set_form:
        out = [f"set system host-name {host}"]
        for n, vals in pls.items():
            out += [f"set policy-options prefix-list {n} {v}" for v in vals]
        base = f"set firewall family inet filter {name}"
        for t, fr, then in terms:
            for k, vs in fr:
                if not vs:
                    out.append(f"{base} term {t} from {k}")
                for v in vs:
                    out.append(f"{base} term {t} from {k} {v}")
            out += [f"{base} term {t} then {x}" for x in then]
        return "\n".join(out) + "\n"
    pl = "".join(f"    prefix-list {n} {{ {' '.join(v + ';' for v in vals)} }}\n"
                 for n, vals in pls.items())
    body = []
    for t, fr, then in terms:
        f = " ".join(f"{k} {{ {' '.join(v + ';' for v in vs)} }}" if vs else f"{k};" for k, vs in fr)
        frm = f"from {{ {f} }} " if fr else ""
        body.append(f"            term {t} {{ {frm}then {{ {' '.join(x + ';' for x in then)} }} }}")
    return ("system { host-name %s; }\npolicy-options {\n%s}\nfirewall {\n    family inet {\n"
            "        filter %s {\n%s\n        }\n    }\n}\n" % (host, pl, name, "\n".join(body)))
