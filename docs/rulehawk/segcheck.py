"""Segmentation-intent checking — the audit-evidence / compliance value.

Declare zones (named CIDR sets) and `must_not_reach` assertions, e.g. "CORP must
not reach PCI on tcp/445,3389". For each assertion we look for a permit rule that
could enable a forbidden flow, build a CONCRETE WITNESS packet inside the
forbidden space, and EVALUATE THE ORDERED ACL on that witness (first-match
semantics, honoring earlier denies). Only a witness the ACL actually permits is
reported — so every violation is a real packet an auditor can verify, and an
earlier deny that already blocks it produces NO false alarm.

Policy (JSON):
  {"zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
   "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp",
                       "ports": [445, 3389]}]}
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple

from .analyze import Finding
from .model import ACE, _WILDCARD_PROTO, _IPNet


def _net(s: str) -> _IPNet:
    return ipaddress.ip_network(s, strict=False)


def _intersect(a: _IPNet, b: _IPNet) -> Optional[_IPNet]:
    if a.version != b.version:
        return None
    if a.subnet_of(b):
        return a
    if b.subnet_of(a):
        return b
    return None


def _witness_host(net: _IPNet) -> str:
    return str(next(iter(net.hosts()), net.network_address))


def _rule_matches(r: ACE, proto: str, src: str, dst: str, port: Optional[int]):
    """How rule r decides concrete flow (proto, src, dst, port):
    returns True (matches), False (no match), or "indeterminate"."""
    if r.stateful:
        return False  # `established` matches only return traffic, not a new flow
    if not (r.proto in _WILDCARD_PROTO or r.proto == proto):
        return False
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s not in r.src or d not in r.dst:
        return False
    if r.imprecise:
        # non-port dims match but the space was over-approximated -> can't decide.
        return "indeterminate"
    if proto in ("tcp", "udp") and port is not None and not r.dst_port.contains(port):
        return False
    return True


def _eval_acl(aces: List[ACE], proto: str, src: str, dst: str,
              port: Optional[int]) -> Tuple[str, Optional[ACE]]:
    """First-match evaluation; default deny if nothing matches."""
    for r in aces:
        m = _rule_matches(r, proto, src, dst, port)
        if m is False:
            continue
        if m == "indeterminate":
            return "indeterminate", r
        return r.action, r           # first concrete match decides
    return "deny", None              # implicit default deny


def check_segmentation(aces: List[ACE], policy: dict) -> List[Finding]:
    findings: List[Finding] = []
    zones = {name: [_net(c) for c in cidrs]
             for name, cidrs in (policy.get("zones") or {}).items()}
    for assertion in (policy.get("must_not_reach") or []):
        sname, dname = assertion.get("src"), assertion.get("dst")
        proto = (assertion.get("proto") or "ip").lower()
        ports = assertion.get("ports") or [None]
        label = f"{sname}!->{dname}" + (f"/{proto}" if proto != "ip" else "")
        reported = False
        for sa in zones.get(sname, []):
            for db in zones.get(dname, []):
                for port in ports:
                    for r in aces:
                        if r.action != "permit":
                            continue
                        if not (r.proto in _WILDCARD_PROTO or r.proto == proto
                                or proto == "ip"):
                            continue
                        si, di = _intersect(sa, r.src), _intersect(db, r.dst)
                        if si is None or di is None:
                            continue
                        if (port is not None and r.proto in ("tcp", "udp")
                                and not r.imprecise and not r.dst_port.contains(port)):
                            continue
                        swit, dwit = _witness_host(si), _witness_host(di)
                        eff, dec = _eval_acl(aces, proto, swit, dwit, port)
                        portsfx = f":{port}" if port is not None else ""
                        if eff == "permit":
                            findings.append(Finding(
                                f"{r.acl}:{dec.seq}", "segmentation-violation",
                                "critical",
                                f"SEGMENTATION VIOLATION ({sname} must not reach "
                                f"{dname}): the ACL PERMITS {swit} -> {dwit}"
                                f"{portsfx} ({proto}) via rule {dec.seq}.",
                                dec.raw,
                                fix=f"deny {sname}->{dname}{portsfx} before rule {dec.seq}"))
                            reported = True
                            break
                        if eff == "indeterminate":
                            findings.append(Finding(
                                f"{r.acl}:{dec.seq}", "segmentation-indeterminate",
                                "medium",
                                f"Cannot prove {sname} is isolated from {dname} — "
                                f"rule {dec.seq} uses an unmodeled form "
                                f"(neq/complex mask); review manually.",
                                dec.raw, fix="rewrite the rule with explicit ports/masks"))
                            reported = True
                            break
                    if reported:
                        break
                if reported:
                    break
            if reported:
                break
        if not reported:
            findings.append(Finding(
                label, "segmentation-ok", "info",
                f"PASS: {sname} cannot reach {dname}"
                + (f" on {proto}/{ports}" if proto != "ip" else "")
                + " (no permitted witness flow found).", "",
                fix=""))
    return findings
