"""Zone placement for the allowlist (#42 design v3 section 5.1, v4 sections
2, 3, 10 and 13), read from the final model. Shadow only: nothing here
changes a verdict.

A filter between two zones protects the asserted flow only if traffic
between them has to cross it. From the final model of a file the grammar
parses:
- a segment is an addressed Junos unit (`family inet` with an `address`),
  its network the address's subnet. The PAN-OS and iptables grammars have
  no interface production yet, so their files have no segment;
- (a) a segment that overlaps two asserted zones gives
  `zones-share-segment`;
- a zone is pinned when every CIDR of it lies inside one segment that
  carries no other asserted zone. A CIDR that is not IPv4 cannot be shown
  inside a segment, so its zone is unpinned;
- any unpinned zone adds the placement assumption: a `scope_assumptions`
  sentence, a `headline_assumptions` line, the `zone-placement-assumed` row,
  and, in the strict mode, `zone-placement-unpinned`.

Every zone in the policy is an asserted zone (decided by agent,
unattended: the more conservative reading). Rules (b), (c) and (d) and
`rule-type` read constructs no grammar has a production for, so a file
holding one does not parse and gets no placement.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

ZONES_SHARE_SEGMENT = "zones-share-segment"
ZONE_PLACEMENT_UNPINNED = "zone-placement-unpinned"
ZONE_PLACEMENT_ASSUMED = "zone-placement-assumed"

# Review of #52-#57, G9: no grammar has a static-route production, so the
# sentence does not claim routes were checked.
SCOPE = ("RuleHawk checked the interfaces this file configures; it read no "
         "static route; zones not attached in this file are assumed not to "
         "share a segment with another asserted zone.")


def _networks(cidrs) -> Optional[List[ipaddress.IPv4Network]]:
    """The zone's IPv4 networks, or None when any CIDR is not one."""
    out = []
    for c in cidrs if isinstance(cidrs, list) else [cidrs]:
        try:
            net = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            return None
        if not isinstance(net, ipaddress.IPv4Network):
            return None
        out.append(net)
    return out


def _segments(model: dict) -> List[dict]:
    out = []
    if model.get("dialect") != "junos":
        return out
    for obj in model["objects"]:
        path = obj["path"]
        if (len(path) == 4 and path[0] == "interfaces" and path[3] == "family inet"
                and "address" in obj["values"]):
            iface = ipaddress.ip_interface(obj["values"]["address"])
            out.append({"path": list(path), "network": str(iface.network)})
    return out


def _join(names: List[str]) -> str:
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def assess(model: dict, zones: Dict[str, object]) -> dict:
    """The placement entry for one parsed file under a policy's zones."""
    nets = {name: _networks(cidrs) for name, cidrs in sorted(zones.items())}
    # Review of #52-#57, G3: a zone with any CIDR placement cannot read as
    # IPv4 is not dropped from rule (a); it may sit on any segment, so
    # placement is off (fail closed).
    unreadable = sorted(name for name, ns in nets.items() if ns is None)
    segments = _segments(model)
    reason = ZONES_SHARE_SEGMENT if unreadable else None
    # Review of #52-#57, G4: the units of one physical interface are one L2
    # wire (no VLAN separation is cited), so they are one segment.
    port_nets: Dict[tuple, list] = {}
    for seg in segments:
        port_nets.setdefault(tuple(seg["path"][:2]), []).append(
            ipaddress.ip_network(seg["network"]))
    for seg in segments:
        wire = port_nets[tuple(seg["path"][:2])]
        seg["zones"] = sorted(
            name for name, ns in nets.items()
            if ns is None or any(w.overlaps(n) for w in wire for n in ns))
        if len(seg["zones"]) >= 2:
            reason = ZONES_SHARE_SEGMENT
    pinned = []
    for name, ns in nets.items():
        if not ns:
            continue
        own = [ipaddress.ip_network(s["network"]) for s in segments if s["zones"] == [name]]
        if all(any(n.subnet_of(o) for o in own) for n in ns):
            pinned.append(name)
    unpinned = [name for name in nets if name not in pinned]
    assumed = bool(unpinned) and not unreadable
    return {
        "segments": segments,
        "pinned": pinned,
        "unpinned": unpinned,
        "unreadable": unreadable,
        "reason": reason,
        "scope_assumptions": [SCOPE],
        "headline_assumptions": ([f"assumes {_join(list(nets))} are on separate segments"]
                                 if assumed else []),
        "rows": [ZONE_PLACEMENT_ASSUMED] if assumed else [],
        "strict_reason": reason or (ZONE_PLACEMENT_UNPINNED if unpinned else None),
    }


def unavailable(error: BaseException) -> dict:
    """The placement entry when assessing failed (review of #52-#57, G8):
    nothing is pinned, and both modes block."""
    return {"segments": [], "pinned": [], "unpinned": [], "unreadable": [],
            "error": type(error).__name__, "reason": ZONE_PLACEMENT_UNPINNED,
            "scope_assumptions": [SCOPE], "headline_assumptions": [], "rows": [],
            "strict_reason": ZONE_PLACEMENT_UNPINNED}
