"""Property-based soundness oracle for the Infoblox / BIND DNS-ACL frontend.

The two DNS frontends (Infoblox/BIND and Microsoft DNS) are the least
battle-tested vendors — fewer hand-written tests, less-standardized real-world
input. This test raises confidence the way the core engine's oracle does: it
GENERATES hundreds of random but grammatically-valid `allow-query` address
match-lists, computes the TRUE first-match reach-the-resolver decision for every
client in a small universe independently (a faithful re-implementation of BIND's
ordered address_match_list semantics), and asserts RuleHawk's end-to-end verdict
never contradicts it in the unsound direction.

BIND semantics being pinned (ISC BIND ARM, "Address Match Lists"): an
address-match-list is evaluated top-to-bottom, first match wins; a `!` prefix
means "explicitly does NOT match" (deny); if nothing matches the implicit
default is deny. `allow-query` gates whether a client may get a DNS answer.

Two arms:
  * EXACT arm — lists built only from CIDRs, `!CIDR` negations, and `any`
    (the fully-modeled subset). RuleHawk must be PRECISE: its verdict equals
    the oracle's for every client (no false PASS, no false OK, no needless
    indeterminate).
  * FAIL-CLOSED arm — lists that also include an unmodeled element
    (`localnets`, an undefined acl reference). RuleHawk must never emit a
    CONFIDENT wrong verdict; where it can't be exact it must be indeterminate.
"""

from __future__ import annotations

import ipaddress
import random

from rulehawk.parse_infoblox import parse_infoblox
from rulehawk.segcheck import check_segmentation

# A small, fully-enumerable client universe of SINGLE HOSTS (/32) — the oracle
# evaluates one IP, so the tool must be asked about that same one IP (a broader
# client zone could straddle a /25 boundary and legitimately both reach and not
# reach). Hosts span the /25 boundary at .0 and .128 so ordered negations bite.
_RESOLVER = "10.53.0.1"
_CLIENT_HOSTS = ([f"10.0.{i}.10" for i in range(4)]
                 + ["10.0.0.200", "10.0.1.200", "192.0.2.10", "172.16.0.10"])

# CIDR pool the generator draws match-list members from — nested and disjoint
# so first-match ordering actually matters.
_CIDR_POOL = [
    "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24",
    "10.0.3.0/24", "10.0.0.0/25", "192.0.2.0/24", "0.0.0.0/0",
]


def _member_matches(kind_cidr, client_ip):
    """Does this match-list member match the client? kind_cidr is
    ("any",) | ("cidr", net) | ("!cidr", net)."""
    if kind_cidr[0] == "any":
        return True
    return ipaddress.ip_address(client_ip) in kind_cidr[1]


def _oracle_reachable(members, client_ip):
    """TRUE BIND first-match: walk members; first that matches decides
    (permit for a plain member, DENY for a `!` member); default deny."""
    for m in members:
        if _member_matches(m, client_ip):
            return m[0] != "!cidr"        # plain -> permit, negated -> deny
    return False                          # implicit default deny


def _render(members):
    parts = []
    for m in members:
        if m[0] == "any":
            parts.append("any;")
        elif m[0] == "cidr":
            parts.append(f"{m[1]};")
        else:
            parts.append(f"!{m[1]};")
    return "options {\n allow-query { " + " ".join(parts) + " }; };\n"


def _gen_members(rng, allow_any=True):
    n = rng.randint(1, 6)
    out = []
    for _ in range(n):
        r = rng.random()
        if allow_any and r < 0.08:
            out.append(("any",))
        elif r < 0.55:
            out.append(("cidr", ipaddress.ip_network(rng.choice(_CIDR_POOL))))
        else:
            out.append(("!cidr", ipaddress.ip_network(rng.choice(_CIDR_POOL))))
    return out


def _tool_verdict(config, client_ip):
    """RuleHawk's reach verdict for the single host client_ip -> resolver on 53,
    both directions. Returns one of "reach", "noreach", "indet"."""
    aces, _ = parse_infoblox(config)
    zones = {"CLIENT": [f"{client_ip}/32"], "DNS": [f"{_RESOLVER}/32"]}
    mnr = {f.kind for f in check_segmentation(aces, {
        "zones": zones,
        "must_not_reach": [{"src": "CLIENT", "dst": "DNS", "proto": "udp",
                            "ports": [53]}]})}
    mr = {f.kind for f in check_segmentation(aces, {
        "zones": zones,
        "must_reach": [{"src": "CLIENT", "dst": "DNS", "proto": "udp",
                        "ports": [53]}]})}
    if "segmentation-indeterminate" in mnr or "connectivity-indeterminate" in mr:
        return "indet"
    # must_not_reach: violation => the tool says reachable; ok => isolated.
    if "segmentation-violation" in mnr:
        return "reach"
    if "segmentation-ok" in mnr:
        return "noreach"
    return "indet"


def test_exact_matchlists_match_bind_first_match_oracle():
    rng = random.Random(0xB1AD)
    trials = 0
    for _ in range(400):
        members = _gen_members(rng, allow_any=True)
        config = _render(members)
        for client_ip in _CLIENT_HOSTS:
            truth = _oracle_reachable(members, client_ip)
            got = _tool_verdict(config, client_ip)
            # Exact subset -> RuleHawk must be precise and correct.
            assert got != "indet", (
                f"needless indeterminate on an exact list: {config!r} client {client_ip}")
            assert (got == "reach") == truth, (
                f"SOUNDNESS DIVERGENCE: config {config!r} client {client_ip} "
                f"oracle_reachable={truth} tool={got}")
            trials += 1
    assert trials >= 3000            # the oracle actually exercised the engine


def test_unmodeled_elements_fail_closed_never_confidently_wrong():
    # A list that mixes exact members with an UNMODELED one (localnets / an
    # undefined acl ref). RuleHawk must never emit a CONFIDENT verdict that
    # contradicts what is *provable* from the exact members alone: specifically
    # it must never certify "isolated" (noreach) for a client an exact permit
    # already reaches, nor certify "reachable" for a client an exact deny
    # already blocks. Elsewhere it may be indeterminate.
    rng = random.Random(0x10CA)
    for _ in range(300):
        members = _gen_members(rng, allow_any=False)
        # splice in an unmodeled element at a random position
        unmodeled = rng.choice([("raw", "localnets;"), ("raw", "trustedX;")])
        pos = rng.randint(0, len(members))
        rendered = []
        for i, m in enumerate(members):
            if i == pos:
                rendered.append(unmodeled[1])
            rendered.append("any;" if m[0] == "any" else
                            (f"{m[1]};" if m[0] == "cidr" else f"!{m[1]};"))
        if pos >= len(members):
            rendered.append(unmodeled[1])
        config = "options {\n allow-query { " + " ".join(rendered) + " }; };\n"
        for client_ip in _CLIENT_HOSTS:
            got = _tool_verdict(config, client_ip)
            # What is decided BEFORE the unmodeled element (exact prefix)?
            decided = None
            for m in members[:pos]:
                if _member_matches(m, client_ip):
                    decided = (m[0] != "!cidr")
                    break
            if decided is True:                 # an exact permit already reaches
                assert got != "noreach", (
                    f"FALSE isolation despite an exact permit: {config!r} {client_ip}")
            elif decided is False:              # an exact deny already blocks
                assert got != "reach", (
                    f"FALSE reach despite an exact deny: {config!r} {client_ip}")
            # else: undecided before the unmodeled element -> any verdict is
            # allowed to be indeterminate; we only forbid confident-wrong.
