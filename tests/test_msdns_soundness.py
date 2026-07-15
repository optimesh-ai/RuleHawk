"""Property-based soundness oracle for the Microsoft DNS frontend.

Sibling of test_infoblox_soundness — raises confidence in the second
least-battle-tested vendor by checking RuleHawk's verdict against an
independent ground-truth first-match evaluator over hundreds of random but
valid `Add-DnsServerQueryResolutionPolicy` configs.

Windows DNS semantics being pinned (Microsoft `Add-DnsServerQueryResolutionPolicy`
docs): query-resolution policies are evaluated in ascending `-ProcessingOrder`,
first match wins; `-Action ALLOW` serves the query (reachable), `DENY`/`IGNORE`
does not; a client matched by NO policy hits the server DEFAULT, which is to
resolve normally (ALLOW). Because that default-allow region cannot be *proven*
isolated from the config alone, RuleHawk models it with a fail-closed imprecise
marker → the honest verdict there is INDETERMINATE, never a confident PASS.

The generator uses only the exactly-modeled forms: distinct client-subnet names,
`-ClientSubnet "EQ,<name>"` selectors, distinct `-ProcessingOrder` values
(collisions and NE/AND are deliberately excluded — the frontend already flags
those imprecise, verified by the unit tests). So for a client a policy DECIDES,
RuleHawk must be exact; for a client in the default-allow region it must be
indeterminate (never a false isolation, never a false connectivity).
"""

from __future__ import annotations

import ipaddress
import random

from rulehawk.parse_msdns import parse_msdns
from rulehawk.segcheck import check_segmentation

_RESOLVER = "10.53.0.1"
_CLIENT_HOSTS = ([f"10.{i}.0.10" for i in range(4)]
                 + ["10.0.5.10", "10.1.5.10", "192.0.2.10", "172.16.0.10"])

# Named client subnets the generator draws from (name -> CIDR). Nested/disjoint
# so ordering matters and some hosts fall into the default-allow region.
_SUBNETS = {
    "S8": "10.0.0.0/8", "S16a": "10.0.0.0/16", "S16b": "10.1.0.0/16",
    "S24": "10.0.0.0/24", "Spub": "192.0.2.0/24",
}


def _oracle(policies, client_ip):
    """TRUE Windows first-match by ProcessingOrder. policies is a list of
    (order, action, cidr). Returns "reach" | "noreach" | "default_allow"."""
    ip = ipaddress.ip_address(client_ip)
    for order, action, cidr in sorted(policies, key=lambda p: p[0]):
        if ip in cidr:
            return "reach" if action == "ALLOW" else "noreach"
    return "default_allow"          # matched no policy -> server default ALLOW


def _render(subnet_defs, policies):
    lines = []
    for name, cidr in subnet_defs.items():
        lines.append(f'Add-DnsServerClientSubnet -Name "{name}" '
                     f'-IPv4Subnet "{cidr}"')
    for order, action, name in policies:
        lines.append(f'Add-DnsServerQueryResolutionPolicy -Name "P{order}" '
                     f'-Action {action} -ClientSubnet "EQ,{name}" '
                     f'-ProcessingOrder {order}')
    return "\n".join(lines) + "\n"


def _gen(rng):
    names = list(_SUBNETS)
    k = rng.randint(1, 4)
    orders = rng.sample(range(1, 50), k)          # DISTINCT processing orders
    chosen = [(o, rng.choice(["ALLOW", "DENY", "IGNORE"]), rng.choice(names))
              for o in orders]
    # subnet defs actually referenced (plus maybe an extra unused one)
    used = {c[2] for c in chosen}
    defs = {n: _SUBNETS[n] for n in used}
    return defs, chosen


def _tool_verdict(config, client_ip):
    aces, _ = parse_msdns(config)
    zones = {"CLIENT": [f"{client_ip}/32"], "DNS": [f"{_RESOLVER}/32"]}
    mnr = {f.kind for f in check_segmentation(aces, {
        "zones": zones,
        "must_not_reach": [{"src": "CLIENT", "dst": "DNS", "proto": "udp",
                            "ports": [53]}]})}
    if "segmentation-indeterminate" in mnr:
        return "indet"
    if "segmentation-violation" in mnr:
        return "reach"
    if "segmentation-ok" in mnr:
        return "noreach"
    return "indet"


def test_msdns_verdicts_match_windows_first_match_oracle():
    rng = random.Random(0xD115)
    decided_trials = 0
    default_trials = 0
    for _ in range(500):
        defs, chosen = _gen(rng)
        policies = [(o, a, ipaddress.ip_network(_SUBNETS[n]))
                    for (o, a, n) in chosen]
        config = _render(defs, chosen)
        for client_ip in _CLIENT_HOSTS:
            truth = _oracle(policies, client_ip)
            got = _tool_verdict(config, client_ip)
            if truth == "reach":
                # an ALLOW policy decides this /32 exactly -> must be a violation
                assert got == "reach", (
                    f"MISSED reach (false isolation risk): {config!r} "
                    f"{client_ip} tool={got}")
                decided_trials += 1
            elif truth == "noreach":
                # a DENY/IGNORE policy exactly blocks this /32 -> isolated
                assert got == "noreach", (
                    f"WRONG verdict on an exact deny: {config!r} {client_ip} "
                    f"tool={got}")
                decided_trials += 1
            else:  # default_allow region
                # Windows would resolve (allow) — RuleHawk can't PROVE isolation
                # here, so it must be indeterminate: it must NEVER certify
                # "isolated" (noreach) for a client the default actually serves.
                assert got != "noreach", (
                    f"FALSE isolation of a default-allowed client: {config!r} "
                    f"{client_ip} tool={got}")
                default_trials += 1
    assert decided_trials >= 500      # policies actually decided many clients
    assert default_trials >= 100      # and the default-allow region was hit
