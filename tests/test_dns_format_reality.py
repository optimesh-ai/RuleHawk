"""Format-reality guardrails for the two DNS frontends.

Research against the authoritative sources (ISC BIND 9.18 ARM; Microsoft
`Add-`/`Get-DnsServerQueryResolutionPolicy` docs) established WHAT real
artifacts an admin actually has:

  * Infoblox/BIND — an ISC BIND operator's native artifact is `named.conf`
    (what this frontend targets). A pure *Infoblox NIOS* shop instead exports
    the `namedacl` WAPI JSON object / Grid CSV; NIOS emits `named.conf` only as
    a one-way legacy IMPORT source, so a NIOS live config is out of scope.
  * Microsoft DNS — this frontend targets the `Add-DnsServerQueryResolutionPolicy`
    / `Add-DnsServerClientSubnet` provisioning cmdlets (an IaC/DSC artifact).
    The audit-time `Get-DnsServerQueryResolutionPolicy` OUTPUT hides the match
    criteria behind the opaque `{DnsServerPolicyCriteria}` token, so it is not a
    usable input on its own and is out of scope.

The load-bearing property these tests pin: **feeding an OUT-OF-SCOPE DNS format
never yields a false green.** An unrecognized format routes to no parser →
`no_rules_parsed` → the gate exits 2 (fail-closed) — it can never be mistaken
for a clean audit. The format gap is therefore a coverage/UX limit, not a
soundness risk. The tests also pin that the real, in-scope `named.conf` grammar
(as published in the BIND ARM) parses.
"""

from __future__ import annotations

import json

from rulehawk import gate
from rulehawk.parse_infoblox import detect as detect_infoblox, parse_infoblox
from rulehawk.parse_msdns import detect as detect_msdns
from rulehawk.segcheck import check_segmentation

# A canonical, grammar-conformant ISC BIND named.conf ACL config (BIND 9.18 ARM
# forms: named acl, CIDR, `!` negation, builtins, `key`, first-match ordering,
# and the 9.18 `port`/`transport` allow-transfer prefix).
_NAMED_CONF = """acl "trusted" {
    !192.0.2.66;
    192.0.2.0/24;
    10.0.0.0/8;
    localnets;
    localhost;
    key "transfer-key";
};
options {
    allow-query       { trusted; };
    allow-recursion   { trusted; };
    allow-transfer port 853 transport tls { 192.0.2.10; key "transfer-key"; };
    allow-transfer    { none; };
};
"""

# The Microsoft audit-time artifact — Get-DnsServerQueryResolutionPolicy output.
# Note the criteria are hidden behind {DnsServerPolicyCriteria}; there is no
# ClientSubnet/CIDR anywhere, so it is NOT a usable input (out of scope).
_MSDNS_GET_OUTPUT = """Action                : Ignore
AppliesOn             : QueryProcessing
Condition             : And
Content               :
Criteria              : {DnsServerPolicyCriteria}
IsEnabled             : True
Level                 : Server
Name                  : DropPolicyMalicious
ProcessingOrder       : 2
ZoneName              :
CimClass              : root/Microsoft/Windows/DNS:DnsServerPolicy
"""

# The Infoblox NIOS artifact — a `namedacl` WAPI JSON object (out of scope).
_INFOBLOX_WAPI_JSON = json.dumps({
    "name": "trusted", "comment": "internal ranges",
    "access_list": [
        {"address": "192.0.2.0/24", "permission": "ALLOW"},
        {"address": "10.0.0.5", "permission": "DENY"},
    ],
})


def test_real_bind_named_conf_parses_and_is_sound():
    # The in-scope format (ISC BIND named.conf) parses to real ACEs, no crash.
    assert detect_infoblox(_NAMED_CONF)
    aces, notes = parse_infoblox(_NAMED_CONF)
    assert len(aces) > 0
    # A genuinely-permitted client (192.0.2.10, in `trusted`, not the negated
    # .66) is reachable -> the isolation check correctly reports a violation,
    # not a false PASS.
    pol = {"zones": {"C": ["192.0.2.10/32"], "D": ["10.53.0.1/32"]},
           "must_not_reach": [{"src": "C", "dst": "D", "proto": "udp",
                               "ports": [53]}]}
    assert "segmentation-ok" not in {f.kind for f in check_segmentation(aces, pol)}


def _fails_closed(tmp_path, name, content):
    """An out-of-scope format must route to no parser and fail closed (exit 2),
    NEVER a clean pass. Returns the gate result for extra assertions."""
    p = tmp_path / name
    p.write_text(content)
    rc = gate.main([str(p), "-q"])
    assert rc == 2, f"{name}: expected fail-closed exit 2, got {rc}"


def test_msdns_get_output_is_out_of_scope_and_fails_closed(tmp_path):
    # The Get- audit output is not the Add- cmdlet form and hides its criteria;
    # it must NOT be mis-detected, and must fail closed (never a false green).
    assert not detect_msdns(_MSDNS_GET_OUTPUT)
    _fails_closed(tmp_path, "policy.txt", _MSDNS_GET_OUTPUT)


def test_infoblox_wapi_json_is_out_of_scope_and_fails_closed(tmp_path):
    # A NIOS namedacl WAPI JSON object is not named.conf; it must not be claimed
    # by the BIND parser (or any JSON parser) and must fail closed.
    assert not detect_infoblox(_INFOBLOX_WAPI_JSON)
    _fails_closed(tmp_path, "acl.json", _INFOBLOX_WAPI_JSON)


def test_out_of_scope_dns_never_certifies_a_policy_pass(tmp_path):
    # Belt-and-suspenders: even WITH a segmentation policy, an out-of-scope DNS
    # artifact never produces segmentation-ok / connectivity-ok — the gate fails
    # closed on the unparsed file before any verdict can be rendered.
    import os
    pol = {"zones": {"C": ["10.0.0.0/16"], "D": ["10.53.0.1/32"]},
           "must_not_reach": [{"src": "C", "dst": "D", "proto": "udp",
                               "ports": [53]}]}
    polp = tmp_path / "pol.json"
    polp.write_text(json.dumps(pol))
    cfgp = tmp_path / "cfg.txt"
    cfgp.write_text(_MSDNS_GET_OUTPUT)
    rc = gate.main([str(cfgp), "--policy", str(polp), "-q"])
    assert rc == 2
    assert os.path.exists(str(polp))  # silence lint
