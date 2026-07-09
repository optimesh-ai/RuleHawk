# Segmentation policy reference

A RuleHawk segmentation policy is a small JSON file that declares your network's
**zones** and the flows that must **never** be possible between them. RuleHawk
proves each promise on every run by searching for a concrete packet the config
would permit across the forbidden boundary — and reports that packet as the
finding if it finds one.

Pass it with `--policy path/to/policy.json` (CLI) or the `policy:` input (Action).

## Schema

```jsonc
{
  "zones": {
    "<ZONE_NAME>": ["<CIDR>", "<CIDR>", ...],   // one or more networks per zone
    ...
  },
  "must_not_reach": [
    {
      "src":   "<ZONE_NAME>",   // required — source zone (must be a key in "zones")
      "dst":   "<ZONE_NAME>",   // required — destination zone
      "proto": "<protocol>",    // optional — default "ip" (any protocol)
      "ports": [<int>, ...]     // optional — default: all ports
    },
    ...
  ]
}
```

### `zones`
An object mapping a zone name to a list of CIDR networks.

- Networks are parsed non-strictly, so `10.20.0.0/16` and `10.20.5.0/24` both work,
  and host bits are tolerated.
- **IPv4 and IPv6** are both supported (`2001:db8::/32`).
- A zone may contain several disjoint networks: `"CORP": ["10.20.0.0/16", "172.16.0.0/12"]`.

### `must_not_reach`
An array of assertions. Each says "`src` must not be able to reach `dst`" — over a
protocol/ports you optionally narrow.

| Field | Required | Default | Notes |
|---|---|---|---|
| `src` | yes | — | a zone name defined in `zones` |
| `dst` | yes | — | a zone name defined in `zones` |
| `proto` | no | `"ip"` | `ip` = **any** protocol. Otherwise the rule's protocol must match. |
| `ports` | no | all ports | a JSON **array of integers**. Only meaningful for `tcp`/`udp`. |

**Valid `proto` values:** `ip` (wildcard — any protocol), `tcp`, `udp`, `icmp`,
`icmpv6`, and other IP protocols the parsers recognize (`gre`, `esp`, `ah`,
`ospf`, `sctp`). Use `ip` when *any* reachability is forbidden (the strongest
assertion); use `tcp`/`udp` + `ports` when only specific services are forbidden.

**`ports` is an integer array only** — there is **no range syntax** here (`"80-443"`
is not valid in the policy; that belongs in the *config*, not the policy). List the
exact ports: `"ports": [445, 3389, 22, 1433]`. Omit `ports` to forbid all ports of
that protocol.

## Examples

**Minimal — CORP must never reach PCI on SMB/RDP:**
```json
{
  "zones": { "PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"] },
  "must_not_reach": [
    { "src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445, 3389] }
  ]
}
```

**Total isolation — the DMZ must never reach the CDE at all (any protocol):**
```json
{ "src": "DMZ", "dst": "PCI", "proto": "ip" }
```

**Multi-zone (the worked example) — PCI / CORP / DMZ / OT:**
```json
{
  "zones": {
    "PCI":  ["10.10.0.0/16"],
    "CORP": ["10.20.0.0/16"],
    "DMZ":  ["203.0.113.0/24"],
    "OT":   ["10.30.0.0/16"]
  },
  "must_not_reach": [
    { "src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445, 3389, 22, 1433] },
    { "src": "DMZ",  "dst": "PCI", "proto": "ip" },
    { "src": "CORP", "dst": "OT",  "proto": "tcp", "ports": [502, 20000] },
    { "src": "DMZ",  "dst": "OT",  "proto": "ip" }
  ]
}
```

**IPv6:**
```json
{
  "zones": { "MGMT": ["2001:db8:0:1::/64"], "PROD": ["2001:db8:0:2::/64"] },
  "must_not_reach": [ { "src": "PROD", "dst": "MGMT", "proto": "tcp", "ports": [22] } ]
}
```

## What RuleHawk reports per assertion

- **`segmentation-violation`** (critical) — the config permits a concrete witness
  packet across the boundary; reported with the exact packet and the rule that
  allowed it. An earlier `deny`/`DROP` that already blocks the flow yields **no**
  finding (first-match semantics are honored).
- **`segmentation-indeterminate`** (medium) — a rule on the path uses a form
  RuleHawk can't model exactly (a non-contiguous mask, an unresolved object-group,
  a `neq` operator). RuleHawk **fails closed** and asks you to review, rather than
  guess "isolated."
- **`segmentation-ok`** (info) — proven isolated: no permitted witness flow exists.
  This is a positive attestation, not just the absence of a finding.
- **`segmentation-policy-error`** (high) — the policy itself is invalid: a
  `src`/`dst` naming a zone that isn't defined, an unparseable CIDR in `zones`,
  or an unusable `ports` value. RuleHawk **fails closed**: the affected
  assertion is never given a PASS until the policy is fixed (a typo must not
  certify isolation over an empty search space).

## Gotchas

- **Zone names must match exactly.** A `src`/`dst` that isn't a key in `zones`
  raises `segmentation-policy-error` (high) — it can never vacuously "pass."
- **Ports may be integers or numeric strings** (`[445]` and `["445"]` both
  work); anything else is a `segmentation-policy-error`. There is **no range
  syntax** in the policy.
- **`ports` with `proto: "ip"`** restricts the check to port-carrying protocols
  (tcp/udp/sctp/...). Omit `ports` for total isolation.
- An unknown `proto` value is probed as-written: only wildcard (`ip`-proto)
  rules can match it, so a `permit ip any any` still trips it, but a typo like
  `"tpc"` will not match your tcp rules — stick to the protocols listed above.
- The policy declares **forbidden** flows. Everything not forbidden is allowed by
  the policy; the configs decide what is actually permitted.
