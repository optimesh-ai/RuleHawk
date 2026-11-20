# What RuleHawk does not check

RuleHawk reads the rules in one config file at a time and reasons about them on
their own. It does not know how your devices are wired together, so some
questions are outside what it can answer.

| Question | RuleHawk |
|---|---|
| Which rules are shadowed, dead, redundant, any-any, or expose risky services? | Yes |
| Does this ruleset permit a flow my policy forbids? (with an example packet) | Yes, per ruleset |
| Is that packet actually delivered across routing, NAT and topology? | No |
| What does this change (or the fix) break elsewhere, before I push? | No |
| What does a change affect across several devices? | No |

Answering the "No" rows needs a forwarding model of the whole network: one that
reads every device's routing, NAT and filters together. The open-source
[Batfish](https://github.com/batfish/batfish) is one. The maintainers of
RuleHawk also make a separate commercial product, Hammerhead, that does this.
Nothing in RuleHawk requires either; every feature in the README works on its
own.

When a RuleHawk result raises one of those questions (a live segmentation
violation, or a broken `must_reach` flow), the report adds one "Next:" line that
says a forwarding model is needed and names Batfish as an open-source one.

## Optional: path-grounded segmentation (`--hh-snapshot`)

This is the one RuleHawk feature that works only with Hammerhead: it needs a
Hammerhead install, which is licensed separately, and a Hammerhead snapshot of
the network. Leave the flags below out and RuleHawk works as described in the
README; nothing else in RuleHawk depends on them.

With both, RuleHawk checks each segmentation-violation witness packet against
Hammerhead's forwarding model (`hammerhead traceroute`). A violation on a routing
path that cannot actually deliver the packet is downgraded to informational; a
confirmed leak is stamped **path-confirmed**:

```
rulehawk config.txt --policy policy.json --hh-snapshot DIR --hh-from DEVICE
```

`DIR` is the Hammerhead snapshot directory and `DEVICE` is the source device the
witness packet starts from. **Soundness rule:** only a deterministic, NAT-free
"not delivered" answer ever downgrades a finding. NAT on the path, an error from
the forwarding model, or an unknown device all **fail closed** and the violation
is kept (see `rulehawk/pathground.py`). So does a degraded model: from
Hammerhead 0.2.2, when Hammerhead could not read part of the snapshot it still
answers but exits 3, and RuleHawk keeps the violation and names the unread lines
and devices in it.

When `DEVICE` is a Cisco ASA, Hammerhead decides the witness by the interface
the packet arrives on (interface security levels), so a host-sourced probe with
no received interface is Unknown and the violation is kept. Name that interface
with `--hh-ingress NAME` (the ASA `nameif`, e.g. `inside`); RuleHawk passes it as
`hammerhead traceroute --ingress NAME` and never picks one itself.

The MCP server does not expose these flags.
