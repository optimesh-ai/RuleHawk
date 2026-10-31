"""Differential test: RuleHawk's vendor ACL frontends vs Batfish.

    python -m tools.oracle.bf_diff --random 40 --vendors ios,asa,eos,nxos,junos
    python -m tools.oracle.bf_diff --files ios:path/a.cfg junos:path/b.conf ...

Needs a Batfish service (`docker run -p 9996:9996 batfish/allinone`) and
pybatfish. Per config:
  (dead) every line RuleHawk proves dead (all of its ACEs dead/redundant) must
         be in Batfish's filterLineReachability "unreachable" set; Batfish
         unreachable lines RuleHawk does not flag are counted as misses;
  (ii)   boundary + random packets through testFilters vs RuleHawk's first
         match (RuleHawk "unknown" when its first match is imprecise);
  (i)    every must_not_reach witness RuleHawk emits (auto-built policy) must
         be PERMITTED by Batfish on the cited line.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import sys
import tempfile
from typing import Dict, List

from rulehawk.analyze import analyze
from rulehawk.gate import _pick_parser
from rulehawk.segcheck import check_segmentation

from . import gen_acl
from .iptables_diff import _DEAD, _witness_pkt, auto_policy
from .packets import sample, usable
from .rhsim import Pkt, by_acl, verdict

_BF_PROTO = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "gre": "GRE"}


def _norm(line: str) -> str:
    s = re.sub(r"\s+", " ", (line or "").strip())
    s = re.sub(r"^(?:\d+|sequence \d+) ", "", s)                 # EOS/NX-OS/IOS seq
    s = re.sub(r"^access-list \S+ (?:line \d+ )?(?:extended )?", "", s)  # ASA prefix
    return s.lower()


def _hc(p: Pkt):
    from pybatfish.datamodel.flow import HeaderConstraints
    kw = dict(srcIps=p.src, dstIps=p.dst, ipProtocols=[_BF_PROTO[p.proto]])
    if p.proto in ("tcp", "udp"):
        kw.update(srcPorts=str(p.sport), dstPorts=str(p.dport))
    # testFilters defaults a TCP flow to a bare SYN: the connection-initiating
    # packet RuleHawk's model describes.
    if p.proto == "icmp":
        kw.update(icmpTypes=[p.icmp_type], icmpCodes=[p.icmp_code])
    return HeaderConstraints(**kw)


def _vendor_header(vendor: str, host: str, text: str) -> str:
    """One line that makes Batfish detect the vendor of a snippet that lacks
    its usual preamble (a bare `set firewall ...` file is UNKNOWN to Batfish;
    a bare ASA ACL is read as IOS, wildcard masks and all)."""
    if vendor == "asa" and not re.search(r"(?m)^\s*(?:ASA|PIX) Version", text):
        return "ASA Version 9.8(4)\n"
    if vendor.startswith("junos") and "host-name" not in text:
        return (f"set system host-name {host}\n" if re.search(r"(?m)^\s*set\s", text)
                else f"system {{ host-name {host}; }}\n")
    if vendor in ("ios", "eos", "nxos") and not re.search(r"(?m)^\s*hostname\s", text):
        return f"hostname {host}\n"
    return ""


def _snapshot(bf, items, tag):
    """Write one snapshot; return {host: line offset} (1 when a vendor header
    line was prepended, so Batfish line numbers are shifted by one)."""
    d = tempfile.mkdtemp(prefix=f"bf-{tag}-")
    os.makedirs(os.path.join(d, "configs"))
    offsets = {}
    for host, vendor, text in items:
        # Force Batfish's node name to the item name (real configs share
        # hostnames like "router1"); edits stay on the same line.
        text = re.sub(r"(?m)^(\s*hostname\s+)\S+", lambda m: m.group(1) + host, text)
        text = re.sub(r"(host-name\s+)[^;\s]+", lambda m: m.group(1) + host, text)
        hdr = _vendor_header(vendor, host, text)
        offsets[host] = 1 if hdr else 0
        with open(os.path.join(d, "configs", host + ".cfg"), "w") as fh:
            fh.write(hdr + text)
    bf.init_snapshot(d, name=tag, overwrite=True)
    return offsets


def run_batch(bf, items, rng, n_pkts=300, threads=4, witnesses=True):
    """items: [(host, vendor, text)] in ONE snapshot. Returns per-host results."""
    tag = f"s{rng.randrange(1 << 30)}"
    offsets = _snapshot(bf, items, tag)
    issues = bf.q.initIssues().answer().frame()
    res: Dict[str, dict] = {}
    rh = {}
    all_aces = []
    for host, vendor, text in items:
        _, fn = _pick_parser(text, "junos" if vendor.startswith("junos") else vendor)
        aces, notes = fn(text)
        acls = by_acl([a for a in aces if a.src.version == 4 and a.dst.version == 4])
        rh[host] = (aces, acls)
        all_aces += [a for a in aces if a.src.version == 4 and a.dst.version == 4]
        res[host] = {"vendor": vendor, "rh_rules": len(aces), "cmp": 0, "agree": 0,
                     "unknown": 0, "disagree": [], "unmatched_acls": [],
                     "dead_lines": 0, "dead_confirmed": 0, "dead_refuted": [],
                     "bf_unreachable": 0, "rh_missed": [], "witness": 0,
                     "witness_ok": 0, "witness_bad": [], "attr_mismatch": 0,
                     "bf_issues": [], "rh_notes": len(notes), "flr_failed": 0,
                     "dead_unverifiable": 0, "disagree_bf_partial": [],
                     "dead_refuted_bf_partial": [], "witness_bad_bf_partial": [],
                     "bf_partial_acls": []}
    lc = {h.lower(): h for h in res}
    unparsed = {h: set() for h in res}          # source lines Batfish dropped
    for _, row in issues.iterrows():
        # Parse warnings carry no Nodes, only Source_Lines (file + lines):
        # map configs/<host>.cfg back to the host.
        hosts = {lc[n.lower()] for n in (row.get("Nodes") or []) if n.lower() in lc}
        flines = list(row.get("Source_Lines") or [])
        for fl in flines:
            stem = os.path.splitext(os.path.basename(str(getattr(fl, "filename", ""))))[0]
            if stem.lower() in lc:
                hosts.add(lc[stem.lower()])
        for h in hosts:
            res[h]["bf_issues"].append(f"{row['Type']}: {row.get('Line_Text') or row['Details']}"[:200])
            if "parse" in str(row["Type"]).lower():
                for fl in flines:
                    stem = os.path.splitext(os.path.basename(str(getattr(fl, "filename", ""))))[0]
                    if stem.lower() == h.lower():
                        for ln in (getattr(fl, "lines", None) or []):
                            unparsed[h].add(int(ln) - offsets.get(h, 0))
    # ---- dead lines vs filterLineReachability
    unreach = {}
    try:
        flr_frames = [bf.q.filterLineReachability().answer().frame()]
    except Exception:   # noqa: BLE001  one config can crash Batfish's question
        flr_frames = []
        for host, _v, _t in items:
            try:
                flr_frames.append(bf.q.filterLineReachability(nodes=host).answer().frame())
            except Exception as e:   # noqa: BLE001
                res[host]["bf_issues"].append(f"filterLineReachability failed: {str(e)[-160:]}")
                res[host]["flr_failed"] = 1
    rows = [row for fr in flr_frames for _, row in fr.iterrows()]
    for row in rows:
        for src in row["Sources"]:
            host, _, acl = src.partition(": ")
            unreach.setdefault((host.lower(), acl), set()).add(_norm(row["Unreachable_Line"]))
    for host, (aces, acls) in rh.items():
        if res[host].get("flr_failed"):
            continue
        findings = analyze(aces)
        dead_ids = {f.rule_id for f in findings if f.kind in _DEAD}
        by_line = {}
        for a in aces:
            by_line.setdefault((a.acl, a.line), []).append(a)
        for (acl, line), group in by_line.items():
            if not line or not all(f"{a.acl}:{a.seq}" in dead_ids for a in group):
                continue
            res[host]["dead_lines"] += 1
            text_line = _norm(_src_line(items, host, line))
            u = unreach.get((host.lower(), acl), set())
            if _line_in(text_line, u):
                res[host]["dead_confirmed"] += 1
            else:
                res[host]["dead_refuted"].append({"acl": acl, "line": line,
                                                  "text": text_line})
        for (h, acl), lines in unreach.items():
            if h != host.lower():
                continue
            res[host]["bf_unreachable"] += len(lines)
            rh_dead_text = {_norm(_src_line(items, host, a.line)) for a in aces
                            if a.acl == acl and f"{a.acl}:{a.seq}" in dead_ids}
            for ln in lines:
                if not _line_in(ln, rh_dead_text):
                    res[host]["rh_missed"].append({"acl": acl, "line": ln})
    # ---- packets vs testFilters
    pkts = [p for p in sample(all_aces, rng, per_ace=3, n_random=60)
            if usable(p.src) and usable(p.dst) and p.proto in _BF_PROTO
            and not (p.proto in ("tcp", "udp") and (p.sport == 0 or p.dport == 0))]
    rng.shuffle(pkts)
    pkts = pkts[:n_pkts]

    def ask(p):
        try:
            return p, bf.q.testFilters(headers=_hc(p)).answer().frame()
        except Exception:   # noqa: BLE001  Batfish refuses some flows
            return p, None

    with cf.ThreadPoolExecutor(threads) as ex:
        answers = list(ex.map(ask, pkts))
    for p, fr in answers:
        if fr is None:
            continue
        rows = {(str(r["Node"]).lower(), r["Filter_Name"]): r for _, r in fr.iterrows()}
        for host, (aces, acls) in rh.items():
            for acl, acl_aces in acls.items():
                r = rows.get((host.lower(), acl))
                if r is None:
                    if acl not in res[host]["unmatched_acls"]:
                        res[host]["unmatched_acls"].append(acl)
                    continue
                rv, ace = verdict(acl_aces, p)
                if rv == "unknown":
                    res[host]["unknown"] += 1
                    continue
                res[host]["cmp"] += 1
                bv = "permit" if r["Action"] == "PERMIT" else "deny"
                if rv == bv:
                    res[host]["agree"] += 1
                    if ace is not None and r["Line_Content"] and not _line_in(
                            _norm(r["Line_Content"]), {_norm(_src_line(items, host, ace.line))}):
                        res[host]["attr_mismatch"] += 1
                else:
                    res[host]["disagree"].append({
                        "acl": acl, "pkt": str(p), "batfish": bv, "bf_line": r["Line_Content"],
                        "rulehawk": rv, "rh_line": _src_line(items, host, ace.line) if ace else "(implicit deny)"})
    # Batfish dropped (parse warning) at least one line of this ACL: its view
    # of the ACL is partial, so a discrepancy there is an oracle limit, not a
    # RuleHawk bug. Kept apart, per kind.
    for host, (aces, acls) in rh.items():
        r = res[host]
        partial = {acl for acl, aa in acls.items() if {a.line for a in aa} & unparsed[host]}
        for kind in ("disagree", "dead_refuted"):
            keep = []
            for x in r[kind]:
                (r[kind + "_bf_partial"].append(x) if x["acl"] in partial else keep.append(x))
            r[kind] = keep
        r["bf_partial_acls"] = sorted(partial)
    # A dead claim in an ACL Batfish never answered for (it doesn't model it,
    # e.g. a QoS class ACL or one it failed to parse) is unverifiable, not
    # refuted.
    for host, r in res.items():
        keep = []
        for x in r["dead_refuted"]:
            if x["acl"] in r["unmatched_acls"]:
                r["dead_unverifiable"] += 1
                r["dead_lines"] -= 1
            else:
                keep.append(x)
        r["dead_refuted"] = keep
    # ---- witnesses
    if witnesses:
        wl = []
        for host, (aces, acls) in rh.items():
            pol = auto_policy([a for a in aces if a.transit])
            for f in check_segmentation(aces, pol):
                if f.kind == "segmentation-violation" and f.witness:
                    p = _witness_pkt(f.witness)
                    if p and usable(p.src) and usable(p.dst):
                        wl.append((host, f, p))
        rng.shuffle(wl)
        wl = wl[:80]
        with cf.ThreadPoolExecutor(threads) as ex:
            outs = list(ex.map(lambda t: (t, bf.q.testFilters(headers=_hc(t[2])).answer().frame()), wl))
        for (host, f, p), fr in outs:
            acl = f.rule_id.rsplit(":", 1)[0]
            row = [r for _, r in fr.iterrows() if str(r["Node"]).lower() == host.lower()
                   and r["Filter_Name"] == acl]
            res[host]["witness"] += 1
            ace_line = next((a.line for a in rh[host][0] if f"{a.acl}:{a.seq}" == f.rule_id), 0)
            ok = bool(row) and row[0]["Action"] == "PERMIT"
            if ok and ace_line:
                ok = _norm(row[0]["Line_Content"]) == _norm(_src_line(items, host, ace_line)) \
                    or _line_in(_norm(row[0]["Line_Content"]), {_norm(_src_line(items, host, ace_line))})
            if ok:
                res[host]["witness_ok"] += 1
            elif acl in res[host]["bf_partial_acls"]:
                res[host]["witness_bad_bf_partial"].append({"witness": f.witness, "rule": f.rule,
                                                            "bf_line": row[0]["Line_Content"] if row else None})
            else:
                res[host]["witness_bad"].append({"witness": f.witness, "rule": f.rule,
                                                 "bf": row[0]["Action"] if row else None,
                                                 "bf_line": row[0]["Line_Content"] if row else None})
    return res


def _line_in(line: str, pool) -> bool:
    """Batfish's line text vs the source line: exact after normalising, or one
    contains the other (Batfish shortens Junos terms to `term NAME` etc.)."""
    if line in pool:
        return True
    m = re.match(r"^term (\S+)", line)
    for p in pool:
        if m and (p == m.group(1) or p.startswith("term " + m.group(1))
                  or f" term {m.group(1)} " in f" {p} "):
            return True
        if p and (p in line or line in p):
            return True
    return False


def _src_line(items, host, line: int) -> str:
    for h, _v, text in items:
        if h == host:
            lines = text.splitlines()
            if 0 < line <= len(lines):
                ln = lines[line - 1].strip()
                m = re.match(r"^term (\S+) \{", ln)
                return f"term {m.group(1)}" if m else ln
    return ""


def totals(all_res):
    t = {}
    for r in all_res.values():
        for k, v in r.items():
            if isinstance(v, int):
                t[k] = t.get(k, 0) + v
            elif isinstance(v, list) and k in ("disagree", "dead_refuted", "rh_missed",
                                               "witness_bad", "unmatched_acls",
                                               "disagree_bf_partial", "dead_refuted_bf_partial",
                                               "witness_bad_bf_partial", "bf_partial_acls"):
                t[k] = t.get(k, 0) + len(v)
    t["configs"] = len(all_res)
    t["configs_with_bf_issues"] = sum(1 for r in all_res.values() if r["bf_issues"])
    return t


def build_items(n_random=0, seed=1, vendors="ios,asa,eos,nxos,junos", files=()):
    rng = random.Random(seed)
    items = []
    for i in range(n_random):
        rules = gen_acl.random_acl(rng)
        for v in vendors.split(","):
            h = f"r{seed}-{i}-{v}"
            items.append((h, v, gen_acl.render(rules, v, f"ACL{i}", h)))
    for n, spec in enumerate(files):
        v, _, path = spec.partition(":")
        host = f"c{n}-" + re.sub(r"[^A-Za-z0-9_-]", "_", os.path.basename(path))[:50]
        items.append((host, v, open(path, encoding="utf-8", errors="replace").read()))
    return items, rng


def main_run(n_random=0, seed=1, vendors="ios,asa,eos,nxos,junos", files=(),
             batch=20, pkts=300, host=None, log=sys.stderr, checkpoint=""):
    from pybatfish.client.session import Session
    bf = Session(host=host or os.environ.get("BATFISH_HOST", "localhost"))
    bf.set_network("rulehawk-oracle")
    items, rng = build_items(n_random, seed, vendors, files)
    all_res = {}
    for k in range(0, len(items), batch):
        all_res.update(run_batch(bf, items[k:k + batch], rng, n_pkts=pkts))
        print(f"batch {k // batch + 1}: {json.dumps(totals(all_res))}", file=log)
        if checkpoint:
            _dump(checkpoint, totals(all_res), all_res, items)
    return totals(all_res), all_res, items


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--random", type=int, default=0)
    ap.add_argument("--vendors", default="ios,asa,eos,nxos,junos")
    ap.add_argument("--files", nargs="*", default=[])
    ap.add_argument("--file-list", default="", help="file of vendor:path lines")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--batch", type=int, default=20)
    ap.add_argument("--pkts", type=int, default=300)
    ap.add_argument("--json", default="")
    a = ap.parse_args(argv)
    files = list(a.files)
    if a.file_list:
        files += [x.strip() for x in open(a.file_list) if x.strip()]
    t, all_res, items = main_run(a.random, a.seed, a.vendors, files, a.batch, a.pkts,
                                 checkpoint=a.json)
    print(json.dumps(t, indent=1))


def _dump(path, t, all_res, items):
    with open(path, "w") as fh:
        json.dump({"totals": t, "results": all_res,
                   "configs": {h: text for h, _, text in items}}, fh, indent=1)


if __name__ == "__main__":
    main()
