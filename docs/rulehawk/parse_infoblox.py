"""Parse Infoblox / ISC BIND named.conf DNS client access-control lists into
`ACE`s — the DNS **client access-control (reach-the-resolver) layer only**.

SCOPE (read this first). This frontend answers ONE question a packet auditor can
answer: **which client networks may query / transfer from the DNS service on
port 53?** Infoblox NIOS runs ISC BIND under the hood, and BIND governs client
reachability with ORDERED address-match-lists (`allow-query`, `allow-recursion`,
`allow-transfer`, `allow-query-cache`, and a per-`view` `match-clients`). Those
lists ARE an L3/L4 packet-filter over (client-address -> resolver:53), so they
map directly onto RuleHawk's ordered first-match `permit`/`deny` model and the
existing `analyze`/`segcheck` engine consumes the `(List[ACE], notes)` IR
unchanged. RPZ / response-policy zones and any other domain-content / name-based
filtering are a DNS-LAYER concern (they filter by queried NAME, not by client
packet) and are explicitly OUT OF SCOPE for a packet auditor — this module never
models them.

THE ADDRESS-MATCH-LIST -> ORDERED FIRST-MATCH MAPPING. BIND evaluates an
address-match-list top-to-bottom, first match wins, and a leading `!` on an
entry means "explicitly do NOT match here" (an ordered deny). This is EXACTLY
RuleHawk's first-match semantics, so each access statement becomes one ordered
ACL context (`acl` = f"{view or 'global'}:{statement}", e.g. "internal:allow-
query" — each statement is an independent first-match list):
  * a plain member          -> `permit`   at that position
  * a `!member` (negated)    -> `deny`     at that position
  * BIND's default (nothing matched) -> deny  (segcheck's implicit per-context
    default-deny, also emitted explicitly as a trailing `deny ip any any`).

WHY NEGATED MEMBERS ARE MODELED EXACTLY (not imprecise). Elsewhere in RuleHawk a
negated match is a set-complement that isn't one rectangle, so it is
over-approximated + flagged imprecise. Here it is DIFFERENT: a BIND match-list is
ORDERED first-match, so `!10.20.99.0/24;` BEFORE `10.20.0.0/16;` is precisely "at
this position, deny the /24" followed by "permit the rest of the /16". A `deny`
ACE for the excluded CIDR placed at the member's position reproduces that
exactly — first-match precedence does the set subtraction for us. So negated
plain CIDR/IP members are EXACT, never imprecise.

THE PACKET (soundly over-approximated). The modeled packet is a DNS query FROM
the client TO the resolver on 53:
  * src  = the client CIDR(s) from the match-list (exact for CIDR/IP members);
  * dst  = ANY — the resolver's own address is not in this config, and ANY is a
           SUPERSET of the true destination, so it stays sound;
  * proto/port = BOTH udp/53 AND tcp/53 (DNS uses both), i.e. two ACEs per
           member — so "can zone X reach the DNS resolver on 53?" is answerable
           for either transport.

BUILTINS / UNRESOLVABLES (superset invariant — widen, mark imprecise, surface):
  * `any`       -> 0.0.0.0/0 and ::/0 (exact).
  * `none`      -> matches nothing: a no-op member (emits no ACE). BIND's default
                   deny (the trailing `deny ip any any`) then denies everyone, so
                   `allow-transfer { none; }` is a context that denies all clients.
  * `localhost` / `localnets` -> BIND resolves these from the host's OWN /
                   ATTACHED interface addresses, which are UNKNOWN from config.
                   Modeling loopback only would be a SUBSET of the real match and
                   could FALSE-PASS an isolation assertion, so both widen to ANY +
                   `imprecise` + a note (fail-closed => segcheck yields
                   indeterminate, never a wrong PASS).
  * a nested `acl` reference -> inline-expanded (in order) at its position.
  * an undefined / cyclic acl reference -> widen to ANY + `imprecise` + note
                   (fail closed; never silently dropped).

ROBUSTNESS. Unbalanced / truncated braces, unknown statements, and all non-ACL
BIND config (zones, keys, logging, options unrelated to access) degrade with a
note or are ignored — never a crash, never a silent hole.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .model import ACE, ANY_PORTS, PortRange, _IPNet

_ANY4: _IPNet = ipaddress.ip_network("0.0.0.0/0")
_ANY6: _IPNet = ipaddress.ip_network("::/0")
_DNS_PORT = 53
_DNS_PR = PortRange(_DNS_PORT, _DNS_PORT)

# The BIND access statements this frontend models as reach-the-resolver ACLs.
# Each becomes its own ordered first-match context. `match-clients` is a view's
# client selector; the rest are the query/transfer access controls.
_ACCESS_STMTS = frozenset({
    "allow-query", "allow-recursion", "allow-transfer",
    "allow-query-cache", "match-clients",
})


class _Tok:
    """One lexical token with its 1-based source line."""

    __slots__ = ("text", "line")

    def __init__(self, text: str, line: int) -> None:
        self.text = text
        self.line = line


def detect(text: str) -> bool:
    """Heuristic: does `text` look like a BIND/Infoblox named.conf DNS ACL?

    True when it contains a BIND-specific DNS-ACL marker, line-anchored so it
    never collides with the other vendors RuleHawk parses:
      * an `acl "NAME" { ... }` (or unquoted `acl NAME { ... }`) block, or
      * an `allow-query` / `allow-recursion` / `allow-transfer` /
        `allow-query-cache` / `match-clients` statement introducing an inline
        `{ ... }` address-match-list.
    Cisco (`ip access-list`/`permit`), iptables (`-A`/`-j`/`*filter`), Fortinet
    (`config firewall`), Junos, and JSON carry none of these tokens at
    start-of-line, so they are never misrouted here. (This also correctly
    detects plain ISC BIND named.conf, which uses the same syntax.)
    """
    if re.search(r'(?m)^\s*acl\s+(?:"[^"]*"|[\w.\-]+)\s*\{', text):
        return True
    # A DNS access statement introducing an inline `{ ... }` list. The keyword
    # must be a BARE word — preceded by start-of-input, whitespace, `{`, or `;`
    # and followed only by whitespace then `{`. That excludes a JSON key
    # `"allow-query": {` (preceded by `"`, and the `:` breaks `\s*\{`).
    if re.search(r'(?:(?<=[\s{;])|^)(?:allow-query|allow-recursion|'
                 r'allow-transfer|allow-query-cache|match-clients)\s*\{', text):
        return True
    return False


def _strip_comments(text: str) -> str:
    """Replace BIND comment spans (`/* */`, `//`, `#`) with spaces, preserving
    every newline so token line numbers stay exact. Quoted strings are honored
    so a `//`/`#` inside a `"..."` name is not mistaken for a comment."""
    out: List[str] = []
    i, n = 0, len(text)
    state = "normal"          # normal | string | line | block
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "normal":
            if c == '"':
                out.append(c); state = "string"; i += 1
            elif c == "/" and nxt == "/":
                out.append("  "); state = "line"; i += 2
            elif c == "#":
                out.append(" "); state = "line"; i += 1
            elif c == "/" and nxt == "*":
                out.append("  "); state = "block"; i += 2
            else:
                out.append(c); i += 1
        elif state == "string":
            out.append(c)
            if c == '"':
                state = "normal"
            i += 1
        elif state == "line":
            if c == "\n":
                out.append("\n"); state = "normal"
            else:
                out.append(" ")
            i += 1
        else:  # block
            if c == "*" and nxt == "/":
                out.append("  "); state = "normal"; i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
    return "".join(out)


def _tokenize(text: str) -> List[_Tok]:
    """Split into tokens: the single-char structurals `{ } ; !`, quoted strings
    (quotes stripped), and barewords (CIDRs, IPs, names, keywords). A `!` glued
    to a value (`!10.20.99.0/24`) is emitted as its own token."""
    toks: List[_Tok] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c.isspace():
            i += 1; continue
        if c in "{};!":
            toks.append(_Tok(c, line)); i += 1; continue
        if c == '"':
            j = i + 1
            buf: List[str] = []
            while j < n and text[j] != '"':
                if text[j] == "\n":
                    line += 1
                buf.append(text[j]); j += 1
            toks.append(_Tok("".join(buf), line))
            i = j + 1 if j < n else j
            continue
        j = i
        buf = []
        while j < n and not text[j].isspace() and text[j] not in '{};!"':
            buf.append(text[j]); j += 1
        toks.append(_Tok("".join(buf), line))
        i = j
    return toks


def _collect_block(toks: List[_Tok], j: int) -> Tuple[List[_Tok], int, bool]:
    """`toks[j]` is `{`. Return (inner tokens, index after the matching `}`,
    truncated?). A missing close brace returns everything to EOF + truncated=True
    (fail-open on the read, surfaced by the caller — never a crash)."""
    depth, k = 0, j
    n = len(toks)
    while k < n:
        t = toks[k].text
        if t == "{":
            depth += 1
        elif t == "}":
            depth -= 1
            if depth == 0:
                return toks[j + 1:k], k + 1, False
        k += 1
    return toks[j + 1:], n, True


def _iter_constructs(toks: List[_Tok], notes: List[str]):
    """Yield each `<kw> [name ...] { ... }` block construct as
    (kw_lower, name_parts, inner_tokens, kw_line). Non-block `<kw> ...;`
    statements are skipped. Used both at top level and inside options/view."""
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.text in ("{", "}", ";"):
            i += 1
            continue
        kw = t.text.lower()
        kw_line = t.line
        j = i + 1
        name_parts: List[str] = []
        while j < n and toks[j].text not in ("{", ";"):
            name_parts.append(toks[j].text)
            j += 1
        if j < n and toks[j].text == "{":
            inner, after, trunc = _collect_block(toks, j)
            if trunc:
                notes.append(f"truncated/unbalanced `{{` in `{kw}` block — parsed "
                             f"to end of input (verify the config is complete)")
            if after < n and toks[after].text == ";":
                after += 1
            yield (kw, name_parts, inner, kw_line)
            i = after
        else:
            # Non-block statement `<kw> ... ;` (or truncated) — nothing to model.
            i = j + 1 if j < n else j


def _try_net(tok: str) -> Optional[_IPNet]:
    """A CIDR (`10.20.0.0/16`), or a bare IP widened to its host route
    (`10.50.0.0` -> /32, `2001:db8::1` -> /128). None if not an address."""
    try:
        if "/" in tok:
            return ipaddress.ip_network(tok, strict=False)
        addr = ipaddress.ip_address(tok)
        return ipaddress.ip_network(f"{tok}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return None


# An atom = (action, nets, imprecise, line): the ordered contribution of one
# resolved match-list member. `nets` is the list of source networks (one, or v4
# + v6 for ANY-valued members). Emitted later as udp/53 + tcp/53 ACE pairs.
_Atom = Tuple[str, List[_IPNet], bool, int]


def _resolve_value(tok: _Tok, negate: bool, acls: Dict[str, List[_Tok]],
                   notes: List[str], ctx: str, stack: List[str]) -> List[_Atom]:
    """Resolve one member value (with its leading-`!` state) into ordered atoms.

    A plain CIDR/IP -> one exact permit/deny. `any` -> all addresses (exact).
    `none` -> no-op (matches nothing). `localhost`/`localnets` and undefined or
    cyclic acl references -> widen to ANY + imprecise (fail closed). A defined
    acl reference -> inline-expand its members in order at this position."""
    v = tok.text
    lv = v.lower()
    action = "deny" if negate else "permit"

    if lv == "none":
        # Matches nothing: BIND continues evaluation, so it contributes no ACE.
        # (An all-`none` list then denies everyone via the default deny.)
        return []
    if lv == "any":
        return [(action, [_ANY4, _ANY6], False, tok.line)]
    if lv in ("localhost", "localnets"):
        notes.append(
            f"BIND builtin `{lv}` in {ctx} is interface-derived (the host's own / "
            f"attached interface addresses, unknown from this config) — widened to "
            f"ANY and marked imprecise (fail-closed; verify manually)")
        return [(action, [_ANY4, _ANY6], True, tok.line)]

    net = _try_net(v)
    if net is not None:
        return [(action, [net], False, tok.line)]

    # A name -> acl reference.
    if v in acls:
        if v in stack:
            notes.append(f"cyclic acl reference `{v}` in {ctx} — widened to ANY "
                         f"(imprecise; fail-closed, verify manually)")
            return [(action, [_ANY4, _ANY6], True, tok.line)]
        if negate:
            # Negating a whole (possibly ordered/mixed) acl is not one rectangle
            # under first-match — fail closed rather than risk an over-wide deny.
            notes.append(f"negated acl reference `!{v}` in {ctx} — a negated "
                         f"match-list is not one rectangle; widened to ANY "
                         f"(imprecise; verify manually)")
            return [("deny", [_ANY4, _ANY6], True, tok.line)]
        return _resolve_matchlist(acls[v], acls, notes, ctx, stack + [v])

    notes.append(f"undefined acl/reference `{v}` in {ctx} — widened to ANY "
                 f"(imprecise; fail-closed, verify manually)")
    return [(action, [_ANY4, _ANY6], True, tok.line)]


def _resolve_matchlist(inner: List[_Tok], acls: Dict[str, List[_Tok]],
                       notes: List[str], ctx: str,
                       stack: List[str]) -> List[_Atom]:
    """Resolve an address-match-list's inner tokens into ordered atoms."""
    atoms: List[_Atom] = []
    negate = False
    i, n = 0, len(inner)
    while i < n:
        tok = inner[i]
        txt = tok.text
        if txt == ";":
            negate = False
            i += 1
            continue
        if txt == "!":
            negate = not negate
            i += 1
            continue
        if txt == "{":
            block_inner, after, trunc = _collect_block(inner, i)
            if trunc:
                notes.append(f"truncated nested address-match-list in {ctx} "
                             f"(verify the config is complete)")
            if negate:
                notes.append(f"negated nested address-match-list in {ctx} — not one "
                             f"rectangle; widened to ANY (imprecise; verify)")
                atoms.append(("deny", [_ANY4, _ANY6], True, tok.line))
            else:
                atoms.extend(_resolve_matchlist(block_inner, acls, notes, ctx, stack))
            negate = False
            i = after
            continue
        if txt == "}":
            i += 1
            continue
        atoms.extend(_resolve_value(tok, negate, acls, notes, ctx, stack))
        negate = False
        i += 1
    return atoms


def _atoms_to_aces(atoms: List[_Atom], label: str, stmt_line: int) -> List[ACE]:
    """Expand ordered atoms into a context's ACEs: two per source net (udp/53
    and tcp/53), plus a trailing explicit BIND default-deny for both families."""
    aces: List[ACE] = []
    seq = 0
    for action, nets, imprecise, line in atoms:
        for net in nets:
            fam_any = _ANY6 if net.version == 6 else _ANY4
            for proto in ("udp", "tcp"):
                seq += 1
                aces.append(ACE(
                    seq=seq, action=action, proto=proto, src=net, dst=fam_any,
                    src_port=ANY_PORTS, dst_port=_DNS_PR, imprecise=imprecise,
                    raw=f"{label}: {action} {proto}/{_DNS_PORT} from {net} "
                        f"(reach DNS resolver)",
                    acl=label, line=line, transit=True))
    # BIND's default is deny-if-unmatched. Emit it explicitly for both families
    # so the context is a concrete "deny everyone else" (segcheck also applies an
    # implicit per-context default-deny, so this changes no verdict — it makes a
    # `none`/empty context concretely deny-all, e.g. `allow-transfer { none; }`).
    for fam_any in (_ANY4, _ANY6):
        seq += 1
        aces.append(ACE(
            seq=seq, action="deny", proto="ip", src=fam_any, dst=fam_any,
            src_port=ANY_PORTS, dst_port=ANY_PORTS, imprecise=False,
            raw=f"{label}: implicit default deny (BIND deny-if-unmatched)",
            acl=label, line=stmt_line, transit=True))
    return aces


def _scan_statements(inner: List[_Tok], label: str, acls: Dict[str, List[_Tok]],
                     notes: List[str]) -> List[ACE]:
    """Find the access statements inside an options/view body and emit one
    ordered ACL context per statement. Non-access statements are ignored."""
    out: List[ACE] = []
    for kw, _name, blk, line in _iter_constructs(inner, notes):
        if kw in _ACCESS_STMTS:
            ctx = f"{label}:{kw}"
            atoms = _resolve_matchlist(blk, acls, notes, ctx, [])
            out.extend(_atoms_to_aces(atoms, ctx, line))
    return out


def parse_infoblox(text: str) -> Tuple[List[ACE], List[str]]:
    """Parse Infoblox/BIND named.conf DNS client ACLs; return (entries, notes).

    Same `(List[ACE], notes)` contract as `parse.parse_acls`, so `analyze` /
    `check_segmentation` consume the result unchanged. Each modeled access
    statement becomes an independent first-match context named
    f"{view or 'global'}:{statement}".
    """
    notes: List[str] = []
    try:
        toks = _tokenize(_strip_comments(text))
        constructs = list(_iter_constructs(toks, notes))

        # Pass 1: collect every acl definition (forward references allowed).
        acls: Dict[str, List[_Tok]] = {}
        for kw, name_parts, inner, _line in constructs:
            if kw == "acl":
                if not name_parts:
                    notes.append("acl block without a name — skipped (verify)")
                    continue
                acls[name_parts[0]] = inner

        # Pass 2: emit ACL contexts for options / view / top-level statements.
        entries: List[ACE] = []
        ignored: set = set()
        for kw, name_parts, inner, line in constructs:
            if kw == "acl":
                continue
            if kw == "options":
                entries.extend(_scan_statements(inner, "global", acls, notes))
            elif kw == "view":
                vname = name_parts[0] if name_parts else "view"
                entries.extend(_scan_statements(inner, vname, acls, notes))
            elif kw in _ACCESS_STMTS:
                ctx = f"global:{kw}"
                atoms = _resolve_matchlist(inner, acls, notes, ctx, [])
                entries.extend(_atoms_to_aces(atoms, ctx, line))
            else:
                ignored.add(kw)
    except Exception as exc:  # never crash the audit on a malformed config
        notes.append(f"parse aborted on malformed BIND config ({type(exc).__name__}: "
                     f"{exc}) — output may be incomplete (verify manually)")
        return [], notes

    if ignored:
        notes.append("ignored non-ACL BIND config block(s): "
                     + ", ".join(sorted(ignored))
                     + " (only DNS client access-control lists are modeled).")
    if not entries:
        notes.append("no BIND/Infoblox DNS client access-control statements found "
                     "(only allow-query/allow-recursion/allow-transfer/"
                     "allow-query-cache/match-clients are modeled).")
    return entries, notes
