"""The checker's own readers, one per dialect: from the split lines to the
record's model shape (`objects`, each a `path`, `values` and `ordered`
list). Written apart from the engine's grammars: anything a reader does not
know makes the whole reading None."""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

Path = Tuple[str, ...]


class _Off(Exception):
    """The reader met something it does not read."""


class _Objects:
    def __init__(self) -> None:
        self.objs: Dict[Path, dict] = {}

    def make(self, path: Path, fresh: bool = False) -> dict:
        for i in range(1, len(path)):
            self.objs.setdefault(path[:i], {"values": {}, "ordered": []})
        if path in self.objs:
            if fresh:
                raise _Off("written twice: " + "/".join(path))
            return self.objs[path]
        o = self.objs[path] = {"values": {}, "ordered": []}
        return o

    def set(self, path: Path, key: str, value: str) -> None:
        o = self.make(path)
        if key in o["values"]:
            raise _Off("set twice: " + key)
        o["values"][key] = value

    def flat(self) -> Dict[Path, Tuple[dict, list]]:
        return {p: (o["values"], o["ordered"]) for p, o in self.objs.items()}


def _net(text: str) -> str:
    """A network written with no host bits, else off."""
    try:
        n = ipaddress.IPv4Network(text, strict=True)
    except ValueError:
        raise _Off("not a network: " + text)
    if str(n) != text:
        raise _Off("not canonical: " + text)
    return text


def _addr(text: str) -> str:
    try:
        i = ipaddress.IPv4Interface(text)
    except ValueError:
        raise _Off("not an address: " + text)
    if str(i) != text or "/" not in text:
        raise _Off("not canonical: " + text)
    return text


# --------------------------------------------------------------------- Junos

def _words(lines: List[str]) -> List[str]:
    out: List[str] = []
    for ln in lines:
        for w in ln.split(" "):
            if not w:
                continue
            if w in ("{", "}"):
                out.append(w)
            elif w.endswith(";") and len(w) > 1:
                out += [w[:-1], ";"]
            else:
                out.append(w)
    for w in out:
        if w not in ("{", "}", ";") and any(c in w for c in '{};#"\'/*') \
                and not _slashed(w):
            raise _Off("token: " + w)
    return out


def _slashed(w: str) -> bool:
    """An interface name or a prefix may hold `/`; nothing else may."""
    return "/" in w and not w.startswith("/") and "*" not in w and "#" not in w \
        and not any(c in w for c in '{};"\'')


def _block(ws: List[str], i: int) -> Tuple[list, int]:
    """Statements up to the matching `}` (or the end at depth 0)."""
    out = []
    while i < len(ws) and ws[i] != "}":
        head: List[str] = []
        while i < len(ws) and ws[i] not in ("{", ";", "}"):
            head.append(ws[i])
            i += 1
        if i >= len(ws) or ws[i] == "}" or not head:
            raise _Off("statement without an end")
        if ws[i] == ";":
            out.append((head, None))
            i += 1
        else:
            kids, i = _block(ws, i + 1)
            if i >= len(ws):
                raise _Off("unclosed block")
            out.append((head, kids))
            i += 1
    return out, i


def _junos(lines: List[str]) -> Dict[Path, Tuple[dict, list]]:
    ws = _words(lines)
    tree, i = _block(ws, 0)
    if i != len(ws):
        raise _Off("stray close")
    objs = _Objects()
    for head, kids in tree:
        if kids is None:
            raise _Off("top-level leaf")
        if head == ["interfaces"]:
            objs.make(("interfaces",), fresh=True)
            _ifaces(objs, kids)
        elif head == ["firewall"]:
            objs.make(("firewall",), fresh=True)
            _firewall(objs, kids)
        else:
            raise _Off("top: " + " ".join(head))
    return objs.flat()


def _ifaces(objs: _Objects, kids) -> None:
    for head, sub in kids:
        if len(head) != 1 or sub is None:
            raise _Off("interface")
        ifd = ("interfaces", head[0])
        objs.make(ifd, fresh=True)
        for h2, s2 in sub:
            if len(h2) != 2 or h2[0] != "unit" or s2 is None or not h2[1].isdigit():
                raise _Off("unit")
            ifl = ifd + ("unit " + h2[1],)
            objs.make(ifl, fresh=True)
            for h3, s3 in s2:
                if h3 != ["family", "inet"] or s3 is None:
                    raise _Off("family")
                fam = ifl + ("family inet",)
                objs.make(fam, fresh=True)
                for h4, s4 in s3:
                    if len(h4) == 2 and h4[0] == "address" and s4 is None:
                        objs.set(fam, "address", _addr(h4[1]))
                    elif h4 == ["filter"] and s4 is not None:
                        flt = fam + ("filter",)
                        objs.make(flt, fresh=True)
                        for h5, s5 in s4:
                            if len(h5) != 2 or h5[0] != "input" or s5 is not None:
                                raise _Off("binding")
                            objs.set(flt, "input", h5[1])
                    else:
                        raise _Off("inet: " + " ".join(h4))


def _firewall(objs: _Objects, kids) -> None:
    for head, sub in kids:
        if head != ["family", "inet"] or sub is None:
            raise _Off("firewall family")
        fam = ("firewall", "family inet")
        objs.make(fam, fresh=True)
        for h2, s2 in sub:
            if len(h2) != 2 or h2[0] != "filter" or s2 is None:
                raise _Off("filter")
            flt = fam + ("filter " + h2[1],)
            objs.make(flt, fresh=True)
            for h3, s3 in s2:
                if len(h3) != 2 or h3[0] != "term" or s3 is None:
                    raise _Off("term")
                term = flt + ("term " + h3[1],)
                objs.make(term, fresh=True)
                objs.objs[flt]["ordered"].append(term[-1])
                for h4, s4 in s3:
                    if h4 == ["from"] and s4 is not None:
                        frm = term + ("from",)
                        objs.make(frm, fresh=True)
                        for h5, s5 in s4:
                            if len(h5) != 1 or h5[0] not in (
                                    "source-address", "destination-address") or s5 is None:
                                raise _Off("match")
                            m = frm + (h5[0],)
                            objs.make(m, fresh=True)
                            for h6, s6 in s5:
                                if len(h6) != 1 or s6 is not None:
                                    raise _Off("address list")
                                objs.make(m + (_net(h6[0]),), fresh=True)
                    elif len(h4) == 2 and h4[0] == "then" and h4[1] in (
                            "accept", "discard") and s4 is None:
                        objs.set(term, "then", h4[1])
                    else:
                        raise _Off("term body: " + " ".join(h4))


# --------------------------------------------------------------------- PAN-OS

_RULE_KEYS = ("from", "to", "source", "destination", "application", "service", "action")


def _panos(lines: List[str]) -> Dict[Path, Tuple[dict, list]]:
    objs = _Objects()
    base = ("rulebase security",)
    objs.make(base)
    for ln in lines:
        w = ln.split(" ")
        if w[:4] != ["set", "rulebase", "security", "rules"] or len(w) != 5 + 2 * len(_RULE_KEYS):
            raise _Off("not a whole rule")
        rule = base + ("rules " + w[4],)
        objs.make(rule, fresh=True)
        objs.objs[base]["ordered"].append(rule[-1])
        pairs = list(zip(w[5::2], w[6::2]))
        if sorted(k for k, _ in pairs) != sorted(_RULE_KEYS):
            raise _Off("rule keys")
        for k, v in pairs:
            if k in ("source", "destination") and v != "any":
                v = _net(v)
            elif k in ("from", "to", "application", "service") and v != "any":
                raise _Off(k)
            elif k == "action" and v not in ("allow", "deny"):
                raise _Off("action")
            objs.set(rule, k, v)
    return objs.flat()


# --------------------------------------------------------------------- iptables

_CHAINS = ("INPUT", "FORWARD", "OUTPUT")
_TARGETS = ("ACCEPT", "DROP")


def _iptables(lines: List[str]) -> Dict[Path, Tuple[dict, list]]:
    objs = _Objects()
    for ln in lines:
        w = ln.split(" ")
        if len(w) < 4 or w[0] != "iptables" or w[2] not in _CHAINS:
            raise _Off("command")
        chain = ("filter", w[2])
        if w[1] == "-P" and len(w) == 4 and w[3] in _TARGETS:
            objs.set(chain, "policy", w[3])
        elif w[1] == "-A" and len(w) % 2 == 1 and w[-2] == "-j" and w[-1] in _TARGETS:
            opts = list(zip(w[3:-2:2], w[4:-2:2]))
            if [k for k, _ in opts] not in ([], ["-s"], ["-d"], ["-s", "-d"]):
                raise _Off("options")
            for _, v in opts:
                _net(v)
            key = " ".join(w[3:])
            objs.make(chain + (key,), fresh=True)
            objs.objs[chain]["ordered"].append(key)
        else:
            raise _Off("command")
    return objs.flat()


READERS = {"junos": _junos, "panos": _panos, "iptables": _iptables}


def derive(dialect: str, lines: List[str]) -> Optional[Dict[Path, Tuple[dict, list]]]:
    """The model the checker reads, as {path: (values, ordered)}, or None."""
    reader = READERS.get(dialect)
    if reader is None:
        return None
    try:
        return reader(lines)
    except _Off:
        return None
