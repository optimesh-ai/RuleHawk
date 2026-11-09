"""#42 phase 2, slice 5: the final model and merge rules, in shadow (design
v2 section 2.1, v3 section 6.1, v4 sections 12 and 13).

Every production declares the write it makes: an attribute and a merge
rule. The final model is the fold of every write in text order. A second
write to the same (object, attribute) has no cited merge rule and gives
`write-merge-uncited`; no production declares `replace` or `delete`.
Ordered children (`append-in-order`: Junos terms, PAN-OS rules, iptables
`-A` rules) rest on a cited order row, or record the pending one: PAN-OS
rule order is not cited, so the PAN-OS model states no order it can rely
on.

The model goes only into the shadow block, beside `grammar`, for a file the
grammar parses. `would_pass` stays false.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rulehawk import gate as g  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_D = os.path.join(_ROOT, "tests", "fixtures", "fail_closed", "variants", "design")
_K00 = os.path.join(_D, "controls", "k00_base.conf")
_P00 = os.path.join(_D, "controls", "p00_base.set")
_I00 = os.path.join(_D, "controls", "i00_base.sh")

_RULES = {"create", "append-in-order", "error"}
_ORDER_ROWS = {"junos": "junos-term-order", "panos": "panos-rule-order",
               "iptables": "iptables-append"}


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _grammars():
    from rulehawk import grammar_iptables, grammar_junos, grammar_panos
    return {"junos": grammar_junos, "panos": grammar_panos, "iptables": grammar_iptables}


@pytest.fixture
def shadow(monkeypatch):
    monkeypatch.setenv("RULEHAWK_SHADOW", "1")


def _gate_shadow(path):
    d = json.loads(g.to_json(g.run_gate([path], None, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    return f.get("shadow")


def _obj(model, *path):
    (o,) = [o for o in model["objects"] if o["path"] == list(path)]
    return o


# ------------------------------------------------------------- the merge table

@pytest.mark.parametrize("dialect", ["junos", "panos", "iptables"])
def test_every_production_declares_its_write(dialect):
    gm = _grammars()[dialect]
    for p in gm.PRODUCTIONS:
        assert len(p.write) == 2, p
        attribute, rule = p.write
        assert attribute, p
        assert rule in _RULES, p


@pytest.mark.parametrize("dialect", ["junos", "panos", "iptables"])
def test_no_production_replaces_or_deletes(dialect):
    """No non-Cisco row cites `replace` or `delete` (v3 section 6.1)."""
    gm = _grammars()[dialect]
    assert not {p.write[1] for p in gm.PRODUCTIONS} & {"replace", "delete"}


@pytest.mark.parametrize("dialect", ["junos", "panos", "iptables"])
def test_an_ordered_write_rests_on_an_order_row(dialect):
    gm = _grammars()[dialect]
    ordered = [p for p in gm.PRODUCTIONS if p.write[1] == "append-in-order"]
    assert ordered, dialect
    for p in ordered:
        assert _ORDER_ROWS[dialect] in p.cites, p


def test_panos_rule_order_is_cited_from_an_unversioned_page():
    """Review of #52/#53, F6: cited, and its release recorded as
    unversioned; a file still holds one rule (F2)."""
    from rulehawk import citations
    assert "panos-rule-order" not in citations.PENDING
    assert "unversioned" in citations.resolve("panos-rule-order").release
    for p in _grammars()["panos"].PRODUCTIONS:
        assert "panos-rule-order" in p.cites and "panos-rule-order" not in p.needs, p


# ------------------------------------------------------------------- the fold

def test_the_fold_refuses_a_second_write_to_one_attribute():
    from rulehawk.grammar_junos import Fold
    f = Fold("toy")
    assert f.write(1, (), "a", "create") is None
    assert f.write(2, ("a",), "x", "error", "1") is None
    assert f.write(3, ("a",), "x", "error", "2") == "write-merge-uncited"
    assert f.write(4, (), "a", "create") == "write-merge-uncited"


def test_the_fold_keeps_text_order_for_ordered_children():
    from rulehawk.grammar_junos import Fold
    f = Fold("toy")
    f.write(1, (), "list", "create")
    for n, name in enumerate(["b", "a", "c"], 2):
        assert f.write(n, ("list",), name, "append-in-order") is None
    assert _obj(f.model(), "list")["ordered"] == ["b", "a", "c"]
    assert f.write(5, ("list",), "a", "append-in-order") == "write-merge-uncited"


def test_the_fold_needs_an_existing_parent():
    from rulehawk.grammar_junos import Fold
    f = Fold("toy")
    with pytest.raises(KeyError):
        f.write(1, ("nowhere",), "a", "create")


# ---------------------------------------------------------- the three controls

def test_k00_model():
    r, m = _grammars()["junos"].parse_model(_read(_K00).encode())
    assert r["parses"] is True and m["dialect"] == "junos", (r, m)
    filt = _obj(m, "firewall", "family inet", "filter F")
    assert filt["ordered"] == ["term d", "term a"], filt
    assert _obj(m, "firewall", "family inet", "filter F", "term d")["values"] == {
        "then": "discard"}
    assert _obj(m, "firewall", "family inet", "filter F", "term a")["values"] == {
        "then": "accept"}
    src = [o["path"][-1] for o in m["objects"]
           if o["path"][:-1] == ["firewall", "family inet", "filter F", "term d", "from",
                                 "source-address"]]
    assert src == ["192.0.2.0/24"], m
    unit = ["interfaces", "ge-0/0/0", "unit 0", "family inet"]
    assert _obj(m, *unit)["values"] == {"address": "192.0.2.1/24"}
    assert _obj(m, *unit, "filter")["values"] == {"input": "F"}


def test_p00_model():
    r, m = _grammars()["panos"].parse_model(_read(_P00).encode())
    assert r["parses"] is True, r
    assert _obj(m, "rulebase security")["ordered"] == ["rules d"], m
    assert _obj(m, "rulebase security", "rules d")["values"] == {
        "from": "any", "to": "any", "source": "192.0.2.0/24",
        "destination": "198.51.100.0/24", "application": "any", "service": "any",
        "action": "deny"}
    assert "panos-rule-order" in r["rows"], r
    assert "panos-default-rules" in r["pending"], r


def test_i00_model():
    r, m = _grammars()["iptables"].parse_model(_read(_I00).encode())
    assert r["parses"] is True, r
    chain = _obj(m, "filter", "FORWARD")
    assert chain["values"] == {"policy": "DROP"}, chain
    assert chain["ordered"] == ["-s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP"], chain


def test_iptables_append_order_is_text_order():
    text = _read(_I00) + "iptables -A FORWARD -s 10.0.0.0/8 -j ACCEPT\n"
    _, m = _grammars()["iptables"].parse_model(text.encode())
    assert _obj(m, "filter", "FORWARD")["ordered"] == [
        "-s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP", "-s 10.0.0.0/8 -j ACCEPT"]


@pytest.mark.parametrize("dialect,path", [("junos", _K00), ("panos", _P00),
                                          ("iptables", _I00)])
def test_parse_is_parse_model_without_the_model(dialect, path):
    gm = _grammars()[dialect]
    raw = _read(path).encode()
    assert gm.parse(raw) == gm.parse_model(raw)[0]


def test_a_file_that_does_not_parse_has_no_model():
    _, m = _grammars()["iptables"].parse_model(b"#!/bin/sh\n")
    assert m is None


# ------------------------------------------- v4 slice 5 rows: p11, i05, i14

@pytest.mark.parametrize("rel,reason,line", [
    ("cfg3/p11_panos_list_attr_set_twice.set", "line-not-allowlisted", 2),
    ("cfg3/i05_iptables_policy_twice.sh", "write-merge-uncited", 3),
    ("cfg3/i14_iptables_insert_accept_top.sh", "line-not-allowlisted", 3),
])
def test_slice_5_rows(rel, reason, line, shadow):
    """p11 (a list attribute set twice), i05 (`-P` twice) and i14 (`-I`).
    Slice 4 took these off already; they stay off, with no model."""
    sh = _gate_shadow(os.path.join(_D, rel))
    assert sh["blocking_reason"] == reason, sh
    assert sh["grammar"]["line"] == line, sh
    assert "model" not in sh, sh
    assert sh["would_pass"] is False, sh


# ------------------------------------------------------------ the shadow block

@pytest.mark.parametrize("path,dialect", [(_K00, "junos"), (_P00, "panos"),
                                          (_I00, "iptables")])
def test_the_model_goes_into_the_shadow_block(path, dialect, shadow):
    sh = _gate_shadow(path)
    assert sh["grammar"]["parses"] is True, sh
    assert set(sh["model"]) == {"dialect", "objects"}, sh
    assert sh["model"]["dialect"] == dialect, sh
    assert sh["blocking_reason"] == "file-uncertified", sh
    assert sh["would_pass"] is False, sh
    for word in ("PASS", "VERIFIED", "NO_NEW_RISK", "certified\"", "complete"):
        assert word not in json.dumps(sh["model"]), sh


def test_no_model_without_the_switch(monkeypatch):
    monkeypatch.delenv("RULEHAWK_SHADOW", raising=False)
    d = json.loads(g.to_json(g.run_gate([_K00], None, fail_on="high", vendor="auto")))
    (f,) = d["files"]
    assert "shadow" not in f, f
