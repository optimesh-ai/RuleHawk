"""`--hh-ingress NAME`: path-grounding probes received on a named interface.

Hammerhead decides a Cisco ASA's traffic by the interface it arrives on
(interface security levels, hammerhead D50/D51). A probe `--from` an ASA with
a host source and no received interface is Unknown (exit 3) there, so
RuleHawk's verdict is INDETERMINATE. `--hh-ingress` passes the interface
through as `hammerhead traceroute --ingress NAME`, so the trace can be
definite. RuleHawk never infers the interface: without the flag the argv
carries no `--ingress`.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rulehawk.cli as cli  # noqa: E402
from rulehawk.cli import main as cli_main  # noqa: E402
from rulehawk.pathground import (  # noqa: E402
    HammerheadReachOracle, Reach, Witness)

_W = Witness("10.20.0.1", "10.10.0.1", "tcp", 445)

_POLICY = {
    "zones": {"PCI": ["10.10.0.0/16"], "CORP": ["10.20.0.0/16"]},
    "must_not_reach": [{"src": "CORP", "dst": "PCI", "proto": "tcp", "ports": [445]}],
}

_LEAKY_ACL = ("ip access-list extended T\n"
              " permit tcp 10.20.0.0 0.0.255.255 10.10.0.0 0.0.255.255 eq 445\n")


class _FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


def _trace(disposition, coverage=None):
    doc = {"hops": [], "disposition": disposition}
    if coverage is not None:
        doc["coverage"] = coverage
    return json.dumps(doc)


def _snapshot(tmp_path):
    d = tmp_path / "snap"
    d.mkdir()
    (d / "fw.cfg").write_text("interface Gi0/0\n")
    return d


def _capturing(tmp_path, **kw):
    seen = []

    def capture(argv):
        seen.append(argv)
        return _FakeProc(0, _trace("Delivered"))

    return HammerheadReachOracle(str(_snapshot(tmp_path)), "FW", runner=capture, **kw), seen


def test_ingress_is_passed_to_traceroute(tmp_path):
    orc, seen = _capturing(tmp_path, ingress="inside")
    assert orc(_W) is Reach.REACHABLE
    (argv,) = seen
    assert argv[1] == "traceroute"
    assert argv[argv.index("--ingress") + 1] == "inside"
    assert argv[argv.index("--from") + 1] == "FW"


def test_no_ingress_flag_without_the_option(tmp_path):
    """RuleHawk never picks an interface on its own."""
    orc, seen = _capturing(tmp_path)
    orc(_W)
    (argv,) = seen
    assert "--ingress" not in argv


def test_unknown_without_ingress_stays_indeterminate(tmp_path):
    """Hammerhead's per-flow Unknown (exit 3, typed blocker) is never a PASS."""
    cov = {"status": "degraded", "degraded": True,
           "affected_devices": ["FW"],
           "blockers": [{"blocker": "unmodeled_feature", "device": "FW",
                         "feature": "asa-security-level-unmodeled",
                         "status": "unmodeled"}]}
    body = _trace("Unknown: the answer at device FW depends on the interface "
                  "the packet is received on", cov)
    orc = HammerheadReachOracle(str(_snapshot(tmp_path)), "FW",
                                runner=lambda argv: _FakeProc(3, body))
    assert orc(_W) is Reach.INDETERMINATE


def _files(tmp_path):
    acl = tmp_path / "fw.acl"
    acl.write_text(_LEAKY_ACL)
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps(_POLICY))
    return str(acl), str(pol), str(_snapshot(tmp_path))


def test_cli_hh_ingress_reaches_the_oracle(tmp_path, monkeypatch):
    acl, pol, snap = _files(tmp_path)
    made = []

    class _Spy:
        def __init__(self, snapshot_dir, from_device, **kw):
            made.append((snapshot_dir, from_device, kw))

        def __call__(self, w):
            return Reach.INDETERMINATE

    monkeypatch.setattr(cli, "HammerheadReachOracle", _Spy)
    cli_main([acl, "--policy", pol, "--hh-snapshot", snap, "--hh-from", "FW",
              "--hh-ingress", "inside", "--json"])
    assert made == [(snap, "FW", {"ingress": "inside"})]


def test_cli_hh_ingress_needs_a_value(tmp_path, capsys):
    acl, pol, snap = _files(tmp_path)
    rc = cli_main([acl, "--policy", pol, "--hh-snapshot", snap, "--hh-from", "FW",
                   "--hh-ingress"])
    assert rc == 2
    assert "--hh-ingress" in capsys.readouterr().err


def test_cli_hh_ingress_needs_path_grounding(tmp_path, capsys):
    acl, pol, _ = _files(tmp_path)
    rc = cli_main([acl, "--policy", pol, "--hh-ingress", "inside"])
    assert rc == 2
    assert "--hh-ingress" in capsys.readouterr().err


def test_help_documents_hh_ingress(capsys):
    assert cli_main(["--help"]) == 0
    assert "--hh-ingress" in capsys.readouterr().out
