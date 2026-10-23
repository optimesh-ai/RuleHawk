"""MCP stdio integration: launch `python -m rulehawk.mcp_server` as a real
subprocess and drive it with the official MCP Python SDK client.

Skipped when the SDK is not installed (it is the optional `mcp` extra and
needs Python 3.10+); CI installs it on the 3.12 leg.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")

EXPECTED_TOOLS = {"rulehawk_audit", "rulehawk_list_findings",
                  "rulehawk_explain_finding", "rulehawk_compare",
                  "rulehawk_supported_inputs"}


def _session(fn):
    async def go():
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "rulehawk.mcp_server"],
                                       cwd=ROOT)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                return await fn(s)
    return asyncio.run(go())


def _payload(res):
    assert not res.is_error, res
    return json.loads(res.content[0].text)


def test_tools_list_is_the_five_read_only_tools():
    tools = _session(lambda s: s.list_tools()).tools
    assert {t.name for t in tools} == EXPECTED_TOOLS
    for t in tools:
        assert t.description
        assert t.annotations.read_only_hint is True, t.name
        assert t.annotations.open_world_hint is False, t.name
        assert t.annotations.destructive_hint is False, t.name


def test_audit_over_stdio_returns_verdict_coverage_and_scope():
    res = _session(lambda s: s.call_tool(
        "rulehawk_audit", {"path": os.path.join(SAMPLES, "ios_acl.txt"),
                           "policy_path": os.path.join(SAMPLES, "policy.json")}))
    r = _payload(res)
    assert r["verdict"] == "FAIL"
    assert r["coverage"]["state"] == "complete"
    assert any(f["kind"] == "segmentation-violation" for f in r["blocking_findings"])
    assert r["scope"]["statement"].startswith("Rule layer only")


def test_list_then_explain_over_stdio():
    sample = os.path.join(SAMPLES, "ios_acl.txt")

    async def flow(s):
        lf = _payload(await s.call_tool("rulehawk_list_findings",
                                        {"path": sample, "min_severity": "high"}))
        fid = lf["findings"][0]["id"]
        ex = _payload(await s.call_tool("rulehawk_explain_finding",
                                        {"finding_id": fid, "path": sample}))
        return lf, ex
    lf, ex = _session(flow)
    assert lf["findings_total"] >= 1
    assert ex["found"] is True and ex["finding"]["id"] == lf["findings"][0]["id"]


def test_compare_and_unsupported_input_over_stdio(tmp_path):
    fgt = tmp_path / "fgt.conf"
    fgt.write_text("config firewall policy\n    edit 1\n    next\nend\n")

    async def flow(s):
        c = _payload(await s.call_tool("rulehawk_compare", {
            "before": os.path.join(SAMPLES, "adv_realistic.txt"),
            "after": os.path.join(SAMPLES, "ios_acl.txt")}))
        a = _payload(await s.call_tool("rulehawk_audit", {"path": str(fgt)}))
        e = _payload(await s.call_tool("rulehawk_audit",
                                       {"path": str(tmp_path / "nope")}))
        return c, a, e
    c, a, e = _session(flow)
    assert c["verdict"] == "INTRODUCES_RISK" and c["introduced_total"] >= 1
    assert a["verdict"] == "INCOMPLETE"
    assert a["coverage"]["not_analysed"][0]["path"] == "fgt.conf"
    assert e["verdict"] == "ERROR"

