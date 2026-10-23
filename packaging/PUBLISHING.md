# Publishing the MCP server and the skill (prepared, not done)

Nothing in this file has been published. Each step below needs a maintainer's
explicit go-ahead.

## MCP Registry (`server.json`)

`server.json` at the repo root describes the server for the official MCP
Registry (`registry.modelcontextprotocol.io`). It validates against
`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`.

The registry only lists packages it can fetch from a public package registry
(npm, PyPI, NuGet, crates.io, OCI, or an `.mcpb` release asset). A
`git+https://` install is not accepted, so **this entry needs `rulehawk` 0.4.0
on PyPI first**. The PyPI name `rulehawk` was unclaimed on 2026-10-22.

The entry runs `uvx --from "rulehawk[mcp]==0.4.0" rulehawk mcp`: the `mcp`
subcommand of the normal `rulehawk` CLI starts the same stdio server as
`rulehawk-mcp`.

Ownership checks:

- PyPI: the registry looks for `mcp-name: io.github.optimesh-ai/rulehawk` in
  the package description. It is the last line of `README.md` (an HTML
  comment), which becomes the PyPI description.
- Namespace: `io.github.optimesh-ai/*` needs a GitHub login with access to the
  `optimesh-ai` org.

Steps:

1. Tag the release commit `v0.4.0` and build: `python -m build` (sdist + wheel).
2. Upload to PyPI: `python -m twine upload dist/rulehawk-0.4.0*`.
3. Check it runs from PyPI: `uvx --from "rulehawk[mcp]==0.4.0" rulehawk mcp --version`.
4. Install the publisher CLI (`brew install mcp-publisher`, or a release
   binary from github.com/modelcontextprotocol/registry).
5. `mcp-publisher login github` (as a member of optimesh-ai).
6. `mcp-publisher publish` from the repo root.
7. Check it is listed:
   `curl "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.optimesh-ai/rulehawk"`.

For a later release, bump `version` in `pyproject.toml`, `rulehawk/__init__.py`
and both `version` fields plus the `--from` pin in `server.json`.

## skills.sh (`skills/rulehawk-preflight/SKILL.md`)

skills.sh has no submission form. It lists skills from the anonymous install
telemetry of the `skills` CLI (github.com/vercel-labs/skills), which finds
`skills/<name>/SKILL.md` in a GitHub repo. The skill already has the required
frontmatter (`name`, lowercase with hyphens; `description`).

Listing details:

- Source: `optimesh-ai/RuleHawk`
- Skill: `rulehawk-preflight`
- Install: `npx skills add optimesh-ai/RuleHawk --skill rulehawk-preflight`
  (Claude Code only: add `-a claude-code`; all projects: add `-g`)
- One-line summary: Audit a firewall or ACL change with RuleHawk before
  pushing it; stop on high-severity findings or unreadable input unless a human
  overrides.
- Needs: the `rulehawk` MCP server (see README, *Use it from an agent*), or the
  `rulehawk` CLI as a fallback.
- Licence: Apache-2.0

Step:

1. Run `npx skills add optimesh-ai/RuleHawk --skill rulehawk-preflight` once
   (Node.js 22.20+). The skills.sh docs say the directory is built from this
   install telemetry, so the first install should list it. Check
   with `npx skills find rulehawk`.

Running it sends the CLI's anonymous install telemetry, so it counts as
publishing. Do it only once the skill is approved.
