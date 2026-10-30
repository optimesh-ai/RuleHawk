# Hosted page analytics (opt-in, privacy-preserving)
RuleHawk's core promise is that **your config never leaves your browser.** The
hosted tool (`docs/index.html`) keeps that promise even with analytics on: it
emits only anonymous *usage* metadata, never config text or findings. Everything
is **off by default** — set two constants at the top of the `<script>` in
`docs/index.html`:

- `ANALYTICS_ENDPOINT` — a URL that accepts a JSON `POST`. Empty = nothing is
  ever sent. When set, RuleHawk beacons (via `navigator.sendBeacon`, so it never
  blocks the UI):
  - `page_view` — a visit, with the `?ref=` campaign tag and referrer.
  - `scan_run` — that an audit ran, a coarse size **bucket** (e.g. `50-199`,
    never the exact count), and whether a segmentation policy was used.
    **Never the config, never the findings.**
  - `wall_view` — the "what RuleHawk can't tell you" panel was shown (no
    finding details attached).
  - `cta_click` / `lead_capture` — interaction with the results call-to-action
    (`target` is `ci-gate`, `hammerhead` or `hammerhead-wall`).

  Point it at any collector: a Cloudflare Worker, a Plausible/Umami proxy, or
  your own endpoint.
- `LEAD_ENDPOINT` — optional. When set, the results panel shows a "notify me"
  email field. On submit it posts the email plus the **finding counts the user
  already sees on screen** (criticals / highs / rules) — still never the config.
  Empty = no email field is shown.

**Campaign attribution:** append `?ref=<tag>` to the demo link in outreach
(e.g. `…/RuleHawk/?ref=acme-netlead`) and the tag rides along on every event, so
you can see which outreach actually got opened and used — without any config
telemetry.

The privacy banner on the page auto-discloses usage counting **only when
`ANALYTICS_ENDPOINT` is set**, so what the page claims and what it does stay in
sync.
