"""Citation registry for the allowlist grammar (#42 design v2 section 1.2,
v4 sections 5 and 14).

A grammar production may exist only for a row cited here. Each row is a
verbatim quote from a first-party page, fetched in full and confirmed by a
second fetch, with its URL, the page title, the release the page states
(or that it states none) and the dates. Whitespace inside a quote is
collapsed to single spaces; nothing else is changed.

Rows of v4 section 14 that are not yet fetched and confirmed are in
PENDING, with the reason. `resolve` refuses them, so no production can rest
on one. This module is data only and imports only the standard library: the
independent checker (v4 section 5) may import it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Row:
    id: str
    url: str
    title: str
    release: str
    quote: str
    fetched: str
    confirmed: str


_GUIDELINES = ("https://www.juniper.net/documentation/us/en/software/junos/"
               "routing-policy/topics/concept/"
               "firewall-filter-stateless-guidelines-for-configuring.html")
_GUIDELINES_TITLE = "Guidelines for Configuring Firewall Filters | Junos OS | Juniper Networks"
_MATCH_V4 = ("https://www.juniper.net/documentation/us/en/software/junos/"
             "routing-policy/topics/concept/"
             "firewall-filter-match-conditions-for-ipv4-traffic.html")
_MATCH_V4_TITLE = "Firewall Filter Match Conditions for IPv4 Traffic | Junos OS | Juniper Networks"
_FILTER_UNIT = ("https://www.juniper.net/documentation/us/en/software/junos/"
                "cli-reference/topics/ref/statement/filter-edit-interfaces-unit-family.html")
_FILTER_UNIT_TITLE = "filter (Applying to a Logical Interface) | Junos OS | Juniper Networks"
_ADDRESS = ("https://www.juniper.net/documentation/us/en/software/junos/"
            "cli-reference/topics/ref/statement/address-edit-interfaces.html")
_ADDRESS_TITLE = "address | Junos OS | Juniper Networks"

_NO_RELEASE = "the page states no release (Junos OS documentation, current)"
_SINCE_7_4 = "Statement introduced before Junos OS Release 7.4."
_DATE = "2026-11-09"


def _row(cid: str, url: str, title: str, release: str, quote: str) -> Row:
    return Row(cid, url, title, release, " ".join(quote.split()), _DATE, _DATE)


ROWS: Dict[str, Row] = {r.id: r for r in (
    _row("junos-term-order", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "Firewall filter terms are evaluated in the order in which they are "
         "configured."),
    _row("junos-terminating-action", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "Halts all evaluation of a firewall filter for a specific packet."),
    _row("junos-terminating-replaced", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "If you try to specify more than one terminating action within the "
         "filter term then the latest terminating action will replace the "
         "existing terminating action."),
    _row("junos-firewall-family-inet-equivalent", _GUIDELINES, _GUIDELINES_TITLE,
         _NO_RELEASE,
         "because the `[edit firewall]` and `[edit firewall family inet]` "
         "hierarchy levels are equivalent."),
    _row("junos-filter-name", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "The filter name can contain letters, numbers, and hyphens (-) and be "
         "up to 64 characters long."),
    _row("junos-match-destination-address", _MATCH_V4, _MATCH_V4_TITLE, _NO_RELEASE,
         "Match the IPv4 destination address field unless the `except` option "
         "is included."),
    _row("junos-filter-input", _FILTER_UNIT, _FILTER_UNIT_TITLE, _SINCE_7_4,
         "Name of one filter to evaluate when packets are received on the "
         "interface."),
    _row("junos-interface-address", _ADDRESS, _ADDRESS_TITLE, _SINCE_7_4,
         "Configure the interface address."),
)}

# v4 section 14 Junos rows (and the interface address row's companions) that
# are not cited yet. Until each is, every construct that needs it is off the
# allowlist.
PENDING: Dict[str, str] = {
    "junos-match-source-address": (
        "the source-address row sits further down the IPv4 match-conditions "
        "page than the fetches so far reached; fetch and confirm it"),
    "junos-implicit-discard": (
        "the 'Stateless Firewall Filter Components' page is not yet found "
        "and fetched; until it is, a packet that reaches the end of a filter "
        "has no cited outcome"),
    "junos-comments": (
        "the XML/JSON mapping page for `#` and same-line `/* */` comments is "
        "not yet fetched; until it is, a comment is off the allowlist"),
    "junos-lexing": (
        "keyword case and quoting (Junos CLI user guide) are not yet fetched; "
        "until they are, keywords match exact lowercase and a quoted name is "
        "off the allowlist"),
    "junos-evolved-scope": (
        "none of the fetched pages names Junos OS Evolved; v4 section 8 needs "
        "each row cited for Junos OS and Junos OS Evolved"),
}


def resolve(cid: str) -> Row:
    """The cited row `cid`. A pending or unknown id raises KeyError."""
    if cid in PENDING:
        raise KeyError(f"{cid} is not cited yet: {PENDING[cid]}")
    return ROWS[cid]
