"""Citation registry for the allowlist grammar (#42 design v2 section 1.2,
v4 sections 5 and 14).

A grammar production may exist only for a row cited here. Each row is a
verbatim quote from a first-party page, fetched in full and confirmed by a
second fetch, with its URL, the page title, the release the page states
(or that it states none) and the dates. Whitespace inside a quote is
collapsed to single spaces, and the markdown backticks the fetch puts
around code font are dropped (they are not page text); nothing else is
changed.

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

_EVALUATE = ("https://www.juniper.net/documentation/us/en/software/junos/"
             "routing-policy/topics/concept/"
             "firewall-filter-stateless-evaluate-packets.html")
_EVALUATE_TITLE = "How Standard Firewall Filters Evaluate Packets | Junos OS | Juniper Networks"
_JSON_MAP = ("https://www.juniper.net/documentation/us/en/software/junos/"
             "junos-xml-protocol/topics/concept/"
             "junos-xml-protocol-configuration-mapping-to-json.html")
_JSON_MAP_TITLE = "Map Junos OS Configuration Statements to JSON | Junos OS | Juniper Networks"
_CLI_CONFIG = ("https://www.juniper.net/documentation/us/en/software/junos/"
               "cli/topics/topic-map/cli-configuration.html")
_CLI_CONFIG_TITLE = "CLI Configuration Mode Overview | Junos OS | Juniper Networks"
_PROTO_FAMILY = ("https://www.juniper.net/documentation/us/en/software/junos/"
                 "interfaces-fundamentals/topics/topic-map/"
                 "protocol-family-interface-address-properties.html")
_PROTO_FAMILY_TITLE = "Protocol Family | Junos OS | Juniper Networks"

# PAN-OS (slice 4c).
_COMPONENTS = ("https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/"
               "security-policy/components-of-a-security-policy-rule")
_COMPONENTS_TITLE = "Components of a Security Policy Rule"
_COMPONENTS_RELEASE = "the PAN-OS 11.1 documentation set (the page URL); no other release"
_KB_CREATE = ("https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?"
              "id=kA10g000000ClaCCAS")
_KB_CREATE_TITLE = "How to View, Create and Delete Security Policies on the CLI"
_KB_CREATE_RELEASE = "the article states Environment: Any Firewall, and no release"
_KB_SET = ("https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?"
           "id=kA10g000000ClHoCAK&lang=en_US")
_KB_SET_TITLE = "Viewing the configuration in set and XML format"
_KB_SET_RELEASE = "the article states Environment: Any PAN-OS, and no release"
_KB_ONE_LINE = ("https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?"
                "id=kA10g000000ClcLCAS")
_KB_ONE_LINE_TITLE = ("How to Add and Verify Address Objects to Address Group and "
                      "Security Policy through the CLI")
_KB_ONE_LINE_RELEASE = "the article states Environment: PanOS's CLI access., and no release"

# iptables (slice 4d).
_IPT = "https://man7.org/linux/man-pages/man8/iptables.8.html"
_IPT_TITLE = "iptables(8) - Linux manual page"
_IPT_RELEASE = "This manual page applies to iptables/ip6tables 1.8.13."

# v4 section 14 fetches (2026-11-09): Junos static routes.
_STATIC = ("https://www.juniper.net/documentation/us/en/software/junos/"
           "cli-reference/topics/ref/statement/static-edit-routing-options.html")
_STATIC_TITLE = "static (Routing Options) | Junos OS | Juniper Networks"
_RESOLVE = ("https://www.juniper.net/documentation/us/en/software/junos/"
            "cli-reference/topics/ref/statement/resolve-edit-routing-options.html")
_RESOLVE_TITLE = "resolve | Junos OS | Juniper Networks"

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
         "because the [edit firewall] and [edit firewall family inet] "
         "hierarchy levels are equivalent."),
    _row("junos-filter-name", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "The filter name can contain letters, numbers, and hyphens (-) and be "
         "up to 64 characters long."),
    _row("junos-match-destination-address", _MATCH_V4, _MATCH_V4_TITLE, _NO_RELEASE,
         "Match the IPv4 destination address field unless the except option "
         "is included."),
    _row("junos-filter-input", _FILTER_UNIT, _FILTER_UNIT_TITLE, _SINCE_7_4,
         "Name of one filter to evaluate when packets are received on the "
         "interface."),
    _row("junos-interface-address", _ADDRESS, _ADDRESS_TITLE, _SINCE_7_4,
         "Configure the interface address."),
    # Slice 4b. The statement pages' Syntax and Hierarchy Level blocks do not
    # come through a full Exa fetch, so the hierarchy is cited from prose.
    _row("junos-match-source-address", _MATCH_V4, _MATCH_V4_TITLE, _NO_RELEASE,
         "Match the IPv4 address of the source node sending the packet unless "
         "the except option is included."),
    _row("junos-interface-filter-hierarchy", _MATCH_V4, _MATCH_V4_TITLE, _NO_RELEASE,
         "To assign a logical interface to an interface group group-number, "
         "specify the group-number at the [interfaces interface-name unit "
         "number family family filter group] hierarchy level."),
    # The design's "Stateless Firewall Filter Components" page is not in the
    # current documentation (the juniper.net URL is not found, and the copy
    # on networkingdocs.hpe.com is the release-scoped Junos 12.3 set). This
    # current page states the same implicit discard.
    _row("junos-implicit-discard", _EVALUATE, _EVALUATE_TITLE, _NO_RELEASE,
         "Every firewall filter configuration includes an implicit discard "
         "action at the end of the filter."),
    _row("junos-discard-term", _EVALUATE, _EVALUATE_TITLE, _NO_RELEASE,
         "This implicit terminating action is equivalent to including the "
         "following example term t_explicit_discard as the final term in the "
         "firewall filter: term t_explicit_discard { then discard; }"),
    _row("junos-accept-terminating", _EVALUATE, _EVALUATE_TITLE, _NO_RELEASE,
         "In this case, we recommend that you configure the firewall filter "
         "with a final term that specifies the accept terminating action."),
    _row("junos-comments", _JSON_MAP, _JSON_MAP_TITLE, _NO_RELEASE,
         "Comments are indicated using one of two delimiters: the paired "
         "strings /* and */ enclosing the comment, or the # character "
         "preceding the comment."),
    _row("junos-config-indent", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "The CLI indents each level in the hierarchy to indicate each "
         "statement’s relative position in the hierarchy."),
    _row("junos-config-braces", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "Additionally, in general, it sets off each level with braces, using "
         "an open brace at the beginning of each hierarchy level and a closing "
         "brace at the end."),
    _row("junos-config-leaf-semicolon", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "Each leaf statement ends with a semicolon."),
    _row("junos-interface-family-hierarchy", _PROTO_FAMILY, _PROTO_FAMILY_TITLE,
         _NO_RELEASE,
         "To configure the protocol family, complete the minimum configuration "
         "tasks under the [edit interfaces interface-name unit "
         "logical-unit-number family family] hierarchy."),
    # Verbatim, with the page's interface for interfaces.
    _row("junos-interface-address-inet", _PROTO_FAMILY, _PROTO_FAMILY_TITLE,
         _NO_RELEASE,
         "To configure an IP version 4 (IPv4) address on routers and switches, "
         "use the interface interface-name unit number family inet address "
         "a.b.c.d/nn statement at the [edit interfaces] hierarchy level."),
    # Table 2, "Configuration Mode Top-Level Statements" (the firewall
    # and interfaces rows).
    _row("junos-top-firewall", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "Configure filters that select packets based on their contents."),
    # review of #51, F4: Table 2's Statement cells, not only its Description
    _row("junos-top-statements", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "Table 2 lists top-level configuration statements."),
    _row("junos-top-firewall-keyword", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "firewall"),
    _row("junos-top-interfaces-keyword", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "interfaces"),
    _row("junos-top-interfaces", _CLI_CONFIG, _CLI_CONFIG_TITLE, _NO_RELEASE,
         "Configure interface information, such as encapsulation, interfaces, "
         "virtual channel identifiers (VCIs), and data-link connection "
         "identifiers (DLCIs)."),
    _row("junos-firewall-family-inet", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "family inet—To filter Internet Protocol version 4 (IPv4) traffic."),
    _row("junos-filter-statement", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "Under the family family-name statement, you can include filter "
         "filter-name statements to create and name firewall filters."),
    _row("junos-term-statement", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "Under the filter filter-name statement, you can include term "
         "term-name statements to create and name filter terms."),
    _row("junos-term-name", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "The term name can contain letters, numbers, and hyphens (-) and can "
         "be up to 64 characters long."),
    _row("junos-from-statement", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "With the exception of MPLS-tagged IPv4 or IPv6 traffic, you specify "
         "the term’s match conditions under the from statement."),
    _row("junos-then-statement", _GUIDELINES, _GUIDELINES_TITLE, _NO_RELEASE,
         "Under the then statement for a firewall filter term, you can "
         "specify the actions to be taken on a packet that matches the term."),
    # PAN-OS (slice 4c)
    _row("panos-rule-name", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "A label (up to 63 characters) that identifies the rule."),
    _row("panos-source-zone", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "The zone from which the traffic originates."),
    _row("panos-destination-zone", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "The zone at which the traffic terminates."),
    _row("panos-source-address", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "Define host IP addresses, subnets, address objects (of type IP "
         "netmask, IP range, FQDN, or IP wildcard mask), address groups, or "
         "country-based enforcement."),
    _row("panos-destination-address", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "The location or destination for the packet."),
    _row("panos-application", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "The application that you wish to control."),
    _row("panos-service-any", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "You can choose any, specify a port, or use application-default to "
         "permit use of the standards-based port for the application."),
    _row("panos-action", _COMPONENTS, _COMPONENTS_TITLE, _COMPONENTS_RELEASE,
         "Specifies an Allow or Deny action for the traffic based on the "
         "criteria you define in the rule."),
    _row("panos-cli-create-rule", _KB_CREATE, _KB_CREATE_TITLE, _KB_CREATE_RELEASE,
         "# set rulebase security rules <name> from <source zone> to "
         "<destination zone> destination <ip> application <application> "
         "service <any/application-default/service name> action <allow/deny> "
         "(press enter)"),
    _row("panos-set-from-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 from any"),
    _row("panos-set-to-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 to any"),
    _row("panos-set-source-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 source any"),
    _row("panos-set-destination-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 destination any"),
    _row("panos-set-application-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 application any"),
    _row("panos-set-service-any", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 service any"),
    _row("panos-set-action-allow", _KB_SET, _KB_SET_TITLE, _KB_SET_RELEASE,
         "set rulebase security rules rule1 action allow"),
    # review of #52/#53, F3: several attributes on one `set` line, in an
    # order other than the create template's
    _row("panos-one-line-form", _KB_ONE_LINE, _KB_ONE_LINE_TITLE, _KB_ONE_LINE_RELEASE,
         "# set rulebase security rules trust-DMZ action allow source testgroup"),
    # iptables (slice 4d)
    _row("iptables-synopsis-append", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "iptables [-t table] {-A|-C|-D|-V} chain rule-specification"),
    _row("iptables-synopsis-policy", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "iptables [-t table] -P chain policy"),
    _row("iptables-rule-specification", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "rule-specification := [matches...] [target]"),
    _row("iptables-first-match", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "If the packet does not match, the next rule in the chain is "
         "examined; if it does match, then the next rule is specified by the "
         "value of the target, which can be the name of a user-defined "
         "chain, one of the targets described in iptables-extensions(8), or "
         "one of the special values ACCEPT, DROP or RETURN."),
    _row("iptables-accept-drop", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "ACCEPT means to let the packet through. DROP means to drop the "
         "packet on the floor."),
    _row("iptables-policy-end", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "If the end of a built-in chain is reached or a rule in a built-in "
         "chain with target RETURN is matched, the target specified by the "
         "chain policy determines the fate of the packet."),
    _row("iptables-filter-default", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "This is the default table (if no -t option is passed)."),
    # Quoted up to the line wrap in `locally-` (review of #52/#53, F4:
    # fetched twice more, verbatim); the rest of the sentence is not quoted.
    _row("iptables-filter-chains", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "It contains the built-in chains INPUT (for packets destined to "
         "local sockets), FORWARD (for packets being routed through the box), "
         "and OUTPUT (for locally-"),
    _row("iptables-append", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "Append one or more rules to the end of the selected chain."),
    _row("iptables-policy", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "Set the policy for the built-in (non-user-defined) chain to the "
         "given target. The policy target must be either ACCEPT or DROP."),
    _row("iptables-source", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "Source specification. Address can be either a network name, a "
         "hostname, a network IP address (with /mask), or a plain IP "
         "address."),
    _row("iptables-mask", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "The mask can be either an ipv4 network mask (for iptables) or a "
         "plain number, specifying the number of 1's at the left side of the "
         "network mask."),
    _row("iptables-destination", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "Destination specification. See the description of the -s (source) "
         "flag for a detailed description of the syntax."),
    _row("iptables-jump", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "This specifies the target of the rule; i.e., what to do if the "
         "packet matches it."),
    # v4 section 14 fetches: cited for a later slice; no production rests on
    # these rows yet. Neither Junos page states Junos OS Evolved
    # (junos-evolved-scope stays pending).
    _row("junos-static-next-hop", _STATIC, _STATIC_TITLE, _SINCE_7_4,
         "next-hop address\u2014Reach the next-hop routing device by specifying "
         "an IP address, an interface name, or an ISO network entity title "
         "(NET)."),
    _row("junos-static-direct-next-hop", _RESOLVE, _RESOLVE_TITLE, _SINCE_7_4,
         "Static routes can point only to a directly connected next hop."),
    # A protocol name is looked up in /etc/protocols on the host, which the
    # file does not hold; a production must take that into account.
    _row("iptables-protocol", _IPT, _IPT_TITLE, _IPT_RELEASE,
         "The protocol of the rule or of the packet to check. The specified "
         "protocol can be one of tcp, udp, udplite, icmp, icmpv6, esp, ah, "
         "sctp, mh or the special keyword \"all\", or it can be a numeric "
         "value, representing one of these protocols or a different one. A "
         "protocol name from /etc/protocols is also allowed. A \"!\" argument "
         "before the protocol inverts the test. The number zero is equivalent "
         "to all. \"all\" will match with all protocols and is taken as "
         "default when this option is omitted."),
)}

# v4 section 14 Junos and PAN-OS rows (and the interface address row's
# companions) that are not cited yet. Until each is, every construct that
# needs it is off the allowlist.
PENDING: Dict[str, str] = {
    "junos-lexing": (
        "keyword case: no first-party page found that states configuration "
        "keywords are case-sensitive (the CLI user guide's 'Modify the "
        "Configuration of a Device' and 'CLI Configuration Mode Overview' "
        "pages were fetched on 2026-11-09 and say nothing on it; its quoting "
        "rule comes through Exa with the character list dropped). Until it "
        "is cited, keywords match exact lowercase and a quoted name is off "
        "the allowlist"),
    "junos-evolved-scope": (
        "none of the fetched pages states its rows for Junos OS Evolved (it "
        "is named only in side notes); v4 section 8 needs each row cited for "
        "Junos OS and Junos OS Evolved, so the uncited-remainder member "
        "(v3 section 6.3) stays"),
    # review of #51, F4: what the name classes and an address list rest on.
    # A production that needs one of these still parses in shadow and
    # lists it under `pending`; each needs a row before slice 7.
    "junos-unit-number": (
        "no fetched page states the range of a logical unit number; the "
        "class is narrowed to 0-9999 (decided by agent, unattended)"),
    "junos-interface-name": (
        "no fetched page states the interface-naming rule; the class is "
        "narrowed to ge-F/P/N with F 0-9, P 0-3 and N 0-47 (decided by "
        "agent, unattended)"),
    "junos-v4-prefix": (
        "no fetched page states how an a.b.c.d/nn prefix is lexed; the class "
        "is canonical dotted quad with a length 0-32, and a match prefix "
        "with host bits set is off"),
    "junos-address-list-or": (
        "no fetched page states that the prefixes in one source-address or "
        "destination-address list match as an OR"),
    # PAN-OS (slice 4c)
    "panos-release-scope": (
        "the components page is in the PAN-OS 11.1 documentation set; the "
        "knowledge-base articles (kA10g000000ClcLCAS among them) state no "
        "release, and the Security Policy Rules page "
        "(docs.paloaltonetworks.com/network-security/security-policy/"
        "administration/security-rules) is in the unversioned Network "
        "Security documentation set (review of #52-#57, G1); v4 section 8 needs "
        "each row cited per supported release, so the uncited-remainder "
        "member (v3 section 6.3) stays"),
    "panos-lexing": (
        "no first-party page fetched on 2026-11-09 states the set-CLI "
        "quoting, `[ ]` list, escape or keyword-case rules; until one does, "
        "keywords match exact lowercase and a quote or bracket is off"),
    "panos-list-semantics": (
        "setting an attribute of a rule that is already set adds members "
        "for a list attribute (v4 section 14); no fetched page states it, so "
        "a rule name set twice is off (v3 section 6.1)"),
    # review of #52-#57, G1: verbatim on two fetches, but unversioned, and it
    # states evaluation order, not where a new rule lands
    "panos-rule-order": (
        "the Security Policy Rules page "
        "(docs.paloaltonetworks.com/network-security/security-policy/"
        "administration/security-rules) says 'Security rules are evaluated "
        "left to right and from top to bottom. A packet is matched against "
        "the first rule that meets the defined criteria and, after a match "
        "is triggered, subsequent rules are not evaluated.'; the page is in "
        "the unversioned Network Security documentation set, and it states "
        "evaluation order only, not where a `set` places a new rule (append "
        "position)"),
    # review of #52-#57, G2
    "panos-one-line-order": (
        "panos-one-line-form shows several attributes on one `set` line in "
        "another order (`action allow source testgroup`); no fetched row "
        "shows the grammar's seven attributes in its fixed order, `source` "
        "after `to`, so that order is an inference"),
    # review of #52/#53, F2: what the meaning of one rule still rests on
    "panos-default-rules": (
        "the Security Policy Rules page says traffic that matches no rule "
        "goes to the default rules, which allow intrazone and deny interzone "
        "traffic and can be overridden; the outcome depends on zones and "
        "overrides the file does not hold (v4 section 3: not a row)"),
    "panos-any-meaning": (
        "the rows show the syntax `from any`, `to any`, `source any`, "
        "`destination any`; no fetched row states that `any` means every "
        "zone or every address"),
    "panos-rule-type-default": (
        "the Security Policy Rules page lists 'universal (default)' in its "
        "Rule Type cell; no row quotes it, and v4 section 3 keeps rule-type "
        "off until its KB row is cited"),
    "panos-session-semantics": (
        "the Security Policy Rules page says 'When a session match occurs, "
        "the Security rule is applied to bidirectional traffic in that "
        "session'; a per-packet reading differs, and no model of sessions is "
        "built"),
    # review of #51, F4, for PAN-OS
    "panos-rule-name-chars": (
        "panos-rule-name states the length only; the character set is "
        "narrowed to letters, digits and hyphens, starting with a letter or "
        "digit (decided by agent, unattended)"),
    "panos-v4-prefix": (
        "panos-source-address names subnets but no fetched page states the "
        "a.b.c.d/nn form; the class is canonical dotted quad with a length "
        "0-32, and a prefix with host bits set is off"),
    # iptables (slice 4d)
    "iptables-lexing": (
        "iptables(8) says 'For long versions of the command and option "
        "names, you need to use only enough letters to ensure that iptables "
        "can differentiate it from all other options.'; abbreviation, long "
        "options, aliases and shell quoting are not read, so options match "
        "their exact short spelling"),
    "iptables-script-scope": (
        "a script is run by a shell against the rule set already loaded; no "
        "fetched first-party page states the rule set before the script, "
        "that its lines run in order, or any shell construct, so every "
        "production records this row and no shell syntax is read. Only the "
        "filter table of iptables is read: iptables(8) says 'There are "
        "currently five independent tables', and 'The security table is "
        "called after the filter table'; rules in the security table, the "
        "nat, mangle and raw tables, ip6tables and nftables on the same host "
        "also decide a packet's fate and are not seen (review of #52/#53, "
        "F5)"),
    "iptables-release-scope": (
        "the fetched page applies to iptables 1.8.13 only; the legacy and "
        "nft back ends and other releases are not cited, so the "
        "uncited-remainder member (v3 section 6.3) stays"),
    "iptables-save-format": (
        "iptables-save(8) and iptables-restore(8) (iptables 1.8.13) were "
        "fetched twice on 2026-11-09 and state options only: no line states "
        "the *filter, :CHAIN or COMMIT lines. The only format text is the "
        "--noflush example '*filter :FILTERS - [0:0] -A FILTERS ... will "
        "flush and re-build the FILTERS chain from scratch, while retaining "
        "the content of all other chains in the table.', so the save format "
        "is off"),
    # v4 section 14 fetches (2026-11-09), kept pending
    "panos-static-route": (
        "the PAN-OS 11.1 web interface help page 'Static Routes' "
        "(docs.paloaltonetworks.com/ngfw/help/11-1/network/"
        "network-virtual-routers/static-routes), fetched twice, describes GUI "
        "fields only ('IP Address\u2014Select to enter the IP address of the "
        "next hop router, or select or create an address object of type IP "
        "Netmask.'); it states no set-CLI form, and a next hop can also be "
        "an address object name, Next VR, FQDN, Discard or None, so no "
        "production"),
    "panos-layer3-interface": (
        "the PAN-OS 11.1 page 'Configure Layer 3 Interfaces' "
        "(docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/"
        "configure-interfaces/layer-3-interfaces/configure-layer-3-interfaces), "
        "fetched twice, is a GUI procedure with no set-CLI form, and says "
        "'Beginning with PAN-OS 11.1.4, you can configure duplicate "
        "(overlapping) IP addresses on Layer 3 interfaces for an Advanced "
        "Routing Engine.', so an interface address does not name one segment "
        "on every 11.1 release"),
    "iptables-dport": (
        "iptables-extensions(8) (iptables 1.8.13) was fetched twice; the "
        "fetch ends before the tcp section, and shows only 'If the -p or "
        "--protocol was specified and if and only if an unknown option is "
        "encountered, iptables will try load a match module of the same name "
        "as the protocol, to try making the option available.' The tcp and "
        "udp --dport text came only as a search highlight, not a full fetch, "
        "and git.netfilter.org returned no content, so --dport, port ranges "
        "and service names are off"),
}


def resolve(cid: str) -> Row:
    """The cited row `cid`. A pending or unknown id raises KeyError."""
    if cid in PENDING:
        raise KeyError(f"{cid} is not cited yet: {PENDING[cid]}")
    return ROWS[cid]
