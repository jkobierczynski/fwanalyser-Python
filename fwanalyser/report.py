"""HTML report generation - the Python equivalent of `do_fwreport`.

Two deliberate improvements over the original (documented in
BUGS_AND_CHANGES.md):

  * All dynamic text (object names, comments, rule text) is HTML-escaped.
    The original interpolated these values straight into the HTML with no
    escaping at all - a comment or object name containing `<`/`&` would
    corrupt the report, and if such text ever originated from a source you
    didn't fully control it would be a stored-HTML-injection bug.
  * The subnet drill-down tree uses plain `<details>/<summary>` instead of
    the original's dependency on external `mktree.js` / `mktree.css` files
    that have to be copied alongside the report by hand. The generated
    report is a single self-contained file.
"""

from __future__ import annotations

import html
import re
from typing import List, TextIO

from .models import Policy, Rule
from .logmatch import Stats

_SPLIT_SEMI = re.compile(r"\s*;\s*")


def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _rule_list_html(raw: str) -> str:
    parts = [p for p in _SPLIT_SEMI.split(raw) if p != ""]
    return "<br>\n".join(_esc(p) for p in parts) if parts else "&nbsp;"


def _object_hits_html(counters_by_name: dict) -> str:
    lines = []
    for name in sorted(counters_by_name):
        c = counters_by_name[name]
        if c.counter != 0:
            lines.append(f"{_esc(c.entry)} [{c.counter}]")
    return "<br>\n".join(lines)


def _subnet_tree_html(subnet_counters: dict) -> str:
    if not subnet_counters:
        return ""
    items = "\n".join(
        f"<li>{_esc(subnet)} [{hit.counter}]</li>"
        for subnet, hit in sorted(
            subnet_counters.items(), key=lambda kv: _subnet_sort_key(kv[0])
        )
    )
    return f'<details><summary>Subnets</summary><ul>\n{items}\n</ul></details>'


def _subnet_sort_key(cidr: str):
    import ipaddress
    net = ipaddress.ip_network(cidr, strict=False)
    return (int(net.network_address), net.prefixlen)


def _service_hits_html(rule: Rule) -> str:
    lines: List[str] = []
    if rule.service_any is not None and rule.service_any.counter != 0:
        lines.append(f"Any [{rule.service_any.counter}]")

    seen_ids = set()
    for proto, portmap in rule.service.items():
        for port, counters in portmap.items():
            for c in counters:
                if id(c) in seen_ids:
                    continue
                seen_ids.add(id(c))
                if c.counter != 0:
                    lines.append(f"{_esc(c.entry)} [{c.counter}]")

    for itype, counters in rule.service_icmp.items():
        for c in counters:
            if id(c) in seen_ids:
                continue
            seen_ids.add(id(c))
            if c.counter != 0:
                lines.append(f"{_esc(c.entry)} [{c.counter}]")

    return "<br>\n".join(lines)


_HEAD = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Firewall Report</title>
<style>
  body { font-family: sans-serif; background: #ffffff; }
  table { border-collapse: collapse; margin: 0 auto; }
  th, td { border: 1px solid #888; padding: 4px 8px; vertical-align: top; text-align: right; }
  th { background: #b0b0b0; }
  tr.disabled { background: #c05050; }
  tr.enabled { background: #fff080; }
  caption { font-weight: bold; padding: 8px; }
  details > summary { cursor: pointer; }
</style>
</head>
<body>
<center>
"""

_TAIL = """
</center>
</body>
</html>
"""


def write_report(
    fh: TextIO,
    policy: Policy,
    stats: Stats,
    source_label: str,
) -> None:
    fh.write(_HEAD)
    fh.write(f"Matches: {stats.rulehit_counter}/{stats.log_filtered_counter}/{stats.log_counter}<br>\n")
    fh.write("<table>\n")
    fh.write(f"<caption>Firewall Report on {_esc(source_label)}</caption>\n")
    fh.write(
        "<tr><th>Rule</th><th>Source Rule</th><th>Source Hits</th>"
        "<th>Destination Rule</th><th>Destination Hits</th>"
        "<th>Service Rule</th><th>Service Hits</th><th>Action</th>"
        "<th>Firewalls</th></tr>\n"
    )

    for rule in policy.rules:
        if rule is None:
            continue

        source_result = _object_hits_html(rule.src)
        src_subnet_html = _subnet_tree_html(rule.src_subnets)
        if src_subnet_html:
            source_result = (source_result + "<br>\n" if source_result else "") + src_subnet_html

        destination_result = _object_hits_html(rule.dst)
        dst_subnet_html = _subnet_tree_html(rule.dst_subnets)
        if dst_subnet_html:
            destination_result = (destination_result + "<br>\n" if destination_result else "") + dst_subnet_html

        service_result = _service_hits_html(rule)

        row_class = "disabled" if rule.disabled else "enabled"
        fh.write(f'<tr class="{row_class}">\n')
        fh.write(f"<td>{rule.num}</td>\n")
        fh.write(f"<td>{_rule_list_html(rule.src_rule_raw)}</td>\n")
        fh.write(f"<td>{source_result}</td>\n")
        fh.write(f"<td>{_rule_list_html(rule.dst_rule_raw)}</td>\n")
        fh.write(f"<td>{destination_result}</td>\n")
        fh.write(f"<td>{_rule_list_html(rule.service_rule_raw)}</td>\n")
        fh.write(f"<td>{service_result}</td>\n")
        fh.write(f"<td>{_esc(rule.action)}</td>\n")
        fh.write(f"<td>{_rule_list_html(rule.firewalls_raw)}</td>\n")
        fh.write("</tr>\n")

    fh.write("</table>\n")
    fh.write(_TAIL)
