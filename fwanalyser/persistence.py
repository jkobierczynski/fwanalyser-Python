"""Cumulative counter persistence (the -fwdataread / -fwdatawrite feature).

Important behavioural fix vs. the original (see BUGS_AND_CHANGES.md #9):
in the Perl script, `-fwdataread` triggers `open_read_persistent_dbnew()`,
which does a *wholesale* `$fw = retrieve($file)` - it doesn't merge counts,
it replaces the entire in-memory object graph. Worse, the main program
calls this a second time *after* the current run has already freshly parsed
the rulebase from `-fwconfigfile`, which throws the freshly parsed rules
away and silently substitutes whatever was saved in a previous run. If the
underlying Check Point policy changed between collection runs (rules
added/removed/reordered - completely normal over time), the report would
silently be built against a stale, no-longer-accurate rulebase.

The two counter-merge functions that look like they were meant to do this
properly (`write_dbreport` / `read_dbreport`, matching stored data to the
current rulebase by rule number + object name and *adding* the counts) are
present in the file but commented out at every call site - dead code that
was seemingly the intended design before being swapped for the blunter
Storable dump/restore.

This module implements what those dead functions were going for: always
parse the current policy fresh, then *merge* historical counts onto it by
name, skipping (with a warning) anything that no longer matches - so a
changed policy degrades gracefully instead of silently reporting stale
data. Snapshots are plain JSON rather than a Perl-specific serialization
format, so they're portable and human-inspectable.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from .models import Policy, SubnetHit

log = logging.getLogger("fwanalyser.persistence")


def snapshot_policy(policy: Policy) -> Dict[str, Any]:
    data: Dict[str, Any] = {"policy": policy.name, "rules": {}}
    for rule in policy.rules:
        if rule is None:
            continue
        data["rules"][str(rule.num)] = {
            "src": {name: c.counter for name, c in rule.src.items()},
            "dst": {name: c.counter for name, c in rule.dst.items()},
            "service": {
                proto: {port: [[c.entry, c.counter] for c in counters] for port, counters in portmap.items()}
                for proto, portmap in rule.service.items()
            },
            "service_icmp": {
                itype: [[c.entry, c.counter] for c in counters]
                for itype, counters in rule.service_icmp.items()
            },
            "service_any": rule.service_any.counter if rule.service_any else None,
            "service_not_found": rule.service_not_found.counter if rule.service_not_found else None,
            "src_subnets": {k: v.counter for k, v in rule.src_subnets.items()},
            "dst_subnets": {k: v.counter for k, v in rule.dst_subnets.items()},
        }
    return data


def save(policy: Policy, path: str) -> None:
    snap = snapshot_policy(policy)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1, sort_keys=True)
    log.info("Wrote cumulative counter snapshot to %s", path)


def load_and_merge(policy: Policy, path: str) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        snap = json.load(fh)

    if snap.get("policy") and snap["policy"] != policy.name:
        log.warning(
            "Stored data was collected for policy %r, current run is for %r - merging anyway",
            snap["policy"], policy.name,
        )

    for rule_key, rd in snap.get("rules", {}).items():
        rule_num = int(rule_key)
        if rule_num >= len(policy.rules) or policy.rules[rule_num] is None:
            log.warning(
                "Stored data references rule %d which no longer exists in the current "
                "policy - dropping its stored counts", rule_num,
            )
            continue
        rule = policy.rules[rule_num]

        for name, count in rd.get("src", {}).items():
            if name in rule.src:
                rule.src[name].counter += count
            else:
                log.warning(
                    "Rule %d: stored source object %r no longer exists - dropping %d stored hits",
                    rule_num, name, count,
                )

        for name, count in rd.get("dst", {}).items():
            if name in rule.dst:
                rule.dst[name].counter += count
            else:
                log.warning(
                    "Rule %d: stored destination object %r no longer exists - dropping %d stored hits",
                    rule_num, name, count,
                )

        for proto, portmap in rd.get("service", {}).items():
            cur_portmap = rule.service.get(proto, {})
            for port, entries in portmap.items():
                counters = cur_portmap.get(port)
                if not counters:
                    continue
                by_name = {c.entry: c for c in counters}
                for entry_name, count in entries:
                    if entry_name in by_name:
                        by_name[entry_name].counter += count

        for itype, entries in rd.get("service_icmp", {}).items():
            counters = rule.service_icmp.get(itype)
            if not counters:
                continue
            by_name = {c.entry: c for c in counters}
            for entry_name, count in entries:
                if entry_name in by_name:
                    by_name[entry_name].counter += count

        if rd.get("service_any") and rule.service_any:
            rule.service_any.counter += rd["service_any"]
        if rd.get("service_not_found") and rule.service_not_found:
            rule.service_not_found.counter += rd["service_not_found"]

        for key, count in rd.get("src_subnets", {}).items():
            hit = rule.src_subnets.setdefault(key, SubnetHit())
            hit.counter += count
        for key, count in rd.get("dst_subnets", {}).items():
            hit = rule.dst_subnets.setdefault(key, SubnetHit())
            hit.counter += count

    log.info("Merged cumulative counters from %s", path)
