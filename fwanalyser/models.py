"""Data model for the parsed Check Point object database and rulebase.

Structure intentionally mirrors the Perl script's `$fw` hash-of-hashes
closely (see BUGS_AND_CHANGES.md) so the porting logic is easy to audit
line-by-line against the original, while giving every piece of state an
explicit home instead of Perl's implicit globals.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .iptrie import IPv4Trie

_log = logging.getLogger("fwanalyser.models")


@dataclass
class Counter:
    """Equivalent of the Perl `{ entry => ..., counter => 0 }` hashrefs.

    `rulenr` mirrors the original's "ERROR refcounter Rule" sanity check: a
    given Counter should only ever be incremented while evaluating the rule
    it was created for. The original script called `exit(1)` on mismatch;
    that's too fragile for a general-purpose port (a data quirk we didn't
    anticipate would kill the whole run), so this logs a warning and keeps
    going instead.
    """

    entry: str
    counter: int = 0
    rulenr: Optional[int] = None

    def hit(self, rule_num: int) -> None:
        if self.rulenr is not None and self.rulenr != rule_num:
            _log.warning(
                "refcounter integrity check: Counter for %r was hit by rule %s "
                "but was first registered under rule %s (counting anyway)",
                self.entry, rule_num, self.rulenr,
            )
        self.counter += 1
        self.rulenr = rule_num


@dataclass
class NetworkDB:
    """The resolved object database (hosts, nets, groups, services...)."""

    hosts: Dict[str, str] = field(default_factory=dict)     # name -> "ip/32"
    nets: Dict[str, str] = field(default_factory=dict)      # name -> "ip/mask"
    groups: Dict[str, List[str]] = field(default_factory=dict)
    exclgrp: Dict[str, Dict[str, str]] = field(default_factory=dict)  # name -> {include, exclude}
    icmp: Dict[str, str] = field(default_factory=dict)      # name -> icmp type
    tcp: Dict[str, str] = field(default_factory=dict)       # name -> port or "start-end"
    udp: Dict[str, str] = field(default_factory=dict)       # name -> port or "start-end"
    srvgroups: Dict[str, List[str]] = field(default_factory=dict)
    firewall_policy: Dict[str, str] = field(default_factory=dict)  # firewall name -> policy name

    def subnet_for(self, name: str) -> Optional[str]:
        if name == "Any":
            return "0.0.0.0/0"
        if name in self.hosts:
            return self.hosts[name]
        if name in self.nets:
            return self.nets[name]
        return None


@dataclass
class SubnetHit:
    counter: int = 0


@dataclass
class Rule:
    num: int
    disabled: bool = False

    # raw (pre-resolution) rulebase text, kept for reporting
    src_rule_raw: str = ""
    dst_rule_raw: str = ""
    service_rule_raw: str = ""
    action: str = ""
    log: str = ""
    firewalls_raw: str = ""
    comment: str = ""
    field3_raw: str = ""   # entry[3] in the original CSV - meaning not documented upstream
    field8_raw: str = ""   # entry[8] in the original CSV - meaning not documented upstream

    # resolved object-level hit counters, keyed by object name
    src: Dict[str, Counter] = field(default_factory=dict)
    dst: Dict[str, Counter] = field(default_factory=dict)

    # per-rule tries used to test "does this src/dst IP belong to this rule"
    src_trie: IPv4Trie = field(default_factory=IPv4Trie)
    dst_trie: IPv4Trie = field(default_factory=IPv4Trie)

    # service matching structures
    service: Dict[str, Dict[str, List[Counter]]] = field(default_factory=dict)       # [proto][port_or_range] -> [Counter,...]
    servicerange: Dict[str, Dict[str, List[Counter]]] = field(default_factory=dict)  # [proto][range] -> [Counter,...]
    service_icmp: Dict[str, List[Counter]] = field(default_factory=dict)             # [icmp_type] -> [Counter,...]
    service_any: Optional[Counter] = None
    service_not_found: Optional[Counter] = None

    # subnet-drilldown hit counters (Algosec-style utilization heatmap)
    src_subnets: Dict[str, SubnetHit] = field(default_factory=dict)
    dst_subnets: Dict[str, SubnetHit] = field(default_factory=dict)


@dataclass
class Policy:
    name: str
    rules: List[Optional[Rule]] = field(default_factory=lambda: [None])  # index 0 unused, rules start at 1
    src_trie: IPv4Trie = field(default_factory=IPv4Trie)   # global: ip -> candidate rule numbers
    dst_trie: IPv4Trie = field(default_factory=IPv4Trie)


@dataclass
class Firewall:
    """Top-level container - the Python equivalent of the Perl `$fw` hashref."""

    db: NetworkDB = field(default_factory=NetworkDB)
    policies: Dict[str, Policy] = field(default_factory=dict)

    def policy(self, name: str) -> Policy:
        if name not in self.policies:
            self.policies[name] = Policy(name=name)
        return self.policies[name]
