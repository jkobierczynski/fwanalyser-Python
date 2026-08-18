"""Reads Check Point log exports and correlates them against a parsed
policy, replicating the rule-evaluation semantics of the original
`lookup_firewall_rules` / `match_firewall_rule` / `check_subnettrie` Perl
subs.

Simplification note (see BUGS_AND_CHANGES.md): the original's
`check_subnettrie` built and cached its own little Patricia trie *per rule
per direction* purely to memoise "which aggregate subnets does this IP
belong to at each drill-down level". Tracing through what it actually
computes, it is equivalent to: for a fixed sequence of prefix lengths
(/0, /8, /16, /24, /32 with the default step of 8), bump a counter keyed by
the IP's containing network at that prefix length. `_record_subnet_hits`
below does exactly that with a plain dict - same output, far less code, and
it can't overshoot /32 the way the original's recursion theoretically could
for non-default step values (bug #4).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from .colorutil import colour
from .models import Firewall, Policy, SubnetHit

log = logging.getLogger("fwanalyser.logmatch")

IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def _clean_line(raw: str) -> str:
    return raw.split("#", 1)[0].strip()


def read_log_header(fh) -> List[str]:
    raw = fh.readline()
    line = _clean_line(raw)
    return re.split(r"\s*;\s*", line) if line else []


def iter_log_entries(fh, fields: List[str]) -> Iterator[Dict[str, str]]:
    for raw in fh:
        line = _clean_line(raw)
        if not line:
            continue
        values = re.split(r"\s*;\s*", line)
        entry = {fields[i]: (values[i] if i < len(values) else "") for i in range(len(fields))}
        yield entry


def _prefix_steps(modulo: int) -> List[int]:
    """Prefix-length drill-down levels, e.g. [0, 8, 16, 24, 32] for the
    default modulo of 8. Clamped to 32 so an unusual modulo can't overshoot
    (original bug #4)."""
    steps = []
    idx = 0
    while True:
        steps.append(idx)
        if idx >= 32:
            break
        idx = idx + modulo if idx < 28 else idx + 2
        if idx > 32:
            idx = 32
    return steps


@dataclass
class Stats:
    log_counter: int = 0
    log_filtered_counter: int = 0
    rulehit_counter: int = 0


class RuleMatcher:
    def __init__(
        self,
        fw: Firewall,
        policy: Policy,
        verbose: bool = False,
        logrule: Optional[int] = None,
        nonmatching: bool = False,
        nosubnettrie: bool = False,
        subnettrie_modulo: int = 8,
        all_covering: bool = False,
        show_progress: bool = False,
    ) -> None:
        self.fw = fw
        self.policy = policy
        self.verbose = verbose
        self.logrule = logrule
        self.nonmatching = nonmatching
        self.nosubnettrie = nosubnettrie
        self.all_covering = all_covering
        self.show_progress = show_progress
        self._prefix_step_list = _prefix_steps(subnettrie_modulo)
        self.stats = Stats()

    # ------------------------------------------------------------------ #
    def process_log_entry(self, logentry: Dict[str, str]) -> None:
        self.stats.log_counter += 1
        if self.show_progress and self.stats.log_counter % 1000 == 0:
            print(
                f"\r{self.stats.rulehit_counter}/{self.stats.log_filtered_counter}/{self.stats.log_counter}",
                end="",
            )

        orig = logentry.get("orig", "")
        if self.fw.db.firewall_policy.get(orig) != self.policy.name:
            return
        self.stats.log_filtered_counter += 1

        src_ip = logentry.get("src", "")
        dst_ip = logentry.get("dst", "")
        if not (IP_RE.search(src_ip) and IP_RE.search(dst_ip)):
            return

        for rule_num in self._lookup_candidate_rules(src_ip, dst_ip):
            if self._match_rule(rule_num, logentry):
                break

    # ------------------------------------------------------------------ #
    def _lookup_candidate_rules(self, src_ip: str, dst_ip: str) -> List[int]:
        # NOTE: this ALWAYS collects every covering prefix (all_covering=True),
        # regardless of the --all-covering flag (which only affects per-rule
        # object matching below). This is a deliberate correctness fix, not a
        # style choice - see BUGS_AND_CHANGES.md #7a.
        #
        # The global trie mixes objects of wildly different specificity across
        # *different* rules - e.g. rule 1 references a specific /16 while the
        # cleanup rule at the bottom references "Any" (0.0.0.0/0). A
        # longest-prefix-match lookup (the original's Net::Patricia-based
        # behaviour) would find only the /16 node for an IP inside it and
        # never even consider the Any/cleanup rule as a candidate - so any
        # traffic that partially matches an earlier, more specific rule (same
        # src/dst objects but wrong service) could never fall through to the
        # catch-all rule at all, silently under-reporting its hit count.
        # Every real rulebase has this shape (specific rules followed by a
        # deny-all cleanup rule), so this isn't an edge case - it would
        # misreport results on essentially any policy.
        srcsect: Dict[int, int] = {}
        for e in self.policy.src_trie.match(src_ip, all_covering=True):
            srcsect[e.rule] = 1 if e.incl == "include" else 0
        dstsect: Dict[int, int] = {}
        for e in self.policy.dst_trie.match(dst_ip, all_covering=True):
            dstsect[e.rule] = 1 if e.incl == "include" else 0
        matched = [r for r, v in srcsect.items() if v == 1 and dstsect.get(r) == 1]
        return sorted(matched)

    def _match_service(self, rule, rule_num: int, logentry: Dict[str, str]) -> bool:
        if rule.service_any is not None:
            rule.service_any.hit(rule_num)
            return True

        proto = logentry.get("proto", "")

        if proto == "icmp":
            icmp_type = logentry.get("ICMP Type", "")
            counters = rule.service_icmp.get(icmp_type)
            if counters:
                for c in counters:
                    c.hit(rule_num)
                if self.verbose or self.logrule == rule_num:
                    names = ",".join(c.entry for c in counters)
                    print(colour("cyan", f"Matched firewall rule {rule_num} Service ICMP in {names}"))
                return True
            if self.verbose or self.logrule == rule_num:
                print(f"Service ICMP type {icmp_type} is not in firewall rule {rule_num}")
            return False

        if proto in ("tcp", "udp"):
            db_map = self.fw.db.tcp if proto == "tcp" else self.fw.db.udp
            svc_name = logentry.get("service", "")
            proto_rules = rule.service.get(proto, {})

            # The original only tried resolving the log's `service` value as
            # an OBJECT NAME (via the global name->port map) before looking
            # it up in the rule's service structure. That silently fails to
            # match *any* single (non-range) TCP/UDP service whenever a log
            # export uses raw port numbers rather than resolved service
            # names in the service field - a very common CSV log export
            # setting - because no config object is normally named "80".
            # Only ranges worked at all, via the separate numeric fallback
            # below. Fixed by also trying the log value directly as a port
            # number. See BUGS_AND_CHANGES.md #1 (this is the highest-impact
            # bug found in the whole tool).
            candidate_ports = []
            resolved_port = db_map.get(svc_name)
            if resolved_port is not None:
                candidate_ports.append(resolved_port)
            if svc_name.isdigit() and svc_name not in candidate_ports:
                candidate_ports.append(svc_name)

            for port in candidate_ports:
                if port in proto_rules:
                    for c in proto_rules[port]:
                        c.hit(rule_num)
                    if self.verbose or self.logrule == rule_num:
                        print(colour("cyan", f"Service {proto}/{svc_name} is defined in firewall rule {rule_num}"))
                    return True

            # Range check. NOTE: the original compares the log's raw
            # `service` value directly as a number here (rather than
            # resolving it by name first, as the exact-match branch above
            # does) - kept as-is for fidelity; see BUGS_AND_CHANGES.md.
            range_map = rule.servicerange.get(proto, {})
            try:
                svc_num = int(svc_name)
            except ValueError:
                svc_num = None
            if svc_num is not None:
                for rng, counters in range_map.items():
                    start_s, end_s = rng.split("-", 1)
                    if int(start_s) <= svc_num <= int(end_s):
                        for c in counters:
                            c.hit(rule_num)
                        if self.verbose or self.logrule == rule_num:
                            print(colour("cyan", f"Range {proto}/{rng} is defined in firewall rule {rule_num}"))
                        return True
            if self.verbose or self.logrule == rule_num:
                print(f"Service {svc_name} is not in firewall rule {rule_num}")
            return False

        return False

    def _record_subnet_hits(self, subnet_counters: Dict[str, SubnetHit], ip: str) -> None:
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            return
        for prefixlen in self._prefix_step_list:
            net = ipaddress.IPv4Network((int(ip_obj), prefixlen), strict=False)
            key = str(net)
            hit = subnet_counters.setdefault(key, SubnetHit())
            hit.counter += 1

    def _match_rule(self, rule_num: int, logentry: Dict[str, str]) -> bool:
        rule = self.policy.rules[rule_num] if rule_num < len(self.policy.rules) else None
        if rule is None:
            return False

        if rule.disabled:
            if self.verbose or self.logrule == rule_num:
                print(colour("red", "This rule is disabled"))
            return False

        src_ip = logentry.get("src", "")
        dst_ip = logentry.get("dst", "")
        source_matched = len(rule.src_trie.match(src_ip, self.all_covering)) > 0
        destination_matched = len(rule.dst_trie.match(dst_ip, self.all_covering)) > 0

        service_matched = self._match_service(rule, rule_num, logentry)

        last_rule_num = len(self.policy.rules) - 1
        is_last_rule = rule_num == last_rule_num

        if self.nonmatching and source_matched and destination_matched and not service_matched:
            log_rule_field = logentry.get("rule", "")
            try:
                log_rule_num: Optional[int] = int(log_rule_field)
            except ValueError:
                log_rule_num = None
            if log_rule_num == rule_num and not is_last_rule:
                if rule.service_not_found is not None:
                    rule.service_not_found.counter += 1
                print(
                    f"Num={logentry.get('num','')},SRC={src_ip},DST={dst_ip},"
                    f"Proto={logentry.get('proto','')},Service={logentry.get('service','')},"
                    f"Action={logentry.get('action','')},Firewall={logentry.get('orig','')},"
                    f"Rule={log_rule_field}"
                )

        if source_matched and destination_matched and (service_matched or is_last_rule):
            self.stats.rulehit_counter += 1

            if not self.nosubnettrie:
                self._record_subnet_hits(rule.src_subnets, src_ip)
                self._record_subnet_hits(rule.dst_subnets, dst_ip)

            for e in rule.src_trie.match(src_ip, self.all_covering):
                if e["entry"] != "Any":
                    e["counter"].hit(rule_num)
            for e in rule.dst_trie.match(dst_ip, self.all_covering):
                if e["entry"] != "Any":
                    e["counter"].hit(rule_num)

            return True

        return False


def process_log_file(matcher: RuleMatcher, path: str) -> None:
    log.info("Opening log file %s", path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fields = read_log_header(fh)
        if not fields:
            log.warning("%s: empty or missing log header, skipping file", path)
            return
        for entry in iter_log_entries(fh, fields):
            matcher.process_log_entry(entry)


def process_log_dir(matcher: RuleMatcher, dirpath: str) -> None:
    log.info("Opening log directory %s", dirpath)
    for name in sorted(os.listdir(dirpath)):
        full = os.path.join(dirpath, name)
        if not os.path.isfile(full):
            continue
        process_log_file(matcher, full)
