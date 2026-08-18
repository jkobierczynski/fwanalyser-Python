"""Parses the fwconfigfile CSV export and fwpolicy.cfg, and resolves the
recursive object/service graph into concrete rule-level structures.

This is the Python equivalent of the Perl subs:
    read_parameters (config-related bits), read_fwpolicy_entries,
    read_fwconfigfile_entries, process_file_* , resolve_recursive_entries,
    resolver_recursive_srv, process_file_subnets_afterwards

See BUGS_AND_CHANGES.md for the two real bugs fixed here:
  * infinite recursion on circular groups/service-groups (no cycle guard
    existed in the original at all)
  * the "Met die Array gaat hier nog een fout zitten..." bug the original
    author flagged in a Dutch comment: ancestor service-group counters could
    be registered more than once against the same leaf port/type when that
    leaf was reachable through more than one nested group path, causing a
    single matching packet to increment a group's hit counter multiple
    times. Fixed here by de-duplicating ancestor counters by identity.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional

from .models import Counter, Firewall, Policy, Rule

log = logging.getLogger("fwanalyser.policy")

_RANGE_RE = re.compile(r"^\d+-\d+$")


@dataclass
class SubnetRef:
    entry: str
    subnet: str   # CIDR string, e.g. "10.0.0.0/8"
    rule: int
    incl: str     # 'include' | 'exclude'


def _clean_line(raw: str) -> str:
    """Strip comments (everything from '#' onward) and surrounding
    whitespace, same as the Perl script's s/#.*// ; s/^\\s+// ; s/\\s+$//."""
    return raw.split("#", 1)[0].strip()


def _make_network(ip: str, mask: str) -> ipaddress.IPv4Network:
    spec = f"{ip}/{mask}" if "." in mask else f"{ip}/{int(mask)}"
    return ipaddress.ip_network(spec, strict=False)


def _subnet_sort_key(sref: SubnetRef):
    net = ipaddress.ip_network(sref.subnet, strict=False)
    return (int(net.network_address), net.prefixlen)


def _merge_unique(existing: List[Counter], ancestors: List[Counter]) -> List[Counter]:
    """Append ancestor Counters that aren't already present (by identity).

    This is the fix for the bug the original author flagged themselves (see
    module docstring): without de-duplication, a leaf service reachable via
    more than one nested service-group path would accumulate duplicate
    references to the same ancestor Counter, so a single matched packet
    would increment that ancestor's hit count more than once.
    """
    seen = {id(c) for c in existing}
    merged = list(existing)
    for c in ancestors:
        if id(c) not in seen:
            merged.append(c)
            seen.add(id(c))
    return merged


class PolicyParser:
    def __init__(self, target_policy: str, verbose: bool = False) -> None:
        self.fw = Firewall()
        self.target_policy = target_policy
        self.verbose = verbose
        self.rule_counter = 0
        self.rulebase_header: Optional[str] = None
        self.global_src_subnets: List[SubnetRef] = []
        self.global_dst_subnets: List[SubnetRef] = []

    # ------------------------------------------------------------------ #
    # fwpolicy.cfg : maps firewall (gateway) name -> policy/package name
    # ------------------------------------------------------------------ #
    def load_fwpolicy_cfg(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = _clean_line(raw)
                if not line:
                    continue
                parts = re.split(r"\s*;\s*", line)
                if len(parts) < 2:
                    log.warning("fwpolicy.cfg: skipping malformed line: %r", raw.rstrip())
                    continue
                firewall, policy = parts[0], parts[1]
                self.fw.db.firewall_policy[firewall] = policy
                if self.verbose:
                    print(f"Firewall {firewall} has policy {policy}")

    # ------------------------------------------------------------------ #
    # main object/rulebase CSV export
    # ------------------------------------------------------------------ #
    def load_fwconfigfile(self, path: str) -> None:
        db = self.fw.db
        db.nets["Any"] = "0.0.0.0/0"

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = _clean_line(raw)
                if not line:
                    continue
                entry = re.split(r"\s*,\s*", line)
                if self.verbose:
                    print("".join(f"[{f}]" for f in entry))
                self._dispatch(entry, lineno)

        self._build_global_tries()

    def _dispatch(self, entry: List[str], lineno: int) -> None:
        kind0 = entry[0] if entry else ""
        type_field = entry[1] if len(entry) > 1 else ""

        # NOTE: kept as a chain of prefix ("startswith") checks to mirror the
        # original's `$entry[1] =~ /^word/` regexes exactly, including its
        # fragility: a security_rule whose *source* field happens to start
        # with e.g. "host" would misroute here, same as in the Perl version.
        if type_field.startswith("host") or type_field.startswith("cpgw"):
            self._process_host(entry)
        elif type_field.startswith("plaingw"):
            self._process_host(entry)
        elif type_field.startswith("net"):
            self._process_net(entry, lineno)
        elif type_field.startswith("group"):
            self._process_group(entry)
        elif type_field.startswith("exclgrp"):
            self._process_exclgrp(entry)
        elif type_field.startswith("icmp"):
            self._process_icmp(entry)
        elif type_field.startswith("tcp"):
            self._process_tcp(entry)
        elif type_field.startswith("udp"):
            self._process_udp(entry)
        elif type_field.startswith("srvgroup"):
            self._process_srvgroup(entry)
        elif kind0.startswith("security_rule"):
            self._process_security_rule(entry, disabled=False, lineno=lineno)
        elif kind0.startswith("disabled_sec_rule"):
            self._process_security_rule(entry, disabled=True, lineno=lineno)
        elif kind0.startswith("rulebase_header"):
            self._process_rulebase_header(entry)
        # anything else is silently ignored, same as the original SWITCH block

    # ---- object definitions ------------------------------------------------
    def _process_host(self, entry: List[str]) -> None:
        name, ip = entry[0], entry[2]
        self.fw.db.hosts[name] = f"{ip}/32"
        if self.verbose:
            print(f"Adding host {name} with ip = {ip}")

    def _process_net(self, entry: List[str], lineno: int) -> None:
        name, ip, mask = entry[0], entry[2], entry[3]
        try:
            net = _make_network(ip, mask)
        except ValueError as exc:
            log.warning("line %d: skipping bad net definition %r: %s", lineno, entry, exc)
            return
        self.fw.db.nets[name] = str(net)
        if self.verbose:
            print(f"Adding net {name} with ip = {net}")

    def _process_group(self, entry: List[str]) -> None:
        name, member = entry[0], entry[2]
        self.fw.db.groups.setdefault(name, []).append(member)
        if self.verbose:
            print(f"Adding group {name} with items = {member}")

    def _process_exclgrp(self, entry: List[str]) -> None:
        name, include, exclude = entry[0], entry[2], entry[3]
        self.fw.db.exclgrp[name] = {"include": include, "exclude": exclude}
        if self.verbose:
            print(f"Adding exclgrp {name} with include = {include} and exclude = {exclude}")

    def _process_icmp(self, entry: List[str]) -> None:
        name, icmp_type = entry[0], entry[2]
        self.fw.db.icmp[name] = icmp_type
        if self.verbose:
            print(f"Adding icmp {name} with type = {icmp_type}")

    def _process_tcp(self, entry: List[str]) -> None:
        name, port = entry[0], entry[2]
        self.fw.db.tcp[name] = port
        if self.verbose:
            print(f"Adding tcp {name} with port = {port}")

    def _process_udp(self, entry: List[str]) -> None:
        name, port = entry[0], entry[2]
        self.fw.db.udp[name] = port
        if self.verbose:
            print(f"Adding udp {name} with port = {port}")

    def _process_srvgroup(self, entry: List[str]) -> None:
        name, member = entry[0], entry[2]
        self.fw.db.srvgroups.setdefault(name, []).append(member)
        if self.verbose:
            print(f"Adding srvgroup {name} with service = {member}")

    def _process_rulebase_header(self, entry: List[str]) -> None:
        header = entry[1] if len(entry) > 1 else ""
        self.rulebase_header = header
        self.rule_counter = 0
        if self.verbose:
            print(f"Rulebase Header = {header}")
        if header == self.target_policy:
            # Fresh Policy object each time this header is (re)encountered.
            # (Deviation from the original: Perl only replaced the tries and
            # left any previously-parsed rule entries in place if the same
            # header section appeared twice with fewer rules the second
            # time. A full reset avoids stale trailing rule data - see
            # BUGS_AND_CHANGES.md.)
            self.fw.policies[header] = Policy(name=header)

    # ---- rules ---------------------------------------------------------
    def _process_security_rule(self, entry: List[str], disabled: bool, lineno: int) -> None:
        self.rule_counter += 1
        if self.rulebase_header != self.target_policy:
            return

        if len(entry) < 10:
            log.warning(
                "line %d: security rule has only %d fields (expected 10) - "
                "missing fields will be treated as empty",
                lineno, len(entry),
            )
            entry = entry + [""] * (10 - len(entry))

        rule = Rule(
            num=self.rule_counter,
            disabled=disabled,
            src_rule_raw=entry[1],
            dst_rule_raw=entry[2],
            field3_raw=entry[3],
            service_rule_raw=entry[4],
            action=entry[5],
            log=entry[6],
            firewalls_raw=entry[7],
            field8_raw=entry[8],
            comment=entry[9],
        )

        policy = self.fw.policy(self.target_policy)
        while len(policy.rules) <= rule.num:
            policy.rules.append(None)
        policy.rules[rule.num] = rule

        if self.verbose:
            state = "disabled" if disabled else "enabled"
            print(f"Security Rule {rule.num} ({state})")

        # ---- source ----
        src_names = [s for s in re.split(r"\s*;\s*", entry[1]) if s != ""]
        rule_src_subnets: List[SubnetRef] = []
        self._resolve_recursive_entries(rule_src_subnets, self.global_src_subnets, rule.src, src_names, "include", frozenset())
        for sref in self._dedup_by_entry(rule_src_subnets):
            counter = rule.src.setdefault(sref.entry, Counter(entry=sref.entry))
            rule.src[sref.entry] = counter
            rule.src_trie.insert_cidr(sref.subnet, {"entry": sref.entry, "incl": sref.incl, "counter": counter})

        # ---- destination ----
        dst_names = [s for s in re.split(r"\s*;\s*", entry[2]) if s != ""]
        rule_dst_subnets: List[SubnetRef] = []
        self._resolve_recursive_entries(rule_dst_subnets, self.global_dst_subnets, rule.dst, dst_names, "include", frozenset())
        for sref in self._dedup_by_entry(rule_dst_subnets):
            counter = rule.dst.setdefault(sref.entry, Counter(entry=sref.entry))
            rule.dst[sref.entry] = counter
            rule.dst_trie.insert_cidr(sref.subnet, {"entry": sref.entry, "incl": sref.incl, "counter": counter})

        # ---- services ----
        services = [s for s in re.split(r"\s*;\s*", entry[4]) if s != ""]
        for srv in services:
            self._resolve_recursive_srv(rule, srv, [], frozenset())

    @staticmethod
    def _dedup_by_entry(subnets: List[SubnetRef]) -> List[SubnetRef]:
        ordered = sorted(subnets, key=_subnet_sort_key)
        seen = set()
        out = []
        for sref in ordered:
            if sref.entry in seen:
                continue
            seen.add(sref.entry)
            out.append(sref)
        return out

    # ---- recursive network object resolution ---------------------------
    def _resolve_recursive_entries(
        self,
        rule_subnets: List[SubnetRef],
        global_subnets: List[SubnetRef],
        ref: Dict[str, Counter],
        entries: List[str],
        incl: str,
        path: FrozenSet[str],
    ) -> None:
        db = self.fw.db
        for raw in entries:
            e = raw
            local_incl = incl
            if e.startswith("!"):
                e = e[1:]
                local_incl = "exclude"
            if not e:
                continue

            if e == "Any":
                sref = SubnetRef("Any", "0.0.0.0/0", self.rule_counter, local_incl)
                global_subnets.append(sref)
                rule_subnets.append(sref)
                ref.setdefault("Any", Counter(entry="Any"))

            subnet = db.hosts.get(e)
            if subnet is not None:
                sref = SubnetRef(e, subnet, self.rule_counter, local_incl)
                global_subnets.append(sref)
                rule_subnets.append(sref)
                ref.setdefault(e, Counter(entry=e))

            subnet = db.nets.get(e)
            if subnet is not None:
                sref = SubnetRef(e, subnet, self.rule_counter, local_incl)
                global_subnets.append(sref)
                rule_subnets.append(sref)
                ref.setdefault(e, Counter(entry=e))

            excl = db.exclgrp.get(e)
            if excl is not None:
                if e in path:
                    log.warning(
                        "Cycle detected at exclusion group %r while resolving rule %d - "
                        "skipping to avoid infinite recursion", e, self.rule_counter,
                    )
                else:
                    new_path = path | {e}
                    inc_name, exc_name = excl["include"], excl["exclude"]
                    if local_incl == "include":
                        if inc_name == "Any":
                            self._resolve_recursive_entries(rule_subnets, global_subnets, ref, ["Any"], "include", new_path)
                        else:
                            self._resolve_recursive_entries(
                                rule_subnets, global_subnets, ref, db.groups.get(inc_name, []), "include", new_path
                            )
                        self._resolve_recursive_entries(
                            rule_subnets, global_subnets, ref, db.groups.get(exc_name, []), "exclude", new_path
                        )
                    else:
                        self._resolve_recursive_entries(
                            rule_subnets, global_subnets, ref, db.groups.get(inc_name, []), "exclude", new_path
                        )
                        self._resolve_recursive_entries(
                            rule_subnets, global_subnets, ref, db.groups.get(exc_name, []), "include", new_path
                        )

            grp = db.groups.get(e)
            if grp is not None:
                if e in path:
                    log.warning(
                        "Cycle detected at group %r while resolving rule %d - "
                        "skipping to avoid infinite recursion", e, self.rule_counter,
                    )
                else:
                    self._resolve_recursive_entries(rule_subnets, global_subnets, ref, grp, local_incl, path | {e})

    # ---- recursive service object resolution ----------------------------
    def _resolve_recursive_srv(self, rule: Rule, srv: str, ancestor_stack: List[Counter], path: FrozenSet[str]) -> None:
        db = self.fw.db
        my_counter = Counter(entry=srv)
        stack = [my_counter] + list(ancestor_stack)

        if srv == "Any":
            rule.service_any = Counter(entry="Any")
        rule.service_not_found = Counter(entry="Service not found")

        children = db.srvgroups.get(srv)
        if children:
            if srv in path:
                log.warning(
                    "Cycle detected at service group %r while resolving rule %d - "
                    "skipping to avoid infinite recursion", srv, rule.num,
                )
            else:
                for child in children:
                    self._resolve_recursive_srv(rule, child, stack, path | {srv})

        if srv in db.icmp:
            icmp_type = db.icmp[srv]
            existing = rule.service_icmp.setdefault(icmp_type, [my_counter])
            rule.service_icmp[icmp_type] = _merge_unique(existing, ancestor_stack)
            if self.verbose:
                print(f"Register service {srv}=icmp/{icmp_type}")

        elif srv in db.tcp:
            port = db.tcp[srv]
            proto_map = rule.service.setdefault("tcp", {})
            existing = proto_map.setdefault(port, [my_counter])
            proto_map[port] = _merge_unique(existing, ancestor_stack)
            if _RANGE_RE.match(port):
                range_map = rule.servicerange.setdefault("tcp", {})
                r_existing = range_map.setdefault(port, [my_counter])
                range_map[port] = _merge_unique(r_existing, ancestor_stack)
            if self.verbose:
                print(f"Register service {srv}=tcp/{port}")

        elif srv in db.udp:
            port = db.udp[srv]
            proto_map = rule.service.setdefault("udp", {})
            existing = proto_map.setdefault(port, [my_counter])
            proto_map[port] = _merge_unique(existing, ancestor_stack)
            if _RANGE_RE.match(port):
                range_map = rule.servicerange.setdefault("udp", {})
                r_existing = range_map.setdefault(port, [my_counter])
                range_map[port] = _merge_unique(r_existing, ancestor_stack)
            if self.verbose:
                print(f"Register service {srv}=udp/{port}")

        elif srv not in db.srvgroups and srv != "Any":
            log.debug("Rule %d: service %r not found in object database", rule.num, srv)

    # ---- global (whole-policy) tries used for fast candidate-rule lookup --
    def _build_global_tries(self) -> None:
        policy = self.fw.policies.get(self.target_policy)
        if policy is None:
            log.warning(
                "No rulebase_header matching policy %r was found in the config file - "
                "no rules were loaded.", self.target_policy,
            )
            return
        for sref in sorted(self.global_src_subnets, key=_subnet_sort_key):
            policy.src_trie.insert_cidr(sref.subnet, sref)
        for sref in sorted(self.global_dst_subnets, key=_subnet_sort_key):
            policy.dst_trie.insert_cidr(sref.subnet, sref)
