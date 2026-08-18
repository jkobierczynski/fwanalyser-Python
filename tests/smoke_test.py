#!/usr/bin/env python3
"""Dependency-free smoke test for the fwanalyser Python port.

Run with:  python3 tests/smoke_test.py
Exits 0 and prints "ALL TESTS PASSED" if everything checks out, otherwise
prints the failing assertion and exits 1.

Covers:
  1. End-to-end run against the synthetic fixtures, checking overall
     match/filter/log counters and per-rule/per-object hit counts.
  2. The service-group ancestor double-counting fix (the bug the original
     author flagged in a Dutch comment - see BUGS_AND_CHANGES.md).
  3. Cycle detection for circular network groups and circular service
     groups (infinite recursion in the original - never crashes here).
  4. The full CLI entry point (argument parsing -> HTML report on disk).
  5. Persistence round-trip (write a snapshot, reload it into a fresh
     parse, confirm counts double as expected).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwanalyser.policy_parser import PolicyParser
from fwanalyser.logmatch import RuleMatcher, process_log_file
from fwanalyser import persistence
from fwanalyser.cli import main as cli_main

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"  [PASS] {label}")
    else:
        msg = f"  [FAIL] {label} {detail}"
        print(msg)
        failures.append(msg)


def build_and_match():
    pparser = PolicyParser(target_policy="MainPolicy", verbose=False)
    pparser.load_fwpolicy_cfg(os.path.join(FIXTURES, "fwpolicy.cfg"))
    pparser.load_fwconfigfile(os.path.join(FIXTURES, "fwconfig.csv"))
    policy = pparser.fw.policies["MainPolicy"]
    matcher = RuleMatcher(pparser.fw, policy, nonmatching=True)
    process_log_file(matcher, os.path.join(FIXTURES, "fwlog.csv"))
    return pparser, policy, matcher


print("== 1. End-to-end fixture run ==")
pparser, policy, matcher = build_and_match()
s = matcher.stats
check("log_counter == 7", s.log_counter == 7, f"got {s.log_counter}")
check("log_filtered_counter == 6 (other-fw excluded)", s.log_filtered_counter == 6, f"got {s.log_filtered_counter}")
check("rulehit_counter == 6", s.rulehit_counter == 6, f"got {s.rulehit_counter}")

rule1 = policy.rules[1]
check("rule1 InternalNet hits == 2", rule1.src["InternalNet"].counter == 2, f"got {rule1.src['InternalNet'].counter}")
check("rule1 WebServer1 hits == 1", rule1.dst["WebServer1"].counter == 1)
check("rule1 WebServer2 hits == 1", rule1.dst["WebServer2"].counter == 1)
check("rule1 service_not_found == 1 (entry 6, port 21)", rule1.service_not_found.counter == 1,
      f"got {rule1.service_not_found.counter}")

rule2 = policy.rules[2]
check("rule2 DMZ hits == 1", rule2.dst["DMZ"].counter == 1)

rule4 = policy.rules[4]
check("rule4 (cleanup) serviceany hits == 3 (entries 4, 5, 6 fall through)", rule4.service_any.counter == 3,
      f"got {rule4.service_any.counter}")

print("\n== 2. Service-group ancestor rollup / double-counting fix ==")
http_counter = None
webservices_counter = None
for c in rule1.service["tcp"]["80"]:
    if c.entry == "HTTP":
        http_counter = c
    if c.entry == "WebServices":
        webservices_counter = c
for c in rule1.service["tcp"]["443"]:
    if c.entry == "WebServices":
        webservices_counter = c  # same object either way; re-fetch for clarity
check("HTTP leaf counter == 1", http_counter is not None and http_counter.counter == 1)
check(
    "WebServices ancestor counter == 2 (one hit per child, not duplicated per nested path)",
    webservices_counter is not None and webservices_counter.counter == 2,
    f"got {webservices_counter.counter if webservices_counter else None}",
)

print("\n== 3. Cycle detection (network group and service group) ==")
with tempfile.TemporaryDirectory() as tmp:
    cfg_path = os.path.join(tmp, "cyclic.csv")
    with open(cfg_path, "w") as fh:
        fh.write(
            "GroupA,group,GroupB\n"
            "GroupB,group,GroupA\n"          # circular network group: A -> B -> A
            "Host1,host,10.0.0.1\n"
            "GroupA,group,Host1\n"
            "SrvGroupA,srvgroup,SrvGroupB\n"
            "SrvGroupB,srvgroup,SrvGroupA\n" # circular service group: SrvGroupA -> SrvGroupB -> SrvGroupA
            "HTTP,tcp,80\n"
            "SrvGroupA,srvgroup,HTTP\n"
            "rulebase_header,CyclicPolicy\n"
            "security_rule,GroupA,Any,,SrvGroupA,accept,log,gw1,,cycle test rule\n"
        )
    pcfg_path = os.path.join(tmp, "fwpolicy.cfg")
    with open(pcfg_path, "w") as fh:
        fh.write("gw1;CyclicPolicy\n")

    try:
        cp = PolicyParser(target_policy="CyclicPolicy")
        cp.load_fwpolicy_cfg(pcfg_path)
        cp.load_fwconfigfile(cfg_path)
        cyclic_policy = cp.fw.policies["CyclicPolicy"]
        check("Cyclic config parsed without RecursionError/crash", True)
        check("Rule 1 still resolved despite the cycle", cyclic_policy.rules[1] is not None)
        check("Host1 reachable through GroupA despite the A<->B cycle", "Host1" in cyclic_policy.rules[1].src)
        check("HTTP service reachable despite the SrvGroupA<->SrvGroupB cycle",
              "80" in cyclic_policy.rules[1].service.get("tcp", {}))
    except RecursionError:
        check("Cyclic config parsed without RecursionError/crash", False, "RecursionError raised!")

print("\n== 4. Full CLI entry point ==")
with tempfile.TemporaryDirectory() as tmp:
    report_path = os.path.join(tmp, "report.html")
    old_cwd = os.getcwd()
    os.chdir(FIXTURES)  # fwpolicy.cfg default path is relative, like the original
    try:
        rc = cli_main([
            "--fwconfigfile", "fwconfig.csv",
            "--fwlogfile", "fwlog.csv",
            "--fwreportfile", report_path,
            "--fwpolicy", "MainPolicy",
            "--nonmatching",
        ])
    finally:
        os.chdir(old_cwd)
    check("CLI exits 0", rc == 0, f"got {rc}")
    check("Report file was created", os.path.isfile(report_path))
    if os.path.isfile(report_path):
        content = open(report_path, encoding="utf-8").read()
        check("Report contains rule table", "<table>" in content)
        check("Report contains WebServer1 hit label", "WebServer1" in content)
        check("Report HTML-escapes safely (no raw unescaped rule text needed here, just sanity)", "<html>" in content)

print("\n== 5. Persistence round-trip ==")
with tempfile.TemporaryDirectory() as tmp:
    snap_path = os.path.join(tmp, "snapshot.json")
    persistence.save(policy, snap_path)

    pparser2, policy2, matcher2 = build_and_match()
    persistence.load_and_merge(policy2, snap_path)
    check(
        "InternalNet counter doubles after merging a prior snapshot onto a fresh run",
        policy2.rules[1].src["InternalNet"].counter == 4,
        f"got {policy2.rules[1].src['InternalNet'].counter}",
    )

print()
if failures:
    print(f"{len(failures)} CHECK(S) FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
    sys.exit(0)
