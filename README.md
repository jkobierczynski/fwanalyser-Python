# fwanalyser (Python)

A Python 3 port of `fwanalyser.pl` - a Check Point firewall rule-usage
analyser that correlates exported traffic logs against an exported policy
to produce per-rule, per-object (source/destination/service), and
per-subnet hit counters, rendered as a single self-contained HTML report.
No commercial AlgoSec/Tufin license required; no external dependencies
required either - pure Python 3 standard library.

See `BUGS_AND_CHANGES.md` for a full list of bugs found in the original
during the port (some fixed, some intentionally preserved and documented).

## Requirements

Python 3.8+. No pip installs needed for normal use.

## Quick start

```bash
python3 fwanalyser.py \
    --fwconfigfile fwconfig.csv \
    --fwlogfile fwlog.csv \
    --fwreportfile report.html \
    --fwpolicy MainPolicy
```

Or process a whole directory of daily log exports at once:

```bash
python3 fwanalyser.py \
    --fwconfigfile fwconfig.csv \
    --fwlogdir ./logs/2026-08-18/ \
    --fwreportfile report.html \
    --fwpolicy MainPolicy
```

Run the smoke test suite (no test framework needed):

```bash
python3 tests/smoke_test.py
```

Try it against the bundled synthetic fixtures:

```bash
cd tests/fixtures
python3 ../../fwanalyser.py \
    --fwconfigfile fwconfig.csv --fwlogfile fwlog.csv \
    --fwreportfile /tmp/report.html --fwpolicy MainPolicy --nonmatching
```

## Input file formats

These match the original tool's formats exactly - if you already have a
pipeline that produces `fwconfig.csv` / `fwpolicy.cfg` / log CSVs for the
Perl version, it feeds this port unchanged.

### `--fwconfigfile` (comma-separated, `#` starts a comment)

| Row type | Columns |
|---|---|
| `Name,host,IP` | a single host object (also accepts `cpgw`, `plaingw`) |
| `Name,net,IP,Mask` | a network object; mask can be dotted (`255.255.0.0`) or a prefix length (`16`) |
| `Name,group,Member` | one line per member; repeat the line to add more members |
| `Name,exclgrp,IncludeGroup,ExcludeGroup` | "IncludeGroup minus ExcludeGroup" |
| `Name,icmp,Type` | an ICMP service by type number |
| `Name,tcp,Port` | a TCP service; `Port` can be a single port or `"start-end"` |
| `Name,udp,Port` | a UDP service |
| `Name,srvgroup,Member` | one line per member, like `group` |
| `rulebase_header,PolicyName` | starts a new policy/rulebase section; rule numbering restarts at 1 |
| `security_rule,Src,Dst,_,Service,Action,Log,Firewalls,_,Comment` | an enabled rule; `Src`/`Dst`/`Service`/`Firewalls` are `;`-separated lists, `!` prefixes an exclusion |
| `disabled_sec_rule,...` | same shape as `security_rule`, marked disabled |

Only the `rulebase_header` section matching `--fwpolicy` is loaded into
memory; other sections are skipped (but still consume rule numbers, so
numbering stays consistent with the original export).

### `--fwpolicy-cfg` (default: `fwpolicy.cfg`, semicolon-separated)

```
firewall-gateway-name;PolicyName
```

Maps each log's `orig` (originating gateway) field to the policy it should
be checked against - only log lines from a gateway mapped to `--fwpolicy`
are counted.

### `--fwlogfile` / `--fwlogdir` (semicolon-separated, header row required)

First line names the fields, e.g.:

```
num;src;dst;proto;service;ICMP Type;action;orig;rule
1;10.1.0.5;10.1.1.10;tcp;80;;accept;gw-fw1;1
```

Required fields: `src`, `dst`, `proto`, `service`, `orig`. `ICMP Type` is
used for `proto=icmp`. `rule` (the log's own recorded matching rule number)
is only used by `--nonmatching`.

## Useful flags beyond the original

- `--fwpolicy-cfg PATH` - the original hardcoded `./fwpolicy.cfg`; this is
  now a real flag (see BUGS_AND_CHANGES.md).
- `--subnettrie-modulo N` - drill-down step size for the subnet breakdown
  (existed as an unreachable internal variable in the original).
- `--all-covering` - count a hit against every object covering an IP
  within a single rule's own src/dst list, not just the most specific one.
- `--log-level {DEBUG,INFO,WARNING,ERROR}` - control diagnostic verbosity
  (cycle warnings, dropped stored counters on policy drift, etc.) separately
  from `--verbose`'s per-line trace output.

## Package layout

```
fwanalyser.py          top-level launcher (python3 fwanalyser.py ...)
fwanalyser/
  cli.py                argument parsing + orchestration (the "main program")
  models.py              data model: Firewall / NetworkDB / Policy / Rule / Counter
  iptrie.py               pure-Python IPv4 Patricia-style trie
  policy_parser.py     parses fwconfigfile + fwpolicy.cfg, resolves groups/services
  logmatch.py            reads logs, correlates against the policy, counts hits
  persistence.py         cumulative counters across runs (JSON snapshots)
  report.py               self-contained HTML report generation
  colorutil.py            tiny ANSI colour helper for --verbose output
tests/
  smoke_test.py            dependency-free end-to-end + regression tests
  fixtures/                synthetic config/policy/log files used by the tests
BUGS_AND_CHANGES.md       bugs found in the original and how this port handles them
```
