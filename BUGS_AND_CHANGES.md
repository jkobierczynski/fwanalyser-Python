# Bugs found in `fwanalyser.pl`, and how this port handles them

This is a faithful, structural port of the original Perl tool: same CSV
config format, same log format, same rule-evaluation order, same report
layout. Everything below was found by reading the original line-by-line
*and* by writing a synthetic policy/log fixture and comparing the ported
tool's behaviour against a hand-traced expectation (`tests/smoke_test.py`) -
two of the four "critical" bugs below were only caught because the faithful
first-draft port reproduced them and the test failed.

No external dependencies were needed to port this - the whole thing runs on
the Python 3 standard library (`ipaddress`, `dataclasses`, `argparse`,
`json`). No `Net::Patricia`, no `NetAddr::IP`, no `Storable`, no CPAN at
all. If you outgrow the pure-Python trie's performance on very large log
volumes, swapping it for `pytricia` (a near-identical C-extension port of
the same Patricia trie algorithm) is a contained, optional change - see
"Performance" at the bottom.

## Critical - these silently changed reported hit counts

### 1. Single-port TCP/UDP services never matched against numeric-style logs
The exact-match branch resolved the log's `service` field as an **object
name** (`$fw->{service}{proto}{$logentry->{service}}`) before using it to
look up the rule's service structure. That only works if your log export
puts resolved service *names* (`http`) in the service field. Many CSV log
exports instead put the raw **port number** (`80`) in that field - and
since no config object is normally literally named "80", the lookup always
missed. The *range* fallback a few lines down compares the log value
directly as a **number**, so multi-port ranges still worked, but any rule
whose service list referenced a single named port object (`HTTP` → tcp/80)
would report **zero hits, always**, with numeric-style logs - probably the
single highest-impact bug in the tool, since single ports are the common
case and ranges are the exception.

**Fix**: `logmatch.py::_match_service` tries the log value both ways - as
an object name *and*, if it's numeric, as a literal port - before falling
through to the range check.

### 2. Catch-all/cleanup rules could be silently excluded as match candidates
`Net::Patricia::match_string` (confirmed via CPAN docs) only ever returns
the **single most specific** covering entry, not every prefix that covers
the address. The global src/dst tries mix objects from every rule
together, so for an IP that falls inside both a specific object (e.g. a
rule's `/16` network) *and* a broader one referenced by a later rule (e.g.
"Any" on the closing cleanup rule), the lookup would only ever return the
more specific rule as a candidate - the cleanup rule would never even be
considered, regardless of whether the specific rule's service actually
matched. Since nearly every real Check Point policy ends with a deny-all
cleanup rule, this would misreport hit counts on that rule (and mask
service-mismatches on earlier rules) in a large fraction of real policies.

**Fix**: `logmatch.py::_lookup_candidate_rules` always walks *every*
covering prefix in the global trie, not just the longest. (Per-rule
object-level matching, a narrower and more debatable case, keeps the
original's longest-prefix-only behaviour by default - see `--all-covering`
below.)

### 3. Ancestor service-group counters could be double-counted
The original author flagged this themselves, in Dutch, in a comment that's
easy to miss:

> *"Met die Array gaat hier nog een fout zitten, die tellers van de
> inherenteerde groepen worden niet voor de entries in elke rule
> gecombineerd tot gezamelijke tellers... dit moet nog verbeterd worden."*
> ("There's still a bug with that array - the counters of inherited groups
> aren't combined into shared counters for the entries in each rule... this
> still needs improving.")

When a leaf service (say, `tcp/80`) is reachable through more than one
nested service-group path within the same rule, the parent group's counter
object got appended into the match-list multiple times - so a single
matched packet could increment that parent group's hit count more than
once.

**Fix**: `policy_parser.py::_merge_unique` de-duplicates ancestor counters
by identity before they're wired into the match structures, so each
ancestor is incremented at most once per packet regardless of how many
paths reach it.

### 4. `-fwdataread` could silently discard the current run's freshly-parsed rulebase
`open_read_persistent_dbnew()` does `$fw = retrieve($file)` - a **wholesale
replace** of the in-memory object graph, not a counter merge. The main
program calls it once *before* parsing the current config, and then calls
it **again after** the current run has freshly parsed `-fwconfigfile` -
which throws away the just-parsed rulebase and substitutes whatever was
saved on a previous run. If the underlying Check Point policy changed
between collection runs (rules added/removed/reordered - normal over time
for a real firewall), the report would silently be built against a stale,
no-longer-accurate rulebase. There are two functions in the file,
`write_dbreport`/`read_dbreport`, that look like the *intended*
name-matched incremental-merge design - but every call site for them is
commented out, so they're dead code.

**Fix**: `persistence.py` always parses the current policy fresh and only
*merges* historical counters onto it by rule number + object/service name,
logging a warning and skipping anything that no longer matches instead of
silently reverting to old data. Snapshots are plain JSON, not a
Perl-specific serialization, so they're portable and diffable.

## Robustness - crash risks in the original

### 5. No cycle detection on group / service-group recursion
`resolve_recursive_entries` and `resolver_recursive_srv` recurse into
nested groups with no guard against a group (directly or indirectly)
containing itself. A circular reference - unusual, but entirely possible
from a bad export or a manual edit - causes unbounded recursion and crashes
the whole run partway through, discarding all progress.

**Fix**: both recursive resolvers in `policy_parser.py` track the set of
group/service-group names currently being expanded on the current path;
hitting a name already on that path logs a warning and skips it instead of
recursing forever. Verified in `tests/smoke_test.py` §3 with a deliberately
circular network group and service group.

### 6. Subnet drill-down step could overshoot /32
`check_subnettrie`'s prefix-length stepping (`$prm_subnettrie_modulo`,
default 8) increments by `+2` once it passes /28, but nothing clamped the
result to 32 - for a non-default modulo the step could jump past 32 and
recurse forever or produce a nonsensical "negative-width" network. This was
latent in the original (the variable existed but was never wired up to a
CLI flag, so it could never actually be changed), but the port *does*
expose `--subnettrie-modulo` as a real flag, so the clamp is a real
necessity here, not just defensive style.

**Fix**: `logmatch.py::_prefix_steps` clamps to 32.

### 7. Malformed CSV rows failed silently
A `security_rule` line with fewer than the expected 10 fields just read
`undef` into the missing ones with no diagnostic anywhere.

**Fix**: the Python port logs a warning identifying the line number and
pads with empty strings, so a truncated export is visible in the logs
instead of silently producing blank rule text.

## Preserved-but-documented quirks (not changed)

These are real oddities, but changing them would alter what counts as a
match in ways that could quietly diverge from an existing baseline of
reports - so they're kept exactly as the original behaved, and just
documented here:

- **Net::Patricia longest-prefix-match semantics for per-rule object
  matching.** Unlike the *global* candidate lookup (bug #2, which is always
  wrong and was fixed), a single rule's own src/dst list overlapping itself
  (e.g. both a supernet and a more specific subnet object in the same
  rule) is a much rarer, more debatable case. The port keeps
  longest-prefix-match here by default for fidelity, and adds an opt-in
  `--all-covering` flag if you want "hit counts against every object that
  covers the IP" instead.
- **The exact-match vs. range-match asymmetry** in service matching (exact
  match resolves the log value by name first; range match compares it
  directly as a number) is preserved as-is beyond the fix in bug #1 above -
  i.e. the range branch still only does a raw numeric comparison.
- **CSV row "type" is inferred by a `startswith` check** on a column value
  (`entry[1] =~ /^host/` etc.) rather than a dedicated type/format marker.
  A rule whose raw source field happens to start with a reserved keyword
  would misroute - preserved because the input format itself defines this
  convention and it isn't this tool's place to reinterpret it.
- **Object-name dedup ordering** when the same object is reachable via two
  different include/exclude paths (through overlapping groups) picks
  whichever sorts first by subnet address - an inherent ambiguity in the
  original design, not resolved either way here.
- **No real CSV quoting/escaping** - fields are split on `,`/`;` with
  optional surrounding whitespace, and `#` starts a comment anywhere
  (including inside a value). Same limitation as the original; changing it
  could reinterpret existing exports differently.

## Cosmetic

- **Verbose-mode SET/NOT SET printer was dead due to Perl operator
  precedence**: `print " X = ".$prm_verbose?("SET\n"):("NOT SET\n");` -
  `.` binds tighter than `?:`, so this always printed `" X = <value>"` and
  silently discarded the ternary. Diagnostic-only impact. Fixed with an
  explicit conditional in the Python CLI.
- **Dead branch in the HTML report** for TCP/UDP ranges: it checked
  `servicerange{$proto}{$service}` but `servicerange` is actually keyed
  `{proto}{range}{"start-end"}`, so that key never matched and ranges fell
  through to the normal per-service formatting - the counts were still
  correct, just not specially labelled as ranges.
- **Report depended on external `mktree.js`/`mktree.css`** that had to be
  copied alongside the HTML output by hand and aren't included anywhere in
  the original tool. Replaced with native `<details>/<summary>` - the
  generated report is fully self-contained, single-file, and does not
  require any assets.
- **No HTML-escaping** of object names/comments/rule text in the report -
  a `<` or `&` in an exported object name would corrupt the rendered
  output. Fixed: everything interpolated into the report goes through
  `html.escape`.
- **Hardcoded `fwpolicy.cfg` filename**, opened literally by name in the
  current directory regardless of any other flag. Exposed as
  `--fwpolicy-cfg` (default: `fwpolicy.cfg`, same as before) so it can live
  wherever you keep the rest of your input files.

## Performance

The original built its own Patricia tries in C (via the `Net::Patricia`
XS module) for a reason - large log volumes. This port's `IPv4Trie`
(`iptrie.py`) is pure Python: correct and reasonably fast (O(32) per
lookup, same as the original), but a C extension will still out-run it on
very large inputs. If you need to process tens of millions of log lines,
the cleanest upgrade path is dropping in `pytricia` (a maintained,
near-exact Python port of the same Patricia trie algorithm) behind
`IPv4Trie`'s existing interface - `insert_cidr` / `match_longest` /
`match_all_covering` - without touching anything else in the codebase.
