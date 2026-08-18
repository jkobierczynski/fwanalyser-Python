"""Command-line entry point - equivalent of the Perl script's
`read_parameters` + "Main Program" section."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List, Optional

from .logmatch import RuleMatcher, process_log_dir, process_log_file
from .persistence import load_and_merge, save
from .policy_parser import PolicyParser
from .report import write_report

log = logging.getLogger("fwanalyser.cli")

_ENV_MAPPING = {
    "fwconfigfile": "FWANALYSER_FWCONFIGFILE",
    "fwlogfile": "FWANALYSER_FWLOGFILE",
    "fwlogdir": "FWANALYSER_FWLOGDIR",
    "fwreportfile": "FWANALYSER_FWREPORTFILE",
    "fwpolicy": "FWANALYSER_FWPOLICY",
    "fwdataread": "FWANALYSER_FWDATAREAD",
    "fwdatawrite": "FWANALYSER_FWDATAWRITE",
    "logrule": "FWANALYSER_LOGRULE",
}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fwanalyser",
        description="Check Point firewall rule-usage analyser (Python port of fwanalyser.pl). "
                     "For those who don't want to spend $$$$ on analysers.",
    )
    p.add_argument("-e", "--use-env", action="store_true",
                    help="Take defaults from FWANALYSER_* environment variables "
                         "(any flag given explicitly on the command line still wins)")
    p.add_argument("--verbose", action="store_true", help="Verbose trace output")
    p.add_argument("--counter", action="store_true", help="Show a running match counter while processing logs")
    p.add_argument("--nonmatching", action="store_true",
                    help="Report log lines whose src/dst matched a rule but no service did")
    p.add_argument("--nosubnettrie", action="store_true",
                    help="Skip the per-object subnet drill-down counters (much faster on large logs)")
    p.add_argument("--logrule", type=int, default=None,
                    help="Verbosely trace evaluation of this rule number only")
    p.add_argument("--fwconfigfile", help="Config/rulebase CSV export to import")
    p.add_argument("--fwlogfile", help="Single CSV log file to import")
    p.add_argument("--fwlogdir", help="Directory of CSV log files to import")
    p.add_argument("--fwreportfile", help="HTML report output path")
    p.add_argument("--fwpolicy", help="Name of the rulebase_header / policy to analyse")
    p.add_argument("--fwpolicy-cfg", default=None,
                    help="Path to the firewall->policy mapping file "
                         "(hardcoded as ./fwpolicy.cfg in the original script; default: fwpolicy.cfg)")
    p.add_argument("--fwdataread", help="Read cumulative counters from this JSON snapshot before processing logs")
    p.add_argument("--fwdatawrite", help="Write cumulative counters to this JSON snapshot after processing logs")
    p.add_argument("--subnettrie-modulo", type=int, default=8,
                    help="Prefix-length step size for the subnet drill-down report "
                         "(a real variable in the original but never exposed as a flag)")
    p.add_argument("--all-covering", action="store_true",
                    help="Count a hit against EVERY object whose subnet covers the IP, not just the most "
                         "specific one (changes behaviour vs. the original - see BUGS_AND_CHANGES.md #7)")
    p.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def apply_env_defaults(args: argparse.Namespace) -> None:
    if not args.use_env:
        return
    for attr, envvar in _ENV_MAPPING.items():
        if getattr(args, attr) is None and envvar in os.environ:
            value = os.environ[envvar]
            if attr == "logrule":
                try:
                    value = int(value)
                except ValueError:
                    log.warning("%s=%r is not a valid integer, ignoring", envvar, value)
                    continue
            setattr(args, attr, value)


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_env_defaults(args)
    if args.fwpolicy_cfg is None:
        args.fwpolicy_cfg = "fwpolicy.cfg"

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        format="%(levelname)s %(name)s: %(message)s",
    )

    missing = [n for n in ("fwconfigfile", "fwreportfile", "fwpolicy") if getattr(args, n) is None]
    no_log_source = args.fwlogfile is None and args.fwlogdir is None
    if missing or no_log_source:
        parser.print_help()
        if missing:
            print(f"\nMissing required arguments: {', '.join('--' + m for m in missing)}", file=sys.stderr)
        if no_log_source:
            print("\nOne of --fwlogfile or --fwlogdir is required", file=sys.stderr)
        return 1

    pparser = PolicyParser(target_policy=args.fwpolicy, verbose=args.verbose)
    try:
        pparser.load_fwpolicy_cfg(args.fwpolicy_cfg)
    except FileNotFoundError:
        print(f"Cannot open firewall->policy mapping file {args.fwpolicy_cfg!r}", file=sys.stderr)
        return 1

    try:
        pparser.load_fwconfigfile(args.fwconfigfile)
    except FileNotFoundError:
        print(f"Cannot open {args.fwconfigfile!r}", file=sys.stderr)
        return 1

    fw = pparser.fw
    policy = fw.policies.get(args.fwpolicy)
    if policy is None or len(policy.rules) <= 1:
        print(
            f"No rules found for policy {args.fwpolicy!r} in {args.fwconfigfile!r} "
            "(check that a matching 'rulebase_header' line exists)",
            file=sys.stderr,
        )
        return 1

    if args.fwdataread:
        try:
            load_and_merge(policy, args.fwdataread)
        except FileNotFoundError:
            print(f"Warning: --fwdataread file {args.fwdataread!r} not found, starting from zero", file=sys.stderr)

    matcher = RuleMatcher(
        fw=fw,
        policy=policy,
        verbose=args.verbose,
        logrule=args.logrule,
        nonmatching=args.nonmatching,
        nosubnettrie=args.nosubnettrie,
        subnettrie_modulo=args.subnettrie_modulo,
        all_covering=args.all_covering,
        show_progress=args.counter,
    )

    if args.fwlogdir:
        process_log_dir(matcher, args.fwlogdir)
    else:
        try:
            process_log_file(matcher, args.fwlogfile)
        except FileNotFoundError:
            print(f"Cannot open {args.fwlogfile!r}", file=sys.stderr)
            return 1

    if args.counter:
        print()

    with open(args.fwreportfile, "w", encoding="utf-8") as fh:
        write_report(fh, policy, matcher.stats, source_label=args.fwlogdir or args.fwlogfile or "")

    if args.fwdatawrite:
        save(policy, args.fwdatawrite)

    print(f"Matches: {matcher.stats.rulehit_counter}/{matcher.stats.log_filtered_counter}/{matcher.stats.log_counter}")
    print(f"Reporting to {args.fwreportfile} ended.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
