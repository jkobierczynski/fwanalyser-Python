#!/usr/bin/env python3
"""Top-level launcher so the tool can be run as `python3 fwanalyser.py ...`
without installing the package, mirroring how the original `fwanalyser.pl`
was invoked directly."""
import sys

from fwanalyser.cli import main

if __name__ == "__main__":
    sys.exit(main())
