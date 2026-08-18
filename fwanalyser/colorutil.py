"""Tiny dependency-free ANSI colour helper (replacement for Term::ANSIColor).

Colour is only emitted when verbose/debug output is requested AND stdout is
a real terminal, so piping output to a file never gets ANSI escape junk in
it (the original Perl script had no such guard).
"""

import sys

_CODES = {
    "reset": "0",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "purple": "35",
}

_ENABLED = sys.stdout.isatty()


def colour(name: str, text: str) -> str:
    if not _ENABLED or name not in _CODES:
        return text
    return f"\033[{_CODES[name]}m{text}\033[0m"
