"""
Pure-Python IPv4 binary (Patricia-style) trie used to replace Perl's
Net::Patricia in the original tool.

Behavioural note (see BUGS_AND_CHANGES.md item #7):
Net::Patricia's ``match_string`` returns only the *single longest-prefix
match* for a queried address - i.e. classic routing-table semantics, not
"all CIDR objects that happen to contain this IP". The original Perl script
relies on that behaviour throughout (global src/dst tries for candidate-rule
lookup, and per-rule src/dst tries for object-level hit counting).

This trie defaults to the same longest-prefix-match (LPM) behaviour so the
Python port produces the same counters as the Perl tool. It additionally
offers ``match_all_covering`` for anyone who wants true "IP belongs to ANY
listed object" semantics instead (see the ``--all-covering`` CLI flag).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterator, List, Optional


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


@dataclass
class _Node:
    children: List[Optional["_Node"]] = field(default_factory=lambda: [None, None])
    data: Optional[List[Any]] = None  # entries registered at this exact prefix


class IPv4Trie:
    """A minimal binary trie over 32-bit IPv4 prefixes.

    Multiple ``insert()`` calls for the *same* exact network accumulate their
    values in a list at that node - mirroring how the Perl script manually
    merged entries when a subnet string already existed in the
    ``Net::Patricia`` trie before calling ``add_string`` again.
    """

    def __init__(self) -> None:
        self._root = _Node()

    def insert(self, network: ipaddress.IPv4Network, value: Any) -> None:
        node = self._root
        net_int = int(network.network_address)
        prefixlen = network.prefixlen
        for i in range(prefixlen):
            bit = (net_int >> (31 - i)) & 1
            if node.children[bit] is None:
                node.children[bit] = _Node()
            node = node.children[bit]
        if node.data is None:
            node.data = []
        node.data.append(value)

    def insert_cidr(self, cidr: str, value: Any) -> None:
        network = ipaddress.IPv4Network(cidr, strict=False)
        self.insert(network, value)

    def _walk(self, ip: str) -> Iterator[List[Any]]:
        """Yield the ``data`` list at every prefix node on the path to ``ip``,
        from least-specific (root, /0) to most-specific, skipping empty
        nodes."""
        ip_int = ip_to_int(ip)
        node = self._root
        if node.data:
            yield node.data
        for i in range(32):
            bit = (ip_int >> (31 - i)) & 1
            nxt = node.children[bit]
            if nxt is None:
                return
            node = nxt
            if node.data:
                yield node.data

    def match_longest(self, ip: str) -> List[Any]:
        """Return the entries registered at the single longest matching
        prefix (Net::Patricia ``match_string`` semantics). Empty list if the
        address matches nothing (not even a 0.0.0.0/0 "Any" node)."""
        best: List[Any] = []
        for data in self._walk(ip):
            best = data
        return best

    def match_all_covering(self, ip: str) -> List[Any]:
        """Return entries from *every* covering prefix, root to most
        specific, concatenated. Opt-in alternative to ``match_longest``."""
        out: List[Any] = []
        for data in self._walk(ip):
            out.extend(data)
        return out

    def match(self, ip: str, all_covering: bool = False) -> List[Any]:
        return self.match_all_covering(ip) if all_covering else self.match_longest(ip)
