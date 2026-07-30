"""Network preflight helpers.

The DNS check queries the CLUSTER's own DNS servers (network.dns), not the
operator's system resolver: with split-horizon DNS the two disagree, and it is
the cluster's view that decides whether <tenant>.<domain> reaches the LB. That is
exactly the failure that only shows up hours into a deploy otherwise.

dnspython is lazy-imported so modules that never do a DNS check still load
without it.
"""

from __future__ import annotations

import socket


def resolve_via(hostname: str, servers: list[str], timeout: float = 5.0) -> set[str]:
    """Resolve A records for `hostname` against the given DNS servers.

    Returns the set of addresses, or an empty set on failure. Uses the cluster's
    resolvers so the answer matches what the nodes will see.
    """
    try:
        import dns.resolver  # lazy: only needed for this check
    except ImportError:
        # No dnspython -- fall back to the system resolver (better than nothing,
        # but note it may differ from the cluster's view under split-horizon).
        try:
            return {ai[4][0] for ai in socket.getaddrinfo(hostname, None)}
        except socket.gaierror:
            return set()

    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(servers)
    r.lifetime = timeout
    try:
        return {rr.address for rr in r.resolve(hostname, "A")}
    except Exception:
        return set()


def port_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ip_taken(ip: str) -> bool:
    """Best-effort 'is this node IP already in use?' -- something answering on
    22 or 443 means the address is not free for a fresh deploy."""
    return port_open(ip, 22, 1.5) or port_open(ip, 443, 1.5)
