"""Phase 30 -- Load balancer.

The tool never configures the load balancer -- that is the customer's own device
(F5 / NSX ALB / HAProxy). It only VERIFIES that <tenant>.<domain> resolves to the
LB IP.

Asked from the BOOTSTRAP once it is reachable, not from the operator's laptop
(docs/08 B6). Split-horizon DNS answers by the CLIENT'S SOURCE IP, not by which
server is asked -- a query sent from the operator's machine, even aimed at the
cluster's own DNS servers, can get a different answer than the cluster itself
gets. Querying from the bootstrap is what actually matches what the nodes will
see, because it shares their network and their configured resolvers. Not fully
proven: the bootstrap and the platform/access nodes are known to resolve
DIFFERENTLY in one respect (docs/04, ova_profiles/26.07.yml) -- the bootstrap
queries the real nameserver directly, the other nodes go through the local
systemd-resolved stub with its own cache. Same upstream servers, but not
provably the identical view at every instant; a stale resolver cache on the
other five nodes is a gap this does not close.

Both engines run every phase strictly sequentially, in one thread, in list
order -- there is no cross-phase parallelism anywhere in this codebase (an
earlier draft of this comment claimed otherwise, inherited unchecked from the
code this replaced). So by the time this phase's `run()` actually executes, it
is AFTER phase 20, which has already built the bootstrap and confirmed it
answers SSH. In the normal case there is nothing left to wait for except the
DNS record itself. The one place the bootstrap is genuinely not there yet is
an `is_done()` probe taken before any phase has run at all (both engines probe
every phase up front) -- there, and only there, this falls back to an ADVISORY
check from the operator's machine: useful for catching a plain typo in the
tenant name or domain early, but explicitly not authoritative, and it can never
mark this phase done. Only the bootstrap's own answer can.

This holds for both TLS topologies (loadbalancer.mode):
  * termination -- the LB terminates TLS with the real cert, re-encrypts to the
    appliance's self-signed cert.
  * passthrough -- the LB passes TLS through; the appliance presents the real
    cert (taken from the operator's PFX).
The mode changes where the certificate lives, not what phase 30 checks.

LB reachability itself is deliberately NOT probed here (an external LB may not be
serving yet; the real proof is the login in phase 70/80). The LB must be in place
before phase 70 (access-profile.yml needs LB IP + cert), and 30 sits ahead of 40
in the fixed phase order -- so waiting here for a DNS record genuinely blocks
the bootstrap's asset upload from starting. That cost is real, not "free",
and it is the trade for the check meaning something (docs/08 E1: a check
friendlier than the system it vouches for is worse than none).

Not proven here, only assumed: that a DNS record the operator creates while
this is running propagates well inside the deadline below, which is a judgement
call, not a measurement -- unlike phase 20's boot-time bound, which IS a
measured figure and does not actually transfer here (by the time this phase
polls, the boot wait phase 20 measured is already paid for). If a resolver's
TTL or replication is unusually slow, this will time out and say so rather
than wait indefinitely.
"""

from __future__ import annotations

import shlex
import time

from .. import netcheck
from ..context import Context
from . import Probe

NAME = "30_lb"
DEPS = ("00_preflight",)

# Markers, not exit codes: `getent` exits non-zero on a genuine "not found",
# and the whole point is telling that apart from "could not even ask" (an
# SSH/transport failure). `&&`/`||` guarantee the compound always exits 0 when
# the shell ran at all, so SshResult.ok means exactly "we asked, and the
# marker says what the answer was" -- and its absence means the transport
# itself failed, not that the record does not exist. Same idiom as
# context.probe_alive's AXS_ALIVE/AXS_DEAD.
_FOUND = "AXS_DNS_FOUND"
_NOTFOUND = "AXS_DNS_NOTFOUND"

# A judgement call, not a measurement -- see the module docstring. Kept at the
# same order of magnitude as phase 20's bound only because there is nothing
# better to anchor it to, not because the reasoning transfers.
_DEADLINE = 80          # * 15s = 20 min
_INTERVAL = 15


def _lb_ip(ctx: Context) -> str:
    return ctx.access.get("lb_ip", "")


def _tenant_fqdn(ctx: Context) -> str:
    a = ctx.access
    return f"{a['first_tenant']['tenant_name']}.{a['domain']}"


def _authoritative(ctx: Context, fqdn: str) -> tuple[set[str] | None, str]:
    """Resolve `fqdn` the way the bootstrap itself resolves it.

    Returns (addresses, "") on a real answer -- including an empty set for a
    genuine "no record". Returns (None, reason) when nothing could be asked at
    all; the reason distinguishes "not up yet" from "up, but refused us",
    because those are different diagnoses and used to be reported as the same
    thing: a login that fails because the configuser password expired (60
    days after the OVA deploy, same as everywhere else in this tool) would
    otherwise be told "the bootstrap is not reachable yet" for 20 minutes and
    then blamed on DNS or the LB when the deadline ran out. Port 22 answering
    is the fact that separates the two.

    A quick TCP probe on 22 first, not straight to SSH: run_with_key/
    run_with_password each carry their own connect timeout, and stacked they
    cost up to ~25s per attempt -- paid on every single probe of this phase
    while the bootstrap does not exist yet. netcheck.port_open answers in
    ~2s and this file already depends on netcheck for exactly this kind of
    check.

    `getent ahostsv4`, not `getent hosts`: the latter prefers AAAA over A and
    would report ONLY an IPv6 address for a dual-stack record, silently
    rejecting a perfectly correct IPv4 load balancer. `ahostsv4` is the same
    glibc/NSS database restricted to IPv4, so it still honours /etc/hosts and
    nsswitch.conf ordering the way the real deploy will -- which is also a
    known, accepted gap: a stray /etc/hosts entry on the bootstrap, or an
    NSS module ahead of dns, would be reported as "the cluster's DNS view"
    without a nameserver ever being asked.

    Known, accepted gap: if `getent` itself is missing on the bootstrap (not
    expected -- it ships with glibc, which nothing on this appliance runs
    without), the shell reports "command not found" and the `||` branch fires,
    reading as a real "not found" rather than "could not ask". Not guarded
    against by parsing stderr text, which would trade one brittleness for
    another; the assumption is stated here instead of hidden.
    """
    if not netcheck.port_open(ctx.bootstrap_ip, 22, timeout=2.0):
        return None, "the bootstrap is not answering on port 22 yet"
    r = ctx.node_run(
        ctx.bootstrap_ip,
        f"getent ahostsv4 {shlex.quote(fqdn)} && echo {_FOUND} || echo {_NOTFOUND}")
    if not r.ok:
        tail = (r.output or "").strip()[-160:]
        return None, (
            "the bootstrap answers on port 22 but the check could not "
            "authenticate to it -- this is a login problem, NOT a DNS or LB "
            f"problem (check the configuser password): {tail}")
    out = r.output or ""
    if _FOUND not in out and _NOTFOUND not in out:
        # Neither marker survived -- some noise on the line ate it (a login
        # banner, a chatty profile script). Not a real answer either way; do
        # not guess at one from whatever text came back.
        return None, "the bootstrap's answer could not be read"
    if _NOTFOUND in out and _FOUND not in out:
        return set(), ""
    addrs = {parts[0] for line in out.splitlines()
            if (parts := line.split()) and parts[0] not in (_FOUND, _NOTFOUND)}
    return addrs, ""


def _probe(ctx: Context) -> tuple[bool, str]:
    """One non-blocking attempt: the authoritative answer if the bootstrap can
    give one, an explicitly-labelled advisory answer otherwise. Only the
    authoritative branch can report done."""
    lb, fqdn = _lb_ip(ctx), _tenant_fqdn(ctx)
    auth, why_not = _authoritative(ctx, fqdn)
    if auth is not None:
        ok = lb in auth
        return ok, (f"[{'ok' if ok else 'FAIL'}] DNS {fqdn} -> {lb} "
                    f"(asked the bootstrap): "
                    f"{', '.join(sorted(auth)) or '(no answer)'}")

    dns_servers = ctx.network.get("dns", [])
    addrs = netcheck.resolve_via(fqdn, dns_servers)
    where = f" via {', '.join(dns_servers)}" if dns_servers else ""
    matches = "matches" if lb in addrs else "does NOT match"
    return False, (
        f"[pending] {why_not} -- ADVISORY only, not authoritative: DNS "
        f"{fqdn}{where} resolves to {', '.join(sorted(addrs)) or '(no answer)'}"
        f", which {matches} the LB {lb}. Split-horizon DNS answers by the "
        f"CLIENT'S source IP, so this can differ from what the cluster itself "
        f"sees -- re-checking from the bootstrap.")


def is_done(ctx: Context) -> Probe:
    ok, detail = _probe(ctx)
    return Probe(ok, detail=detail)


def run(ctx: Context) -> None:
    # The tool never changes the LB -- verify only. This BLOCKS here, unlike a
    # single check-and-raise, because a DNS record the operator just created
    # may still be propagating -- see the module docstring for what this wait
    # does and does not cover.
    last_detail = ""
    for i in range(_DEADLINE):
        ok, detail = _probe(ctx)
        last_detail = detail
        if ok:
            return
        ctx.report(f"[{i + 1}/{_DEADLINE}] {detail}")
        time.sleep(_INTERVAL)
    raise RuntimeError(
        "The LB does not yet resolve/point correctly (the tool never changes "
        f"the LB -- please check DNS and the LB themselves):\n  {last_detail}"
    )


def explain_failure(ctx: Context, exc: Exception) -> str:
    return str(exc)
