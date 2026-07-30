"""Phase 20 -- Wait for SSH and verify each node's network configuration.

Uses the state collector (collect.py): probe every node, confirm it is reachable
and its live config (interface, address, gateway, DNS) has no problems. Runs
before any key trust exists, so it uses the configuser password.

Done-probe: every node reachable, no collector-reported problems.
"""

from __future__ import annotations

import time

from .. import collect
from ..context import Context
from . import Probe

NAME = "20_nodes_ready"
DEPS = ("10_vms",)


def _states(ctx: Context):
    """Probe every node AND check what it reports against the configuration.

    The expected values come from the config's network section -- the same ones
    that went into the OVF properties in phase 10. ovftool exiting 0 only means
    the OVF was accepted; whether the properties actually applied is exactly
    what this compares (docs/04). Without it a node with a wrong gateway passes
    here and fails deep inside ansible two phases later.
    """
    net = ctx.network or {}
    out = []
    for n in ctx.nodes:
        out.append(collect.collect_node(
            n["ip"], password=ctx.configuser_password,
            expected_hostname=n.get("hostname"), user=ctx.user,
            gateway=net.get("gateway"),
            dns=net.get("dns") or None,
            search=net.get("search_domains") or None,
        ))
    return out


def _expiry_warning(states) -> str:
    """The configuser password's remaining life, when it is worth saying.

    It expires 60 days after the OVA deploy, and when it does EVERY ssh path
    breaks at once -- this tool's and wso's ansible alike (docs/03, docs/06).
    The date was already collected and printed as a detail line; nothing ever
    compared it to today. So a deploy could start with two days left, run for
    an hour, and fail somewhere in phase 60/70 on an auth error that looks like
    an entirely different problem. Exactly that confusion cost hours on
    2026-07-29, from the other end: a refused password read as a hang.

    Deliberately a WARNING and not a failure. The password being close to
    expiry does not stop anything working right now, and a phase that goes red
    over it would block a deploy that would have completed. Saying it plainly
    is enough -- rotating it takes `sudo passwd configuser` on every node.

    Nodes whose expiry could not be determined are named too, without a guess
    either way: "we could not tell" is its own answer, not "fine".
    """
    expired, soon, unknown = [], [], []
    for state in states:
        if not state.reachable:
            continue
        kind, days = collect.password_expiry(state.password_expires)
        label = state.expected_hostname or state.ip
        if kind == "never":
            continue
        if kind == "unknown":
            unknown.append(label)
        elif days <= 0:
            expired.append(f"{label} ({-days} days ago)")
        elif days <= collect.EXPIRY_WARN_DAYS:
            soon.append(f"{label} (in {days} days)")

    lines = []
    if expired:
        lines.append(
            "WARNING — the configuser password has ALREADY EXPIRED on: "
            + ", ".join(expired))
        lines.append(
            "  Every ssh path breaks when it does, this tool's and wso's "
            "ansible alike. Set it again on EVERY node, to the same value: "
            "`sudo passwd configuser`.")
    if soon:
        lines.append(
            "WARNING — the configuser password expires soon on: "
            + ", ".join(soon))
        lines.append(
            "  A deploy runs for hours and a resume may be days later; when it "
            "expires, every ssh path breaks at once. Rotate it now on EVERY "
            "node, to the same value: `sudo passwd configuser`.")
    if unknown:
        lines.append(
            "NOTE — could not determine when the configuser password expires "
            "on: " + ", ".join(unknown) + " (nothing follows from that either "
            "way; check with `chage -l configuser` there).")
    return "\n".join(lines)


def is_done(ctx: Context) -> Probe:
    states = _states(ctx)
    bad = [s for s in states if not s.reachable or s.problems]
    detail = collect.render_nodes(states) if bad else f"{len(states)} nodes ok"
    return Probe(not bad, detail=detail, warning=_expiry_warning(states))


def run(ctx: Context) -> None:
    # Wait for SSH on every node. Fresh VMs need more than 10 minutes: a full
    # 6-VM rebuild (2026-07-22) had all nodes up ~1-2 min AFTER a 10-min wait
    # expired, so the deadline is 20 min.
    deadline = 80  # * 15s = 20 min
    for i in range(deadline):
        states = _states(ctx)
        up = [s for s in states if s.reachable]
        if len(up) == len(states):
            ctx.report(f"all {len(states)} nodes reachable ✔")
            break
        waiting = ", ".join(s.ip for s in states if not s.reachable)
        ctx.report(f"[{len(up)}/{len(states)} reachable] waiting for: {waiting} "
                   f"(check {i+1}, up to 20 min)")
        time.sleep(15)
    else:
        unreachable = [s.ip for s in _states(ctx) if not s.reachable]
        raise RuntimeError(f"Nodes not reachable after ~20 min: {', '.join(unreachable)}")

    states = _states(ctx)
    problems = [s for s in states if s.problems]
    if problems:
        raise RuntimeError("Node configuration problems:\n" + collect.render_nodes(states))

    # Said here as well as in the probe: run() is the path about to spend the
    # next hour or two on this cluster, and the progress sink is where the
    # operator is actually looking during a deploy.
    for line in _expiry_warning(states).splitlines():
        ctx.report(line)


def explain_failure(ctx: Context, exc: Exception) -> str:
    return str(exc)
