"""Phase 00 -- Preflight checks before anything is deployed.

Cheap, deterministic checks that catch the common failures early instead of 40
minutes into a deploy: the OVA is present, ovftool is new enough (5.1.0+ -- 4.6.3
is incompatible with ESXi 8.0.3), vCenter answers, and <tenant>.<domain> resolves
to the load balancer.

Done-probe: all checks pass. There is no persistent state -- "done" just means
the environment is currently valid.
"""

from __future__ import annotations

from pathlib import Path

from .. import netcheck, ovftool
from ..context import Context
from ..vcenter import VCenter, VCenterError
from . import Probe

NAME = "00_preflight"
DEPS = ()


def _checks(ctx: Context) -> list[tuple[str, bool, str]]:
    res: list[tuple[str, bool, str]] = []

    ova = Path(ctx.ova_path)
    res.append(("OVA present", ova.is_file(), str(ova)))

    ver = ovftool.installed_version()
    ok = ver is not None and ver >= ovftool.MIN_VERSION
    res.append(("ovftool >= 5.1.0",
                ok, ".".join(map(str, ver)) if ver else "nicht gefunden"))

    vc = ctx.vcenter
    try:
        VCenter(host=vc["host"], user=vc["user"], password=vc.get("password", "")).session()
        res.append(("vCenter reachable + login", True, vc["host"]))
    except (VCenterError, KeyError) as e:
        res.append(("vCenter reachable + login", False, str(e)))

    acc = ctx.access
    dns_servers = ctx.network.get("dns", [])
    if acc.get("first_tenant") and acc.get("domain") and acc.get("lb_ip") and dns_servers:
        host = f"{acc['first_tenant']['tenant_name']}.{acc['domain']}"
        # Ask the CLUSTER's DNS (split-horizon: the operator's resolver may differ).
        addrs = netcheck.resolve_via(host, dns_servers)
        hit = acc["lb_ip"] in addrs
        res.append((
            f"DNS {host} -> LB (via {', '.join(dns_servers)})", hit,
            f"{', '.join(sorted(addrs)) or '(no answer)'} (expected {acc['lb_ip']})",
        ))

    return res


def _render(checks) -> str:
    return "\n".join(f"  [{'ok' if ok else 'FAIL'}] {name}: {msg}"
                     for name, ok, msg in checks)


def is_done(ctx: Context) -> Probe:
    checks = _checks(ctx)
    ok = all(c[1] for c in checks)
    if not ok:
        # Not done: the per-check lines ARE the reason, shown as detail.
        return Probe(False, detail=_render(checks))
    # Done, but NOT a black box. Preflight quietly verifies four things -- the
    # OVA, the ovftool version, that vCenter answers a login, and what DNS
    # returns for the tenant -- and used to collapse all of it into "done". The
    # operator asked to SEE it. The findings go in `warning`, the one field a
    # done phase still renders: the board shows the compact head line, the log
    # and the plain path show every check with its value (ovftool 5.1.0,
    # vCenter host, the DNS answer). It is not an alarm -- it is the receipt.
    head = "verified: " + " · ".join(
        f"{name.split(' ')[0]}={msg}" if msg else name
        for name, _ok, msg in checks)
    return Probe(True, warning=head + "\n" + _render(checks))


def run(ctx: Context) -> None:
    checks = _checks(ctx)
    failed = [c for c in checks if not c[1]]
    if failed:
        raise RuntimeError("Preflight checks failed:\n" + _render(checks))


def explain_failure(ctx: Context, exc: Exception) -> str:
    return str(exc)
