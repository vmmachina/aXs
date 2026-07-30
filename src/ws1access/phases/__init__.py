"""Phase registry and the contract every phase module fulfils.

A phase is a plain module -- matching the functional style of the rest of the
package -- exposing:

    NAME: str                       # e.g. "40_bootstrap"
    DEPS: tuple[str, ...]           # phases that must be done first
    is_done(ctx) -> Probe           # live probe: is this phase already complete?
    run(ctx) -> None                # do the work; raise on failure
    explain_failure(ctx, exc) -> str  # turn a failure into an actionable message

`deploy` runs, in dependency order, every phase whose is_done() is false.
`status` shows each phase's Probe. The probe is the source of truth: nothing is
"done" because a previous step returned 0, only because the live system says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..context import Context


@dataclass
class Probe:
    """Result of asking the live system whether a phase is complete.

    `warning` is for what the operator must see EVEN THOUGH the phase is done.
    It exists because `detail` does not reach them in that case: the TUI writes
    a hard-coded "already done" over it, `axs status` shows only its first
    line, and `ctx.report()` is a no-op during a probe round because no sink is
    attached yet. Phase 50's config drift is the case it was added for -- a
    warning nobody sees is the silent green it was meant to remove.

    Every engine renders this; `detail` stays what it was, the reason a phase
    is NOT done.
    """

    done: bool
    detail: str = ""
    warning: str = ""


class Phase(Protocol):
    NAME: str
    DEPS: tuple[str, ...]

    def is_done(self, ctx: Context) -> Probe: ...
    def run(self, ctx: Context) -> None: ...
    def explain_failure(self, ctx: Context, exc: Exception) -> str: ...


from . import (  # noqa: E402
    p00_preflight,
    p10_vms,
    p20_nodes_ready,
    p30_lb,
    p40_bootstrap,
    p50_cluster_init,
    p60_platform,
    p70_services,
    p80_tenant,
)

# name -> phase module. The cli.py PHASES graph is the authority on order/deps.
REGISTRY: dict[str, Phase] = {
    m.NAME: m  # type: ignore[misc]
    for m in (
        p00_preflight, p10_vms, p20_nodes_ready, p30_lb,
        p40_bootstrap, p50_cluster_init, p60_platform, p70_services, p80_tenant,
    )
}


def dependents(name: str) -> set[str]:
    """Every registered phase that depends on `name`, directly or transitively.

    Used by the PLAIN engine only, and the asymmetry is the reason it is needed.
    `axs deploy` probes all nine phases up front regardless of dependencies, so
    phase 60's "done" is recorded seconds BEFORE phase 50 rewrites profile.yml
    -- and nothing ever re-asked, so that stale answer was the verdict and the
    rollout was skipped entirely (docs/09 §5 describes the marker phase 60 must
    see; without a re-probe it never gets to look).

    The TUI does not have this hole: it probes lazily, leaving a phase unprobed
    while any dependency is still open, and it re-probes right before the
    phase's turn. So a phase only lands in its `done` set when every dependency
    was already done -- and a done phase never runs, so no dependency of a done
    phase can run and invalidate it.

    Still expressed as a general rule rather than a special case for phase 50: a
    probe result is only true as of the state it was taken against.

    The engines re-PROBE these, they do not run them. A phase that is genuinely
    still done after its dependency ran must stay skipped -- re-running phase 70
    because phase 50 touched a file would trade a silent skip for an hour of
    needless work.
    """
    out: set[str] = set()
    frontier = {name}
    while frontier:
        direct = {n for n, module in REGISTRY.items()
                  if set(module.DEPS) & frontier and n != name and n not in out}
        if not direct:
            break
        out |= direct
        frontier = direct
    return out
