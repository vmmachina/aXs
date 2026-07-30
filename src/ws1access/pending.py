"""The pending-rollout marker: what turns a DETECTED drift into an APPLIED one.

docs/09 §5. Phase 50 owns the files, phase 60 rolls them out. Between them sits
a gap that a warning cannot close: `DEPS` only orders the phases, it does not
cascade. Phase 50 going red leaves 60/70/80 green on their own evidence -- a
healthy cluster IS healthy, it is just running yesterday's settings. So phase 50
rewriting profile.yml without this marker means the file is correct on disk and
never deployed, which is the same silent green from one step further along.

Why a file on the bootstrap rather than a variable in the process:

  * It survives an abort. The operator who changes the NTP server, starts a
    deploy and loses the connection in phase 60 comes back to a cluster that
    still knows a rollout is owed.
  * It survives a switch of engine. The drift may be found by `axs status` in
    the terminal and rolled out by the TUI an hour later.
  * It is a fact about the CLUSTER, not about this run. That is also why it
    lives beside the files it refers to, in the cluster directory.

Three states, never two (docs/08 E1, the same rule as probe_alive and
password_expiry): pending, clean, and COULD NOT ASK. Reading "no marker" out of
a failed ssh call would let a transport hiccup cancel a rollout that is genuinely
owed, and this marker exists precisely to be harder to lose than a warning.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from .context import Context

# A dotfile, and inside the cluster directory: wso reads named files there and
# ignores anything else, so this sits next to what it describes without being
# mistaken for input. Deliberately not under /root -- two clusters managed from
# one bootstrap would share one marker and roll out each other's changes.
FILENAME = ".axs-profile-pending"

# Markers, not exit codes: `cat` of a missing file exits non-zero, and that is
# indistinguishable from ssh failing, wso's shell dying, or a wrong path. The
# markers make SshResult.ok mean "we asked and got an answer" and nothing else.
# Same idiom as p30_lb's AXS_DNS_FOUND and context.probe_alive's AXS_ALIVE.
#
# Three, not two, and `test -e` ahead of the `cat`: a file that EXISTS but
# cannot be read (mode 000, or a directory of that name) makes `cat` fail
# exactly like a missing file, and a two-marker version reported that as
# "clean" -- a rollout cancelled by a permission problem. The distinction costs
# one `test`.
_END = "AXS_PENDING_END"
_NONE = "AXS_PENDING_NONE"
_BAD = "AXS_PENDING_UNREADABLE"
_GONE = "AXS_PENDING_GONE"


@dataclass(frozen=True)
class Pending:
    """Tri-state, as a type rather than a convention.

    Not `bool | None` and not a bare list: an empty key list is falsy and would
    read as "nothing pending" at every call site that forgot the difference.
    `state` has to be looked at.
    """

    state: str                                   # "pending" | "clean" | "unknown"
    keys: tuple[str, ...] = field(default=())
    reason: str = ""                             # only for "unknown"


def path(ctx: Context) -> str:
    return f"{ctx.cluster_dir}/{FILENAME}"


def mark(ctx: Context, keys: list[str]) -> None:
    """Record that profile.yml has changed and the platform has not seen it yet.

    Raises on failure, and the caller must let that abort the phase. A marker
    that silently failed to appear is worse than no mechanism at all: the file
    would be patched, the drift gone on the next run, and the rollout owed
    forever with nothing left to notice it.

    This is why phase 50 calls this BEFORE it patches the file. In that order a
    failed write leaves profile.yml stale, so the drift check finds it again and
    the next run retries the whole thing. In the other order the failure is
    unrecoverable.
    """
    ctx.write_file(path(ctx), "".join(f"{key}\n" for key in keys))


def read(ctx: Context) -> Pending:
    """Is a rollout owed? Only the bootstrap can say.

    `in_cluster_dir=False` on purpose. The default wraps the command as
    `cd <cluster dir> && <command>`, and `A && B || C` binds the `||` to the
    WHOLE chain -- so a `cd` that fails answers through the `|| echo NONE`
    branch: "no marker", for a question that was never asked. The path here is
    absolute, so there was never anything for the `cd` to do.

    Honest about the reach of that: since the marker lives INSIDE the cluster
    directory, a directory that is merely missing means the marker is missing
    too, and "clean" was the right answer anyway. It goes wrong only for a
    directory that exists but cannot be entered while the marker inside it does
    exist -- and this runs as root, which is not stopped by that. So the change
    removes a real trap in the shape of the command rather than a defect anyone
    was going to hit; the `cd` was simply doing nothing but adding a failure
    mode.
    """
    p = shlex.quote(path(ctx))
    r = ctx.bootstrap_run(
        f"test -e {p} && {{ cat {p} 2>/dev/null && echo {_END} || echo {_BAD}; }} "
        f"|| echo {_NONE}",
        in_cluster_dir=False)
    if not r.ok:
        return Pending("unknown", reason=(
            "could not ask the bootstrap whether a profile.yml rollout is "
            "still owed"))
    out = r.output or ""
    if _BAD in out:
        return Pending("unknown", reason=(
            f"the marker {path(ctx)} exists on the bootstrap but could not be "
            "read, so it is unknown whether a profile.yml rollout is owed"))
    if _NONE in out and _END not in out:
        return Pending("clean")
    if _END not in out:
        # No marker survived -- a login banner or a chatty profile script ate
        # the line. Not an answer; do not invent one from the noise.
        return Pending("unknown", reason=(
            "the bootstrap's answer about a pending rollout could not be read"))
    # `_END` is stripped rather than only compared: a marker written without a
    # trailing newline glues the last key to it.
    keys = tuple(k for line in out.replace(_END, "\n").splitlines()
                 if (k := line.strip()) and k != _NONE)
    return Pending("pending", keys=keys)


def clear(ctx: Context) -> tuple[bool, str]:
    """Forget the marker after the rollout that satisfied it.

    Verified, not assumed: `rm -f` reports success for a file it never touched,
    and a marker that outlives its rollout makes phase 60 red on every future
    run -- the failure mode docs/09 §4 warns about, a phase that can never go
    green again.

    `-r` as well as `-f` because that is the one case plain `rm -f` cannot
    clear: if something created a DIRECTORY under this name, the removal fails
    forever and so does phase 60. The target is not operator input -- FILENAME
    is a constant, so this can only ever delete something called
    `.axs-profile-pending`.
    """
    p = path(ctx)
    q = shlex.quote(p)
    # in_cluster_dir=False for the same reason as `read`: an absolute path needs
    # no `cd`, and a failing one would be swallowed by the trailing `&&` chain.
    r = ctx.bootstrap_run(f"rm -rf {q} && test ! -e {q} && echo {_GONE}",
                          in_cluster_dir=False)
    if r.ok and _GONE in (r.output or ""):
        return True, ""
    return False, (
        f"the rollout succeeded, but the marker {p} could not be removed. "
        f"Every further run will report phase 60 as not done until it is gone. "
        f"Remove it by hand: rm -rf {p}")
