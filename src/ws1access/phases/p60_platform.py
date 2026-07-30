"""Phase 60 -- Deploy the Control Plane Platform.

Documented procedure (from the bootstrap, in /root/<cluster>):

    wso cp precheck                 # validates profile.yml (advisory)
    nohup wso cp deploy &           # 30 min - 1 hour
    wso healthcheck                 # Vault / Consul / Nomad / Services

Acceptance = a valid "New Folder Hash:" line. wso emits it as the authoritative
success signal, but into cp-cluster/control_plane.log (via cp_logger), NOT into
the deploy's stdout. Watching stdout ("New Folder Hash" never appears there) was
the earlier mistake. We baseline the hash count before the run and require a NEW
hash after it, then confirm with healthcheck.

Done-probe: `wso healthcheck -f json` is green AND a folder hash exists. The
detail shows the hash -- the proof of acceptance.
"""

from __future__ import annotations

import re
import time

from .. import health, pending
from ..context import Context, RemoteError, WSO_BUSY, redact, last_segment
from ..ssh import SshResult
from . import Probe

NAME = "60_platform"
DEPS = ("50_cluster_init",)

_DEPLOY_LOG = "cp-deploy.log"                     # detached stdout (step names)
_CP_LOG = "cp-cluster/control_plane.log"          # authoritative ansible log
_HASH = "New Folder Hash:"
# What wso prints instead of a hash when the platform is already current.
# TWO variants are on record from real runs -- "No Changes detected" (2026-07-28)
# and "Deployment skipped (hash match), use `-f` to re-run" (docs/04-findings).
# Which appears when is not established, so the code must know both: recognising
# only one turns a legitimate no-op re-run into a reported failure on a healthy
# platform.
_NO_CHANGES = ("No Changes detected", "Deployment skipped")
# '[w]so ...' not 'wso ...': the alive-check runs via `bash -lc "... pgrep -f
# 'wso cp deploy'"`, so the search string is IN pgrep's own command line and
# `pgrep -f 'wso cp deploy'` matches ITSELF -> the phase thinks the deploy is
# already running, never starts it, and waits forever. The '[w]' character class
# still matches the real "wso cp deploy" process but not the literal "[w]so..."
# in the checker's command line.
_ALIVE = "pgrep -f '[w]so cp deploy' >/dev/null"


def _hash_count(ctx: Context) -> int:
    r = ctx.bootstrap_run(f"grep -c {_HASH!r} {_CP_LOG} 2>/dev/null || true")
    try:
        return int(r.output.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def _last_hash(ctx: Context) -> str:
    r = ctx.bootstrap_run(f"grep {_HASH!r} {_CP_LOG} 2>/dev/null | tail -1")
    return r.output.strip()


def is_done(ctx: Context) -> Probe:
    hc = ctx.bootstrap_run("wso healthcheck -f json")
    # Platform only: a service still coming up in phase 70 must not make the
    # platform look unfinished (see health.parse_healthcheck).
    ok_h, problems = health.parse_healthcheck(hc.output, include_services=False)
    folder_hash = _last_hash(ctx)
    if ok_h and folder_hash:
        # A healthy platform IS healthy -- it is just possibly running
        # yesterday's settings. The healthcheck cannot tell the difference, and
        # the folder hash is the hash of the LAST deploy, so both are green
        # after phase 50 rewrote profile.yml and nothing rolled it out. The
        # marker is the only thing that knows (docs/09 §5).
        #
        # Read only on this branch: it is one extra `cat` per probe, and on the
        # unhealthy branch it could not change the verdict anyway.
        owed = pending.read(ctx)
        if owed.state == "pending":
            named = ", ".join(owed.keys) or "(the marker names no keys)"
            return Probe(False, detail=(
                "the platform is healthy but has NOT been rolled out with the "
                f"current profile.yml: {named}"))
        if owed.state == "unknown":
            # Done WITH a warning, not red. Being wrong here costs a settings
            # rollout one run later; being red costs a 30-60 minute deploy on
            # every ssh hiccup, and phase 50 says the same thing from its side.
            return Probe(True, detail=folder_hash,
                         warning=f"WARNING — {owed.reason}.")
        return Probe(True, detail=folder_hash)
    detail = ("healthcheck: " + "; ".join(_explain(hc, problems)[:3]) if problems
              else "no Folder Hash yet" if not folder_hash else "not healthy")
    return Probe(False, detail=detail)


def _explain(result: SshResult, problems: list[str]) -> list[str]:
    """Replace the bare unreadable marker with the raw answer and the ssh rc.

    Same treatment p70 gives check-service-readiness since docs/08 A9. Without
    it, "could not read the answer" covers a dropped connection, a wso error, a
    changed output format and an empty reply -- one message for four causes,
    and the operator cannot tell which. Redacted, because whatever came back is
    unknown and may carry a token.
    """
    return [health.unreadable_message(result.rc, redact(result.output))
            if p == health.UNREADABLE_HEALTHCHECK else p
            for p in problems]


# What precheck says about an unset profile.yml entry, e.g.
# "nfs backup server info is not set". Its node-level checks (hostname list,
# DNS) are reported separately and are noisy when the container cannot reach
# the nodes, so only the configuration lines are lifted out.
_NOT_SET = re.compile(r"^(?!.*Task failed)(.*\bis not set\b.*|.*\bnot present\b.*)$",
                      re.MULTILINE)
# The two warnings `wso cp deploy` prints first, before anything else happens.
# They scroll out of a 30-60 minute log within seconds, which is why operators
# remember seeing them and can never find them again.
_WARN = re.compile(r"^.*!!!WARNING!!!.*$", re.MULTILINE)


def _report_precheck(ctx: Context) -> None:
    """Run precheck and show what it found -- advisory, never blocking."""
    out = ctx.bootstrap_run("wso cp precheck").output or ""
    for line in dict.fromkeys(m.strip() for m in _NOT_SET.findall(out)):
        if line:
            ctx.report(f"precheck: {line}")


def report_deploy_warnings(ctx: Context) -> None:
    """Lift the !!!WARNING!!! lines out of the deploy log and repeat them.

    They are the only place Omnissa tells the operator that NTP is
    "highly recommended" and NFS "required for disaster recovery" -- and they
    are printed once, at second zero of an hour-long run.
    """
    # The whole file, then cut to THIS run: the log is appended across runs, so
    # `head -40` would forever show the warnings of the very first deploy and
    # never the current one -- exactly wrong when the operator has just added
    # the NFS target the warning asks for.
    raw = ctx.bootstrap_run(f"cat {_DEPLOY_LOG} 2>/dev/null").output or ""
    tail = last_segment(raw)[:8000]
    for line in dict.fromkeys(m.strip() for m in _WARN.findall(tail)):
        # Drop the log's timestamp prefix; the warning itself is the message.
        ctx.report(re.sub(r"^\S+\s+\S+\s+", "", line))


def _confirm_health(ctx: Context) -> None:
    """Acceptance health for phase 60 -- with a one-shot unseal repair. Vault
    seals after a node reboot (vSphere HA / patching); the doc's fix is
    `wso cp unseal` from the bootstrap. Try it once, harmless if not needed,
    before declaring the platform unhealthy."""
    hc = ctx.bootstrap_run("wso healthcheck -f json")
    if health.sealed_detected(hc.output):
        ctx.report("Vault reports SEALED -- running `wso cp unseal` "
                   "(documented post-reboot repair) ...")
        ctx.bootstrap_run("wso cp unseal")
        time.sleep(20)
        hc = ctx.bootstrap_run("wso healthcheck -f json")
    # Platform only, for the same reason as is_done(): on a re-run the services
    # from phase 70 already exist, and one of them being unsettled is not a
    # verdict on the platform this phase just deployed.
    ok, problems = health.parse_healthcheck(hc.output, include_services=False)
    if not ok:
        raise RemoteError("wso healthcheck",
                          SshResult(1, "; ".join(_explain(hc, problems))))


def run(ctx: Context) -> None:
    # precheck is advisory -- it flags the optional profile.yml items
    # (logging/telemetry/nfs/ntp), non-mandatory per the guide. Advisory is not
    # the same as worthless, though: its output used to be discarded entirely,
    # so the one place where wso tells the operator what is missing went
    # nowhere. It is surfaced now, still without blocking.
    _report_precheck(ctx)

    # Read before the deploy, cleared after it: this run is the rollout the
    # marker was asking for.
    owed = pending.read(ctx)
    if owed.state == "pending" and owed.keys:
        ctx.report("rolling out the profile.yml change(s): "
                   + ", ".join(owed.keys))

    before = _hash_count(ctx)
    # Detached: the deploy must survive the tool's SSH connection dropping.
    ctx.start_detached_once(_DEPLOY_LOG, "wso cp deploy", _ALIVE,
                            busy_cmd=WSO_BUSY)
    # wso prints its NTP/NFS warnings in the first seconds; repeat them into the
    # progress log so they survive the next hour of output.
    time.sleep(5)
    report_deploy_warnings(ctx)
    # Tail BOTH logs: cp-deploy.log (stdout) exists at once so the live log box
    # is never empty during warm-up; control_plane.log (ansible) arrives later
    # with the real TASK names and, listed last, dominates the tail once present.
    ctx.wait_while_running(_ALIVE, label="wso cp deploy (guide: ~30-60 min)",
                           logfile=[_DEPLOY_LOG, _CP_LOG])

    # Acceptance: a NEW "New Folder Hash:" must have been written this run --
    # UNLESS there was nothing to do. `wso cp deploy` is hash-based idempotent:
    # re-run against an unchanged platform it prints "No Changes detected",
    # writes no new hash, and exits cleanly. That is success. Treating it as a
    # failure told the operator the platform was broken when wso had just
    # confirmed it was current (observed live 2026-07-28 13:19).
    if _hash_count(ctx) <= before:
        # THIS run's output only. With an appended log, `tail -40` could still
        # contain a previous run's "No Changes detected" -- and a failed deploy
        # would then be reported as "nothing to do, already current".
        out = last_segment(
            ctx.bootstrap_run(f"cat {_DEPLOY_LOG} 2>/dev/null").output or "")
        if any(m in out for m in _NO_CHANGES) and _last_hash(ctx):
            ctx.report("wso cp deploy: no changes to make — the platform is "
                       "already at the current hash")
            if owed.state == "pending":
                # Surprising, and worth saying rather than smoothing over.
                # profile.yml lives in the folder wso hashes, so changing it
                # should have produced work. "No changes" here means the
                # setting may not have reached the cluster at all -- and this
                # is the only moment the two facts are visible together.
                ctx.report(
                    "WARNING — profile.yml had changed, yet wso reports no "
                    "changes to deploy. The new setting may not be part of "
                    "what `wso cp deploy` applies; verify it on the cluster "
                    f"before relying on it: {', '.join(owed.keys)}")
        else:
            tail = ctx.bootstrap_run(f"tail -n 40 {_CP_LOG} 2>/dev/null").output
            raise RemoteError("wso cp deploy produced no new Folder Hash",
                              SshResult(1, tail))

    # Confirm live health on top of the hash (parsed JSON + one-shot unseal).
    _confirm_health(ctx)

    # Only now: the marker means "phase 60 has not run since profile.yml
    # changed", and that is satisfied by a rollout that reached a healthy
    # cluster. Clearing it earlier would forget the obligation on a deploy that
    # then failed health -- the next run would find nothing owed.
    # One thing this rollout does NOT prove, said before the marker disappears.
    # A retrofitted NTP server was measured to take effect this way (commit
    # bad8894); NFS was not. The volume lives in the Nomad job definition, so
    # `wso cp deploy` should re-render it -- but whether `wso services deploy`
    # is additionally required is still open (docs/09 §4). Clearing the marker
    # silently would let a green run stand in for that proof.
    if owed.state == "pending" and any(k.startswith("nfs_") for k in owed.keys):
        ctx.report(
            "NOTE — the NFS backup target was rolled out with `wso cp deploy`. "
            "Whether that alone is enough for a target added AFTER the first "
            "deploy is not measured (docs/09 §4); if a restore cannot find the "
            "backups, run `wso services deploy` as well and please report it.")

    ok, why = pending.clear(ctx)
    if not ok:
        # Loud and actionable, not swallowed: an outliving marker makes this
        # phase red on every future run. Raising here also beats the engine's
        # own "run finished but probe still reports not done", which is what
        # would happen next and explains nothing.
        raise RemoteError("clear the pending-rollout marker", SshResult(1, why))


def explain_failure(ctx: Context, exc: Exception) -> str:
    if isinstance(exc, RemoteError):
        out = exc.result.output
        if "no new Folder Hash" in exc.step:
            return (
                "wso cp deploy ended WITHOUT a valid 'New Folder Hash:' -- not "
                "accepted.\n"
                "  - Full log on the bootstrap: /root/<cluster>/cp-cluster/control_plane.log\n"
                "    (look for the PLAY RECAP lines: unreachable=/failed= should be 0).\n"
                "  - Re-running is safe: `wso cp deploy` is hash-based idempotent.\n"
                f"  - Last log lines:\n{out[-1200:]}"
            )
        if exc.step == "wso healthcheck":
            return (
                "A Folder Hash was written but healthcheck is not green.\n"
                f"  - A service may still be starting; re-run "
                f"`axs status -c {ctx.local_name}`.\n"
                "  - After a node reboot, Vault needs, ON THE BOOTSTRAP:\n"
                f"      cd {ctx.cluster_dir} && wso cp unseal\n"
                f"  - healthcheck said:\n{out}"
            )
        return f"Phase 60 step '{exc.step}' failed (exit {exc.result.rc}):\n{out}"
    return str(exc)
