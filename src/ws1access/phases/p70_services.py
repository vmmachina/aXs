"""Phase 70 -- Deploy Infrastructure and Access services.

Documented procedure (from the bootstrap, in /root/<cluster>):

    vi /root/<cluster>/access/access-profile.yml    # we generate it
    wso access bootstrap                             # loads config into Vault/Consul
    nohup wso services deploy --type full &          # ~40 min
    wso access check-service-readiness               # all services READY

access-profile.yml is generated from config (see access_profile.py) -- every
customer-variable value comes from there, following the guide's field structure.

Done-probe: `wso access check-service-readiness` returns 0 (all services READY).
"""

from __future__ import annotations

import shlex
import time
from pathlib import Path

from .. import access_profile, health
from ..context import Context, RemoteError, WSO_BUSY, last_segment, redact
from ..ssh import SshResult
from . import Probe

NAME = "70_services"
DEPS = ("60_platform", "30_lb")

_DEPLOY_LOG = "services-deploy.log"
# '[w]so ...' avoids pgrep matching its own command line -- see p60 for the full
# explanation. Without it the phase never starts and waits forever.
# `wso services deploy` is only the CLI wrapper. The work happens in
# `python3 /scripts/deploy_services.py`, and that process OUTLIVES the wrapper:
# killing the wrapper leaves it running to its own 3600 s Nomad watch timeout.
#
# Proven live 2026-07-28. We killed the wrapper on a stalled deploy; pgrep then
# said "not running", start_detached_once launched a SECOND deploy against a
# cluster the first one was still working on, and both remaining attempts died
# within 5:30 having achieved nothing. Checking only the wrapper turns a stall
# into concurrent deploys.
#
# So both the liveness check and the kill must cover the worker as well.
#
# `pkill` runs as root here, and the loose patterns hit two things that are not
# hypothetical (docs/08 B4). This closes ONE of them and states the other:
#
#   `wso services deploy`   also matched `wso services deploy -s <service>` --
#                           the hand repair THIS TOOL prints when it gives up.
#                           CLOSED: only our run says `--type full`. (The module
#                           docstring shows a manual `--type full` too, so a
#                           doc-following operator is still indistinguishable.
#                           That one is at least not the repair we recommend.)
#   `deploy_services.py`    also matched `vim /scripts/deploy_services.py`.
#                           The editor is out; the hand repair's OWN worker is
#                           NOT. If `wso services deploy -s x` spawns the same
#                           `/scripts/deploy_services.py` -- untested, and the
#                           sibling question for `cp deploy` is open as docs/08
#                           D5 -- this pattern still matches it. So B4 is half
#                           closed, not closed.
#
# `.*` between interpreter and path because a flag (`python3 -u ...`) would
# otherwise break the match, and a MISS here is worse than a wide match: the
# kill and its verification share this pattern, so a worker we cannot see reads
# as "it died". docs/08 A1 recorded the command line ONCE, on 2026-07-28; D3
# leaves open whether the process is visible in the host PID namespace at all.
#
# What this deliberately does NOT narrow: context.WSO_BUSY and the two `pgrep
# -fal` listings. Those GATE a start or DESCRIBE what is running -- there a
# false positive costs a re-run while a miss costs a collision, so broad is
# correct, and it is what keeps the A1 double-deploy from coming back if the
# narrowed pattern above ever misses. Only what we KILL is narrowed.
_WRAPPER = "[w]so services deploy --type full"
_WORKER = "[p]ython[0-9.]*.*/scripts/deploy_services.py"
_ALIVE = (f"pgrep -f '{_WRAPPER}' >/dev/null "
          f"|| pgrep -f '{_WORKER}' >/dev/null")
_KILL = (f"pkill -f '{_WRAPPER}'; "
         f"pkill -f '{_WORKER}'; true")

# How long the log may stand still before we call it stalled. The longest
# legitimate quiet in a known-good run was 6 min (federation, 21:30 -> 27:30);
# 20 min is three times that. The stall this was written for lasted 68 min and
# would have been caught at ~25 min into the attempt instead of by hand.
_STALL_AFTER = 20 * 60

# How long to let things settle before calling a repeated blocker set
# permanent. Acceptance runs seconds after the deploy process ends; a
# service redeployed in that same attempt may still be registering its
# readiness, and declaring that deterministic defeats the retry.
_SETTLE = 2 * 60


def _profile_path(ctx: Context) -> str:
    return f"{ctx.cluster_dir}/access/access-profile.yml"


def _stage_certs(ctx: Context) -> None:
    """Copy custom cert/key onto the bootstrap and point the profile at them.

    The docs require the cert AT /root/<cluster>/access/certs/ and referenced by
    its full path there (wso runs in a container and resolves that to
    /workdir/access/certs/). The config holds the LOCAL path
    (clusters/<name>/appliance.crt) which does not exist on the bootstrap -- so
    we upload the file into access/certs/ and rewrite the profile path to the
    bootstrap host-path. Same container-path lesson as the private key.
    """
    certs_dir = f"{ctx.cluster_dir}/access/certs"
    targets: list[tuple[dict, str]] = []
    sc = ctx.access.get("server_certificate", {})
    if sc.get("is_self_signed", True) is False:
        targets += [(sc, "custom_cert_file"), (sc, "custom_cert_keyfile")]
    cp = ctx.access.get("cert_proxy", {})
    if cp.get("enabled") and cp.get("ssl_certificate_type") == "CUSTOM_CERT":
        targets += [(cp, "ssl_certificate_path"), (cp, "ssl_certificate_key")]
    if not targets:
        return  # self-signed / FQDN_CERT reuse -- nothing to stage

    ctx.bootstrap_step("create access/certs",
                       f"mkdir -p {shlex.quote(certs_dir)}", in_cluster_dir=False)
    for holder, key in targets:
        local = holder.get(key)
        if not local:
            continue
        p = Path(local)
        if not p.is_file():
            raise RemoteError(
                f"stage cert ({key})",
                SshResult(1, f"certificate file not found locally: {local}\n"
                             "  - it should have been produced from the PFX during "
                             "configuration; re-run configure or check clusters/"
                             f"{ctx.cluster_name}/."))
        dest = f"{certs_dir}/{p.name}"
        ctx.report(f"staging {p.name} to access/certs/ ...")
        ctx.write_file(dest, p.read_text())
        holder[key] = dest  # rewrite to the bootstrap host-path for the profile


def is_done(ctx: Context) -> Probe:
    ok, detail, _ = _acceptance(ctx)
    return Probe(ok, detail=detail)


def _acceptance(ctx: Context) -> tuple[bool, str, tuple[tuple[str, str], ...]]:
    """Phase-70 acceptance = BOTH gates green (Fable review; the docs pair them):
    check-service-readiness (every Access-core service present AND READY) AND
    healthcheck (Vault/Consul/Nomad healthy, not sealed). We PARSE the JSON, not
    the wso exit code -- readiness has no verified rc semantics, and the exit
    code alone hides the ~30 infra services readiness never lists.

    Third return value: the BLOCKERS -- (kind, service) pairs standing between
    us and green, sorted, where kind is "missing" or "not_ready". The retry
    loop needs them to tell "the same thing is still wrong" from "something
    else is wrong now"; the last 'Deploying service' line cannot answer that
    (see run()), and the kind matters because missing -> not_ready is
    progress.
    """
    csr = ctx.bootstrap_run("wso access check-service-readiness")
    ok_r, not_ready, missing = health.parse_readiness(csr.output)
    hc = ctx.bootstrap_run("wso healthcheck -f json")
    ok_h, problems = health.parse_healthcheck(hc.output)
    # The same treatment readiness has had since A9: an unreadable answer must
    # say WHAT came back and what ssh made of it, or one message stands for a
    # dropped connection, a wso error and a changed format alike.
    problems = [health.unreadable_message(hc.rc, redact(hc.output))
                if p == health.UNREADABLE_HEALTHCHECK else p
                for p in problems]
    if ok_r and ok_h:
        return (True, "all Access services READY + Vault/Consul/Nomad healthy ✔", ())
    bits: list[str] = []
    if missing == [health.UNREADABLE]:
        # Not the same as "services are missing". Show what actually came back --
        # without it the operator is told to hunt for services that may be fine,
        # while the real problem (an error, or silence, from the command) stays
        # hidden. Seen live 2026-07-28.
        raw = redact((csr.output or "").strip())
        bits.append("could not read `wso access check-service-readiness`; it "
                    + (f"answered: {raw[-200:]}" if raw else "answered nothing at all"))
    elif missing:
        bits.append(f"core services MISSING (never deployed): {', '.join(missing)}")
    crit = [s for s in not_ready if not health.is_advisory(s)]
    adv = [s for s in not_ready if health.is_advisory(s)]
    if crit:
        bits.append(f"NOT_READY (critical): {', '.join(crit)}")
    if problems:
        bits.append("healthcheck: " + "; ".join(problems[:4]))
    if adv:
        bits.append(f"[tolerated advisory: {', '.join(adv)}]")
    # Blockers keep their KIND, not just their name. "missing" (never deployed)
    # and "not_ready" (deployed, still coming up) are different states, and the
    # step between them is real progress -- collapsing both to a bare name made
    # a service that had just gone from never-deployed to starting look like
    # nothing had happened, and the retry gave up on it.
    blockers = tuple(sorted(
        [("missing", m) for m in missing if m != health.UNREADABLE]
        + [("not_ready", s) for s in crit]))
    return (False, " | ".join(bits)[:400] or "acceptance not met", blockers)


def _last_service(ctx: Context) -> str:
    """Last 'Deploying service X' from the deploy log -- how far this attempt got,
    for the progress-aware retry."""
    # THIS attempt, not "the last one ever". The log is appended across attempts
    # and across aXs runs, so a plain grep|tail could name a service from an
    # earlier attempt -- and the stuck-message would then send the operator to
    # restart something this attempt never reached.
    raw = ctx.bootstrap_run(f"cat {_DEPLOY_LOG} 2>/dev/null").output or ""
    hits = [ln for ln in last_segment(raw).splitlines() if "Deploying service" in ln]
    if not hits:
        return ""
    return hits[-1].split("Deploying service", 1)[-1].strip()


def run(ctx: Context) -> None:
    if not ctx.access:
        raise RuntimeError("No `access` section in config -- phase 70 needs it "
                           "(domain, lb_ip, first_tenant, cert topology).")

    # Refuse BEFORE touching anything. The guard inside start_detached_once
    # comes too late for this phase: by then run() has already rewritten
    # access-profile.yml and executed `wso access bootstrap`, which writes into
    # Vault and Consul. Running that alongside another wso operation is exactly
    # the collision the guard exists to prevent -- it just happens one step
    # earlier. Phase 60 does not need this: everything before its start is a
    # read-only precheck.
    # probe_alive, not `.ok`: a transport blip must not read as "mine is not
    # running". It would send us down the full path below -- rewriting
    # access-profile.yml and running `wso access bootstrap` into Vault and
    # Consul -- while our own deploy_services.py is reading the same data.
    state = ctx.probe_alive(_ALIVE)
    if state == "unknown":
        raise RemoteError(
            "cannot tell whether the services deploy is running",
            SshResult(1, "The bootstrap did not answer the liveness check. "
                         "Continuing could rewrite the profile and re-run "
                         "`wso access bootstrap` alongside a running deploy.\n"
                         "  Check the connection and re-run."))
    mine_is_running = state == "alive"
    if ctx.bootstrap_run(WSO_BUSY).ok and not mine_is_running:
        raise ctx.busy_error()

    if mine_is_running:
        # Resume, not restart -- and that means touching NOTHING. The steps
        # below rewrite access-profile.yml and run `wso access bootstrap`, which
        # writes into Vault and Consul; doing that while OUR OWN deploy is
        # reading the same data is the very collision this phase guards against.
        # The guard above only catches somebody else's operation, so the most
        # ordinary case -- the operator restarts the tool while the deploy runs
        # -- slipped straight past it.
        ctx.report("services deploy already running — resuming, "
                   "leaving profile and Vault untouched")
        _deploy_services(ctx)
        ok, detail, _ = _acceptance(ctx)
        if not ok:
            raise RemoteError("phase 70 acceptance", SshResult(1, detail))
        return

    # 0. Stage custom cert(s) onto the bootstrap and rewrite the profile paths to
    #    the bootstrap host-path (docs: /root/<cluster>/access/certs/). Must run
    #    BEFORE render so the profile carries the correct paths.
    _stage_certs(ctx)

    # 1. Generate + write access-profile.yml.
    #    XFF ignore list (doc derivation): LB + all non-bootstrap nodes +
    #    reverse proxies. Explicit config override wins.
    derived = [ctx.access["lb_ip"], *ctx.platform_ips, *ctx.access_ips, *ctx.reverse_proxies]
    seen: set = set()
    ip_ignore = ctx.access.get("ip_ignore_list") or [
        ip for ip in derived if not (ip in seen or seen.add(ip))
    ]
    profile = access_profile.render(ctx.access, ip_ignore=ip_ignore)
    ctx.write_file(_profile_path(ctx), profile)

    # 2. Load config into Vault/Consul.
    ctx.bootstrap_step("wso access bootstrap", "wso access bootstrap")

    # 3. Deploy services -- detached (survives the tool disconnecting), ~40 min.
    #    Auto-retry: on a fresh cluster a service (seen with host-logging) can
    #    miss Nomad's deployment-health window on the first pass -- the container
    #    comes up fine, but the deploy reports "failed". A re-run (hash-idempotent,
    #    skips what's already healthy) pulls it over the line. So run up to a few
    #    times until check-service-readiness is green, rather than failing on the
    #    first transient miss. (See docs/07 -- the whole services-deploy saga.)
    _deploy_services(ctx)

    # 4. Acceptance: BOTH gates (readiness + healthcheck) -- NOT the wso exit
    #    code (readiness lists only the ~20 Access services, healthcheck covers
    #    the platform tier; the docs require both green).
    ok, detail, _ = _acceptance(ctx)
    if not ok:
        raise RemoteError("phase 70 acceptance", SshResult(1, detail))


_DEPLOY_ATTEMPTS = 3


def _deploy_services(ctx: Context) -> None:
    """Deploy services, re-running while acceptance is not yet green. Auto-retry
    only helps the TRANSIENT case (a service misses Nomad's health window; a warm
    re-run pulls it over -- proven by the 2026-07-23 success run). If an attempt
    makes NO forward progress and acceptance is still red, the failure is
    deterministic -> stop early and NAME the service with the documented
    remediation, instead of burning 3x ~40 min (Fable review C2).

    "No forward progress" means THE SAME SERVICES ARE STILL BLOCKING, not "the
    log ends on the same name". Those differ exactly when it matters: a deploy
    that walks its whole list twice ends on the last service both times, which
    the old check read as "stuck at that service". Live on 2026-07-28 it
    accused 'usergroup' -- which was READY -- while the actual blocker was
    'launcher', and sent the operator to restart the wrong thing.
    """
    prev_blockers: tuple[tuple[str, str], ...] | None = None
    for attempt in range(1, _DEPLOY_ATTEMPTS + 1):
        ctx.start_detached_once(_DEPLOY_LOG, "wso services deploy --type full",
                                _ALIVE, busy_cmd=WSO_BUSY)
        ctx.wait_while_running(
            _ALIVE,
            label=f"wso services deploy (attempt {attempt}/{_DEPLOY_ATTEMPTS}, ~40 min)",
            logfile=_DEPLOY_LOG,
            stall_after=_STALL_AFTER, on_stall=_KILL)
        ok, detail, blockers = _acceptance(ctx)
        if ok:
            if attempt > 1:
                ctx.report(f"acceptance green after attempt {attempt} ✔")
            return
        last = _last_service(ctx)
        if attempt > 1 and blockers and blockers == prev_blockers:
            # Acceptance ran seconds after the process ended -- far too early to
            # call anything deterministic. A service redeployed in this very
            # attempt may still be registering its readiness. Give it a real
            # settle window and ask again before declaring the failure
            # permanent; the whole point of the retry is the transient case.
            ctx.report(f"same blockers as the previous attempt — waiting "
                       f"{_SETTLE // 60} min before calling it stuck ...")
            time.sleep(_SETTLE)
            ok, detail, blockers = _acceptance(ctx)
            if ok:
                ctx.report(f"acceptance green after settling ✔")
                return
        if attempt > 1 and blockers and blockers == prev_blockers:
            # WHERE the deploy stopped outranks WHICH services are not READY.
            # Readiness only lists the ~20 Access services, so when an
            # INFRASTRUCTURE service blocks -- opensearch, kafka, redis -- it
            # never appears in `blockers`, and all twenty Access services show
            # up instead as downstream casualties. Live on 2026-07-28 this
            # printed twenty innocent names, twenty remediation commands, and
            # the sentence "these services deployed but did not become READY"
            # about services that had never been deployed at all.
            suspect = last if last and last not in {n for _k, n in blockers} else ""
            names = ", ".join(f"{n} ({k.replace('_', ' ')})" for k, n in blockers)
            if suspect:
                head = (f"the deploy stopped at '{suspect}' twice and never "
                        "reached the rest.\n"
                        f"  Blocked downstream ({len(blockers)}, not the cause): "
                        f"{names[:200]}\n")
                fix = f"       cd {ctx.cluster_dir} && wso services deploy -s {suspect}"
            else:
                head = (f"the same service(s) blocked acceptance twice: {names}.\n"
                        "  They deployed but never became READY.\n")
                fix = "\n".join(
                    f"       cd {ctx.cluster_dir} && wso services deploy -s {n}"
                    for _k, n in blockers[:5])
            raise RemoteError(
                "wso services deploy stuck",
                SshResult(1,
                    f"{head}"
                    f"{detail}\n"
                    "Not transient. Documented remediation (Restart a Service):\n"
                    "  1. Stop and purge the job in the Nomad UI.\n"
                    "  2. On the bootstrap -- wso only works from the cluster "
                    f"directory:\n{fix}\n"
                    "Common causes: an unreachable logging target in profile.yml, "
                    "or corrupted Nomad state after an interrupted deploy."))
        prev_blockers = blockers
        if attempt < _DEPLOY_ATTEMPTS:
            # Say WHY, not just how far. "reached: usergroup" tells the operator
            # nothing about whether one service is still settling or twenty
            # never deployed -- and those call for very different reactions.
            # `detail` already names them; it was being computed and dropped.
            ctx.report(f"acceptance not green after attempt {attempt} "
                       f"(reached: {last or '?'}) — {detail}")
            ctx.report(f"re-running (attempt {attempt + 1}/{_DEPLOY_ATTEMPTS}) ...")
            time.sleep(30)  # let the just-started allocations settle first


def explain_failure(ctx: Context, exc: Exception) -> str:
    if isinstance(exc, RemoteError):
        out = exc.result.output
        if exc.step == "wso access bootstrap":
            return (
                "wso access bootstrap failed -- access-profile.yml or its "
                "prerequisites.\n"
                "  - tenant/domain covered by the certificate? (certs cross-check)\n"
                "  - LB IP correct and <tenant>.<domain> resolves there?\n"
                f"  - wso said:\n{out}"
            )
        if exc.step in ("phase 70 acceptance", "wso services deploy stuck"):
            return (
                "Phase 70 not accepted -- checked BOTH gates "
                "(check-service-readiness AND healthcheck).\n"
                f"{out}\n"
                "  - Advisory-only issues (logging/telegraf) are tolerated; a "
                "critical service or an unhealthy platform component is not.\n"
                f"  - Re-run `axs status -c {ctx.local_name}` after a short "
                "wait; some services settle."
            )
        return f"Phase 70 step '{exc.step}' failed (exit {exc.result.rc}):\n{out}"
    return str(exc)
