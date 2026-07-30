"""Phase 50 -- Initialize the Control Plane cluster.

Documented procedure (Omnissa install guide, from the bootstrap, as root unless
noted):

    cd /root/<cluster> && wso access init -n <cluster> -s <size>
    # -> creates cp-cluster/cp-cluster.ini (sample) and profile.yml
    # populate cp-cluster/cp-cluster.ini (we generate it, see cluster_ini.py)
    wso access validate

Auth (cluster.auth, offered in the dialog):
  * key      -- ssh-keygen + ssh-copy-id FROM the bootstrap, private key staged
                into the working dir, host keys pre-seeded into root's
                known_hosts (wso's ansible runs as root; an empty known_hosts is
                the likely reason the key path failed while password worked).
  * password -- ansible_password (configuser), the fallback the lab used first.

Done-probe: `wso access validate` returns 0 -- it checks the inventory and
prerequisites, so it only passes once the ini is written correctly.

The bootstrap IP is deliberately NOT in the node list: validation rejects it.
"""

from __future__ import annotations

import shlex

import yaml

from .. import cluster_ini, nfscheck, pending, profile_yml
from ..context import Context, RemoteError, WSO_BUSY
from ..ssh import SshResult
from . import Probe

NAME = "50_cluster_init"
DEPS = ("40_bootstrap",)


def _ini_path(ctx: Context) -> str:
    return f"{ctx.cluster_dir}/cp-cluster/cp-cluster.ini"


# The private key is STAGED on disk under the cluster dir, but the ini's
# ansible_ssh_private_key_file is consumed INSIDE the wso deploy container, which
# bind-mounts <cluster_dir>/cp-cluster at /workdir. So the ini must reference the
# CONTAINER path, not the host path. The docs / update-cluster-ini.sh write the
# host path -- which does not exist in the container -- so the documented key
# path silently fails; this is the fix (verified in the lab 2026-07-22).
_KEY_HOST_REL = "cp-cluster/private-key/id_ed25519"       # relative to cluster_dir (staging)
_KEY_IN_CONTAINER = "/workdir/private-key/id_ed25519"      # what the ini must say


def is_done(ctx: Context) -> Probe:
    r = ctx.bootstrap_run("wso access validate")
    if not r.ok:
        return Probe(False, detail=r.output.strip())
    apply_now, lines = _drift_check(ctx)
    if apply_now:
        # RED, not a warning. This phase owns the file, so it is the one that
        # can put the difference right -- and unlike a warning, being red is
        # what actually makes it run. It can also go green again the moment it
        # has: that is the test docs/09 §4 sets for turning a phase red at all.
        return Probe(False, detail="\n".join(lines))
    return Probe(True, detail=r.output.strip(), warning="\n".join(lines))


def _drift_check(ctx: Context) -> tuple[list[str], list[str]]:
    """Compare config.yml with the bootstrap's profile.yml.

    Returns (keys this phase should apply, lines for the operator).

    `wso access validate` answers "are the files from the LAST run consistent",
    never "do they match today's config.yml". So a setting added after a
    successful deploy -- an NFS backup target, the very thing wso's own warning
    asks for -- produced `50_cluster_init: already done`, then `60_platform:
    already done` off the historical folder hash, and a completely green run
    with no backup in it (docs/08 B1).

    The split between the two return values is the whole design (docs/09 §4):

      * Keys a re-run can genuinely apply make this phase red, so it runs,
        patches the file, and leaves a marker that phase 60 rolls out.
      * Keys that would need a cluster rebuild -- central logging -- are only
        ever WARNED about. Going red over one would leave a phase that can
        never go green again, which is worse than the drift it reports.

    Lines are RETURNED, not reported: `ctx.report` is a no-op during a probe
    round (no sink is attached yet), so reporting from here reached the plain
    path only -- and not `axs status` or the TUI, which is the default.
    """
    settings = ctx.deployment_settings
    if not profile_yml.is_configured(settings):
        return [], []
    path = f"{ctx.cluster_dir}/profile.yml"
    r = ctx.bootstrap_run(f"cat {shlex.quote(path)}")
    if not r.ok:
        # Not the same as "they agree". Phase 50 has been done at least once
        # for us to be here, so the file should exist; saying nothing would be
        # the silent green in a new costume. Not red either: an ssh hiccup must
        # not trigger a re-init, and the phase's own work is verified below
        # when it does run.
        return [], ["WARNING — could not read profile.yml on the bootstrap, so "
                    "config.yml and the cluster were NOT compared."]
    # actionable_keys, NOT drift_keys: a key config.yml no longer sets but the
    # bootstrap still carries is a real difference and `patch` cannot remove it.
    # Letting it drive the red verdict made this phase fail identically on every
    # run with no way out (found in review; see profile_yml.actionable_keys).
    keys = profile_yml.actionable_keys(r.output, settings)
    if keys is None:
        # "I could not read it" is not "it disagrees" (docs/08 A9). Reporting
        # the first as the second would name a parse failure as a drifted key.
        return [], ["WARNING — profile.yml on the bootstrap could not be parsed, "
                    "so it was NOT compared with config.yml."]
    orphans = profile_yml.orphan_keys(r.output, settings)
    if not keys and not orphans:
        return [], _pending_warning(ctx)
    diffs = profile_yml.drift(r.output, settings)
    apply_now, needs_rebuild = profile_yml.classify(keys)
    lines: list[str] = []
    if apply_now:
        lines.append(
            f"config.yml and the bootstrap's profile.yml disagree on "
            f"{len(apply_now)} key(s). This phase will rewrite profile.yml and "
            f"phase 60 will roll the change out:")
        lines += [f"  {line}" for line in diffs
                  if line.split(":", 1)[0] in apply_now]
    if needs_rebuild:
        lines.append(
            "WARNING — these differ too, and a re-run CANNOT apply them. "
            "Omnissa's own note: updating the logging configuration after the "
            "first deployment requires a full redeployment of the cluster. "
            "profile.yml will be brought in line so the next rebuild is "
            "correct, but the running cluster keeps its current logging:")
        lines += [f"  {line}" for line in diffs
                  if line.split(":", 1)[0] in needs_rebuild]
    if orphans:
        lines.append(
            "NOTE — the bootstrap still carries these, and config.yml no longer "
            "sets them. aXs writes values, it does not remove settings that "
            "nobody asked it to remove, so removing the line from config.yml "
            "does NOT unset them on the cluster:")
        lines += [f"  {line}" for line in diffs
                  if line.split(":", 1)[0] in orphans]
    return apply_now, lines


def _pending_warning(ctx: Context) -> list[str]:
    """The files agree -- but has the change actually been rolled out yet?

    Without this, an abort between phase 50 and phase 60 reads as fully in
    sync: profile.yml is correct, so there is no drift left to find, and the
    only remaining record that the cluster has not seen it is the marker. Phase
    60 is the one that acts on it; this says so here too, because phase 50 is
    where the operator looks after changing a setting.
    """
    state = pending.read(ctx)
    if state.state == "unknown":
        return [f"WARNING — {state.reason}."]
    if state.state != "pending":
        return []
    return ["profile.yml is up to date, but the platform has NOT been "
            "rolled out with it yet — phase 60 will do that:"] + [
        f"  {key}" for key in state.keys]


def run(ctx: Context) -> None:
    # These phases write on the bootstrap -- the asset bundle and `wso
    # configure` here, the inventory and profile.yml there. Doing that while
    # another wso operation is running means two writers on one cluster, and
    # unlike phases 60/70/80 there was no guard at all: a single failed SSH
    # probe is enough to make a completed phase look "todo" again.
    if ctx.bootstrap_run(WSO_BUSY).ok:
        raise ctx.busy_error()

    nodes = ctx.platform_ips + ctx.access_ips

    # 1. Initialize (idempotent: only if the inventory doesn't exist yet).
    ctx.bootstrap_step(
        "wso access init",
        f"test -f cp-cluster/cp-cluster.ini || "
        f"wso access init -n {ctx.cluster_name} -s {ctx.size}",
    )

    # 2. Auth: key (ssh-copy-id from the bootstrap + private-key + host keys) or
    #    password. cluster.auth chooses; the dialog will offer both.
    if ctx.auth == "key":
        ctx.establish_trust(nodes)          # ssh-keygen + ssh-copy-id from bootstrap
        ctx.scan_host_keys(nodes)           # host keys -> root known_hosts (for wso)
        ctx.bootstrap_step(
            "stage private key",
            "install -d cp-cluster/private-key && "
            "cp /home/configuser/.ssh/id_ed25519 cp-cluster/private-key/ && "
            "chmod 400 cp-cluster/private-key/id_ed25519",
        )
        ini = cluster_ini.render(ctx.platform_ips, ctx.access_ips,
                                 size=ctx.size, private_key_path=_KEY_IN_CONTAINER)
    else:
        ini = cluster_ini.render(ctx.platform_ips, ctx.access_ips,
                                 size=ctx.size, password=ctx.configuser_password)

    ctx.write_file(_ini_path(ctx), ini)

    # 3. Operational settings (NTP / NFS / logging / Nomad bridge) into the
    #    profile.yml that `wso access init` just created. Only when the operator
    #    configured something -- otherwise the file is not touched at all and
    #    the cluster deploys with wso's defaults, exactly as before this existed.
    _apply_profile(ctx)

    # 4. Validate (also the done-probe).
    ctx.bootstrap_step("wso access validate", "wso access validate")


def _apply_profile(ctx: Context) -> None:
    """Patch profile.yml in place: read what wso wrote, change only what the
    operator set, write it back. Never regenerated -- wso owns four keys in
    there, and its comments are the operator's reference."""
    settings = ctx.deployment_settings
    if not profile_yml.is_configured(settings):
        return
    # Logging passwords are never stored in config.yml; they are collected at
    # deploy time and merged in here, right before the file is written.
    missing = profile_yml.needs_passwords(settings)
    if missing:
        have = ctx.logging_passwords or {}
        absent = [m for m in missing if not have.get(m)]
        if absent:
            ctx.report(f"WARNING — no password given for {', '.join(absent)}; "
                       "writing the logging config without it. wso will not be "
                       "able to authenticate against that backend.")
        settings = profile_yml.with_passwords(settings, have)
    path = f"{ctx.cluster_dir}/profile.yml"
    r = ctx.bootstrap_run(f"cat {shlex.quote(path)}")
    if not r.ok or not r.output.strip():
        raise RemoteError(
            "read profile.yml",
            SshResult(1, f"{path} not found on the bootstrap after "
                         "`wso access init` -- cannot apply the operational "
                         "settings. Deploy without them, or check the init step."))
    # The marker goes down BEFORE the file changes, and the order is the whole
    # point (see pending.mark). Patch first and a failed marker write is
    # unrecoverable: profile.yml would be correct, the drift therefore gone on
    # the next run, and the rollout owed forever with nothing left to notice
    # it. In this order the same failure leaves the file stale, so the drift
    # check finds it again and the next run retries everything.
    keys = profile_yml.actionable_keys(r.output, settings)
    if keys is None:
        # Could not compare, so we do not know whether a rollout is owed --
        # and "could not ask" must not be read as "nothing to do" (docs/08 E1).
        # Marking costs one redundant `wso cp deploy`; not marking costs the
        # setting.
        pending.mark(ctx, ["profile.yml could not be compared -- "
                           "rolling out to be safe"])
        apply_now: list[str] = []
    else:
        apply_now, _needs_rebuild = profile_yml.classify(keys)
        if apply_now:
            pending.mark(ctx, apply_now)

    # Never hand the bootstrap a file that no longer parses. `patch` appends its
    # block at the end, and a remote file containing a `...` document-end marker
    # therefore got aXs's settings placed in a SECOND YAML document -- valid
    # text, unreadable configuration, and wso reads this file too. It was written
    # anyway, and only the read-back below noticed, on every run, without saying
    # that aXs had broken the file itself.
    patched = profile_yml.patch(r.output, settings)
    try:
        shape = yaml.safe_load(patched)
    except yaml.YAMLError as exc:
        shape = exc
    if not isinstance(shape, dict):
        raise RemoteError(
            "patch profile.yml",
            SshResult(1, (
                "the patched profile.yml would not be valid YAML, so it was NOT "
                f"written -- {path} on the bootstrap is unchanged. This happens "
                "when the file contains something the patcher cannot append "
                "past, a `...` document-end marker being the known case. Fix or "
                "remove the unusual part of the file by hand, or delete the file "
                "and let `wso access init` recreate it.")))
    ctx.write_file(path, patched)

    # Prove the patch did what the comparison asked for, instead of trusting
    # that it did. If `drift_keys` can report a key that `patch` does not
    # actually write, this phase would be red forever and the engine would say
    # only "run finished but probe still reports not done" -- a fatal abort with
    # no diagnosis. Said here, once, with the keys named.
    #
    # Checked against `apply_now` ONLY -- the keys this call actually set out to
    # write. Comparing against every difference made the phase fail over keys it
    # never promised to change: a leftover the operator removed from config.yml
    # (which `patch` cannot remove), and a `logging.*` value, for which
    # `classify` explicitly guarantees the phase will never go red.
    #
    # For logging this is now defence in depth rather than a live fix: the one
    # shape that reached it -- a syslog entry without a host, which shifted every
    # later entry's index on one side of the comparison only -- is fixed at the
    # source in `_flatten_logging`, and none of the nine hostile logging shapes
    # tried afterwards leaves anything behind. The narrowing stays because the
    # contract is "verify what you promised", and a key added to the comparison
    # but not to the writer would otherwise make this fatal again.
    back = ctx.bootstrap_run(f"cat {shlex.quote(path)}")
    written = profile_yml.actionable_keys(back.output, settings) if back.ok else None
    if written is None:
        raise RemoteError(
            "verify profile.yml",
            SshResult(1, f"{path} was written but could not be read back and "
                         "compared, so it is unknown whether the operational "
                         "settings actually landed."))
    left = [key for key in apply_now if key in written]
    if left:
        raise RemoteError(
            "verify profile.yml",
            SshResult(1, "profile.yml was written, but these settings did not "
                         f"take in the file: {', '.join(left)}. Phase 50 will "
                         f"fail the same way on every run until {path} on the "
                         "bootstrap is corrected by hand."))

    for line in profile_yml.summary(settings):
        ctx.report(f"profile.yml: {line}")
    _verify_nfs(ctx, settings)


def _verify_nfs(ctx: Context, settings: dict) -> None:
    """Prove the backup target works, now that the bootstrap can reach it.

    Deliberately NOT fatal. NFS is optional, the operator may be configuring it
    ahead of the server being ready, and refusing to deploy over it would turn
    an optional setting into a gate. But a target that silently does not work
    is worse than none -- so the verdict is stated plainly and lands in the
    deploy log.
    """
    host = str(settings.get("nfs_host") or "").strip()
    path = str(settings.get("nfs_path") or "").strip()
    if not host or not path:
        return
    version = settings.get("nfs_version", 4)

    # Where the mount will REALLY happen. `wso cp deploy` puts the NFS volume
    # into the Nomad job definitions, and those run on the platform nodes; the
    # bootstrap carries no service containers at all (docs/08 C1, C4). Checking
    # only the bootstrap let an export limited to specific hosts pass here and
    # break the deploy afterwards -- docs/08 B8.
    #
    # The bootstrap is checked too, and FIRST: it is the machine that answers
    # fastest and where `showmount` is most likely to work, so a plain typo in
    # the path is caught before three more nodes repeat the same failure.
    targets = [("bootstrap", ctx.bootstrap_ip)] + [
        (f"platform node {ip}", ip) for ip in ctx.platform_ips]

    failures: list[str] = []
    untested: list[str] = []
    verdicts: list[tuple[str, nfscheck.NfsResult]] = []
    for label, ip in targets:
        ctx.report(f"verifying the NFS backup target {host}{path} "
                   f"from the {label} ...")
        runner = (ctx.bootstrap_run if ip == ctx.bootstrap_ip
                  else (lambda command, _ip=ip, **kw: ctx.node_root_run(_ip, command)))
        res = nfscheck.check(runner, host, path, version, where=label)
        if res.ok:
            ctx.report(f"  {label}: verified ✔  ({res.detail})")
            verdicts.append((label, res))
        elif res.stage == "access":
            # We could not ask this machine. That is a statement about our
            # access to it, not about the customer's NFS server, and it must
            # not be counted as either a pass or a failure of the target.
            ctx.report(f"  {label}: NOT TESTED — {res.detail}")
            untested.append(f"{label}: {res.detail}")
        else:
            ctx.report(f"  {label}: NOT usable — {res}")
            failures.append(f"{label}: {res}")
            verdicts.append((label, res))

    if untested:
        ctx.report(f"NOTE — {len(untested)} of {len(targets)} machines could "
                   "not be tested at all (see above). Nothing follows from "
                   "that about the NFS target.")
    if not failures:
        tested = len(targets) - len(untested)
        ctx.report(f"NFS backup target verified from {tested} of "
                   f"{len(targets)} machines ✔")
    else:
        ctx.report(f"WARNING — NFS backup target NOT usable from "
                   f"{len(failures)} of {len(targets)} machines:")
        for line in failures:
            ctx.report(f"    {line}")
        # An access list is ONE explanation for "some yes, some no", and only
        # when the failures are mounts being refused. nfs-utils missing on one
        # node, or a node whose DNS resolves nfs_host differently, produce the
        # same split for entirely different reasons -- and naming a cause the
        # evidence does not carry is how an operator spends a day on exports
        # while the fault is elsewhere.
        mount_only = all(res.stage == "mount" for _label, res in verdicts
                         if not res.ok)
        if failures and len(failures) < len(verdicts) and mount_only:
            ctx.report("    Some machines mounted it and others were refused — "
                       "that points at an export or firewall limited to certain "
                       "hosts. The containers mount from the PLATFORM nodes, so "
                       "those are the ones that have to work.")
        # Whether disaster recovery is actually broken depends on WHICH machine
        # failed. The bootstrap never mounts this share; saying "DR would not
        # work" because of it would be false.
        nodes_failed = any(label != "bootstrap" for label, res in verdicts
                           if not res.ok)
        if nodes_failed:
            ctx.report("    The deploy continues; disaster recovery would not "
                       "work until this is fixed.")
        else:
            ctx.report("    Only the bootstrap failed, and it never mounts this "
                       "share — the machines that do all passed. Worth fixing, "
                       "but backups are not affected.")


def explain_failure(ctx: Context, exc: Exception) -> str:
    if isinstance(exc, RemoteError):
        out = exc.result.output.lower()
        if exc.step == "wso access validate":
            return (
                "wso access validate failed -- the inventory or prerequisites are "
                "not satisfied.\n"
                "  - cp-cluster.ini node lists / roles?\n"
                "  - Is the bootstrap IP wrongly present in the inventory? (rejected)\n"
                f"  - wso said:\n{exc.result.output}"
            )
        return (
            f"Phase 50 step '{exc.step}' failed (exit {exc.result.rc}):\n"
            f"{exc.result.output}"
        )
    return str(exc)
