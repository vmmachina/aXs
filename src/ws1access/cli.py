"""Command line entry point.

Deliberately thin: it parses arguments and calls into the core. All validation
and all deployment logic lives in the phase modules, never here -- so that a
future web UI can drive the exact same code without anything being reimplemented.
"""

from __future__ import annotations

import argparse
import sys

# Single source of truth -- this used to be a second literal that could drift
# from the package version.
from . import __version__

# Phase graph. Not a linear list: the load balancer only depends on preflight,
# so it can be prepared while the VMs are still booting. It must, however, be
# complete before services deploy, because access-profile.yml needs the LB IP
# and certificate.
PHASES: list[tuple[str, str, tuple[str, ...]]] = [
    # Descriptions state what the phase ACTUALLY does -- preflight does not look
    # at the certificate (that cross-check runs in `configure`, against the PFX),
    # and phase 30 never configures the load balancer, it only verifies that DNS
    # points at it.
    ("00_preflight",    "DNS, vCenter login, ovftool version, OVA",      ()),
    ("10_vms",          "Deploy node VMs via ovftool",                   ("00_preflight",)),
    ("20_nodes_ready",  "Wait for SSH, verify network configuration",    ("10_vms",)),
    ("30_lb",           "Verify DNS points at the load balancer",        ("00_preflight",)),
    ("40_bootstrap",    "Asset bundle, wso CLI, EULA, wso configure",    ("20_nodes_ready",)),
    ("50_cluster_init", "wso access init, cp-cluster.ini, SSH trust",    ("40_bootstrap",)),
    ("60_platform",     "wso cp deploy, wso healthcheck",                ("50_cluster_init",)),
    ("70_services",     "access-profile.yml, wso services deploy",       ("60_platform", "30_lb")),
    ("80_tenant",       "wso access create-tenant",                      ("70_services",)),
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="axs",
        description="Guided deployment for Omnissa Access 26.07 (Control Plane).",
    )
    # The tool is aXs; ws1access is only the internal package name. --version is
    # operator-facing, so it says aXs (matching the command, the banner and the
    # README), not the import name.
    p.add_argument("--version", action="version", version=f"aXs {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("phases", help="List deployment phases and their dependencies")

    # -c names the LOCAL folder clusters/<name>/ (config.yml, certs, deploy.log).
    # That is a different thing from cluster.name in the dialog, which names the
    # working directory /root/<name> on the bootstrap node. They may differ.
    _C_HELP = "Local cluster folder under clusters/ (required)"

    configure = sub.add_parser("configure", help="Interactive dialog; writes config.yml")
    # -c is required here too, like deploy/status/validate. It used to be
    # optional and silently fell back to a 'default' cluster -- so you could
    # configure without naming a cluster but not deploy without one, and a
    # forgotten -c wrote clusters/default/config.yml by surprise. A cluster is
    # always named explicitly now; nothing acts on an unnamed 'default'.
    configure.add_argument("-c", "--cluster", required=True, help=_C_HELP)

    deploy = sub.add_parser("deploy", help="Run phases that are not yet complete")
    deploy.add_argument("-c", "--cluster", required=True, help=_C_HELP)
    deploy.add_argument("-p", "--phase", help="Run only this phase")
    # Without this, the drift warning from phase 50 names a way out that does
    # not exist: `-p 50_cluster_init` probes first and skips the phase as
    # "already done", which is precisely the state the warning is about.
    # Deliberately restricted to -p: forcing a whole run would re-do phases
    # whose probes are the only thing standing between a re-run and a second
    # deploy against a live cluster.
    deploy.add_argument("--force", action="store_true",
                        help="With -p: run the phase even if its probe says "
                             "it is already done")

    status = sub.add_parser("status", help="Probe live state of every phase")
    status.add_argument("-c", "--cluster", required=True, help=_C_HELP)

    val = sub.add_parser("validate", help="Static config checks (no network)")
    val.add_argument("-c", "--cluster", required=True, help=_C_HELP)

    return p


def cmd_phases() -> int:
    width = max(len(name) for name, _, _ in PHASES)
    for name, desc, deps in PHASES:
        after = f"  (after {', '.join(deps)})" if deps else ""
        print(f"  {name:<{width}}  {desc}{after}")
    return 0


def cmd_validate(cluster: str) -> int:
    from . import validate

    cfg, load_err = _load_config(cluster)
    if load_err:
        print(load_err, file=sys.stderr)
        return 1
    errs = validate.validate_config(cfg)
    if not errs:
        print("config ok")
        return 0
    print(f"{len(errs)} problem(s) in the config:", file=sys.stderr)
    for e in errs:
        print(f"  - {e}", file=sys.stderr)
    return 1


def cmd_status(cluster: str) -> int:
    from . import config
    from .phases import REGISTRY

    ctx = config.context(cluster)
    width = max(len(name) for name, _, _ in PHASES)
    for name, desc, _ in PHASES:
        phase = REGISTRY.get(name)
        if phase is None:
            print(f"  {name:<{width}}  --      (not implemented)")
            continue
        probe = phase.is_done(ctx)
        mark = "DONE" if probe.done else "OPEN"
        first = probe.detail.splitlines()[0] if probe.detail else desc
        print(f"  {name:<{width}}  {mark:<6}  {first}")
        # A phase can be done AND have something the operator must see -- see
        # Probe.warning. Printing only `detail` here is what made phase 50's
        # config drift invisible in exactly the command meant to reveal state.
        for line in (probe.warning or "").splitlines():
            print(f"  {'':<{width}}          {line}")
    return 0


def cmd_deploy(cluster: str, only: str | None, force: bool = False) -> int:
    # One deploy per cluster. Held for the whole run, both paths -- see
    # runlock.py for why a remote guard alone is not enough.
    from .runlock import AlreadyRunning, ClusterLock
    lock = ClusterLock(cluster)
    try:
        lock.acquire()
    except AlreadyRunning as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        return _deploy_locked(cluster, only, force)
    finally:
        lock.release()


def _load_config(cluster: str):
    """A cluster's config, or (None, message) when it cannot be READ or PARSED.

    config.load raises on a missing file or broken YAML, and those used to reach
    the operator as a raw traceback -- from `axs deploy` and `axs validate`
    alike, since main() catches only KeyboardInterrupt. Turned into a named
    message here so a mis-indented line or a typo'd path reads like every other
    config problem, not like a tool crash.
    """
    import yaml

    from . import config
    try:
        return config.load(cluster), None
    except FileNotFoundError as exc:
        return None, str(exc)
    except yaml.YAMLError as exc:
        return None, (f"clusters/{cluster}/config.yml is not valid YAML -- fix "
                      f"the syntax and retry.\n  {exc}")


def _deploy_locked(cluster: str, only: str | None, force: bool = False) -> int:
    # Validate BEFORE anything -- before the TUI/plain split, before a single
    # password prompt, before any network. `axs deploy` never used to run the
    # static checks (only `axs validate` did), so an accidental entry -- a
    # half-configured NFS, a leading colon in nfs_path, a typo'd version --
    # flowed straight into phase 50/60 and surfaced an hour later, or hung on an
    # NFS mount to a wrong host. Catch it here, with the cause named, and change
    # nothing. Same gate for the TUI and the plain path, so it cannot be fixed
    # in one and not the other.
    from . import config, validate
    cfg, load_err = _load_config(cluster)
    if load_err:
        print(load_err, file=sys.stderr)
        return 1
    errs = validate.validate_config(cfg)
    if errs:
        print("This config would break the deploy -- nothing was changed:",
              file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        print("Fix these (see `axs validate -c <cluster>`) and re-run.",
              file=sys.stderr)
        return 1

    # Interactive terminal + full run -> the live TUI (credentials form, phase
    # board). Piped output (| tee) or a single-phase run -> the plain path.
    if only is None and sys.stdout.isatty():
        from . import tui_deploy
        return tui_deploy.run(cluster)

    from .phases import REGISTRY, dependents

    ctx = config.context(cluster)
    # Give the phases somewhere to report to. Without this every ctx.report()
    # is a no-op here (context.py), and the plain path silently swallowed the
    # very messages that matter most in a scripted run -- the NFS verdict, the
    # precheck findings, and wso's own NTP/NFS warnings.
    ctx.progress = lambda msg: print(f"  {msg}", flush=True)
    # Fail fast on a wrong configuser password (otherwise phase 20 spins for
    # 20 min and can trigger faillock lockouts).
    if ctx.password_refused():
        print(f"configuser password refused by {ctx.bootstrap_ip} -- check it "
              "and retry. Nothing was changed.", file=sys.stderr)
        return 1
    order = [name for name, _, _ in PHASES if name in REGISTRY]
    if only:
        if only not in REGISTRY:
            print(f"Phase {only!r} is not implemented yet.", file=sys.stderr)
            return 2
        order = [only]

    # Probe every phase first (which ones are already done?). This round makes
    # many ssh round-trips, so narrate it -- a silent minute after the password
    # prompts reads as a hang.
    done: set[str] = set()
    for name in [n for n, _, _ in PHASES if n in REGISTRY]:
        print(f"probing {name} ...", end=" ", flush=True)
        try:
            probe = REGISTRY[name].is_done(ctx)
        except Exception as exc:  # noqa: BLE001
            # A probe is not supposed to raise, and BOTH readings of one that
            # does are wrong: "not done" runs a phase against a live cluster on
            # the strength of a bug, "done" is the silent green. Stop and name
            # it. This guard was first added only to the re-probe below -- one
            # of four probe call sites, which is this project's signature
            # defect exactly.
            print("ERROR")
            print(f"{name}: its probe raised {type(exc).__name__}: {exc}\n"
                  "  Nothing was changed. This is a defect or a config.yml the "
                  "probe cannot read; fix the cause and re-run.", file=sys.stderr)
            return 1
        print("done" if probe.done else "todo")
        if probe.done:
            done.add(name)
        if probe.warning:
            for line in probe.warning.splitlines():
                print(f"    {line}")
        if probe.done:
            pass
        elif probe.detail:
            # Say WHY, or a transient probe error is indistinguishable from
            # genuinely missing state.
            first = str(probe.detail).strip().splitlines()[0]
            print(f"    -> {first[:160]}")

    if force and only:
        # Only the phase the operator NAMED. The probes are what keep a re-run
        # from becoming a second deploy against a live cluster, so forcing the
        # whole order would remove the guard, not the inconvenience.
        done.discard(only)
        print(f"{only}: probe says done -- running anyway (--force).")

    stale: set[str] = set()
    for name in order:
        phase = REGISTRY[name]
        if name in stale:
            # The up-front probe for this phase was taken before one of its
            # dependencies ran, so it describes a cluster that no longer
            # exists. Ask again -- and only ask: a phase that is still done
            # stays skipped (see phases.dependents).
            stale.discard(name)
            try:
                probe = phase.is_done(ctx)
            except Exception as exc:  # noqa: BLE001
                # A probe is not supposed to raise, and the two readings of one
                # that does are both wrong: "not done" runs a phase against a
                # live cluster on the strength of a bug, "done" is the silent
                # green. Stop, and say which phase and why.
                print(f"{name}: re-checking after an earlier phase ran raised "
                      f"{type(exc).__name__}: {exc}", file=sys.stderr)
                return 1
            for line in (probe.warning or "").splitlines():
                print(f"    {line}")
            if probe.done:
                done.add(name)
            elif name in done:
                done.discard(name)
                first = str(probe.detail or "").strip().splitlines()
                print(f"{name}: re-checked after an earlier phase ran -- no "
                      f"longer done{': ' + first[0] if first else ''}")
        if name in done:
            print(f"{name}: already done, skipping.")
            continue
        missing = [d for d in phase.DEPS if d in REGISTRY and d not in done]
        if missing:
            print(f"{name}: waiting on {', '.join(missing)} -- not done.", file=sys.stderr)
            return 1
        print(f"{name}: running ...")
        try:
            phase.run(ctx)
        except Exception as exc:  # noqa: BLE001 -- surfaced via explain_failure
            print(phase.explain_failure(ctx, exc), file=sys.stderr)
            return 1
        try:
            final = phase.is_done(ctx)
        except Exception as exc:  # noqa: BLE001
            # Worse than the others: the phase has already DONE its work, so a
            # bare traceback here reads as "the deploy broke" when in fact only
            # the confirmation did.
            print(f"{name}: ran, but the probe that confirms it raised "
                  f"{type(exc).__name__}: {exc}\n"
                  f"  The work itself may well have succeeded -- re-run to "
                  f"re-check.", file=sys.stderr)
            return 1
        if not final.done:
            print(f"{name}: run finished but probe still reports not done.", file=sys.stderr)
            return 1
        done.add(name)
        # Whatever depends on this phase was probed against the cluster as it
        # was BEFORE this ran. Those answers are no longer evidence.
        stale |= dependents(name)
        # A phase that just ran can still have something to say -- phase 80
        # measuring its own tenant URL as unreachable is the case. This probe's
        # warning used to be discarded, on the very run where it matters most.
        for line in (final.warning or "").splitlines():
            print(f"    {line}")
        print(f"{name}: done.")
    # Surface the admin onboarding block (login URL + reset-password link).
    p80 = REGISTRY.get("80_tenant")
    if p80 is not None and hasattr(p80, "onboarding_info"):
        try:
            info = p80.onboarding_info(ctx)
        except Exception:  # noqa: BLE001
            info = ""
        if info:
            print("\n=== Admin onboarding (reset link is single-use and expires) ===")
            print(info)
    return 0


def main(argv: list[str] | None = None) -> int:
    # Line-buffer stdout even when piped (e.g. `axs deploy | tee deploy.log`):
    # otherwise Python block-buffers and the phase output appears only at the
    # end, which reads as a hang after the password prompts.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "phases":
            return cmd_phases()
        if args.command == "status":
            return cmd_status(args.cluster)
        if args.command == "validate":
            return cmd_validate(args.cluster)
        if args.command == "configure":
            from . import tui
            # No hard gate here any more: the TUI opens on its own Requirements
            # page, which shows the same scan (live, incl. the ovftool version),
            # blocks Next while something is missing and offers Re-check. That
            # way the requirements are ALWAYS seen -- not only when they fail.
            # No scan here either: that page runs it on render and fills
            # app.found itself, so doing it twice only delayed the first frame.
            return tui.run(args.cluster, {})
        if args.command == "deploy":
            return cmd_deploy(args.cluster, args.phase, args.force)
    except KeyboardInterrupt:
        # Ctrl-C anywhere (TUI or a long-running phase): exit cleanly with 130
        # (terminated by SIGINT) instead of dumping a traceback.
        print("\nAborted.", file=sys.stderr)
        return 130

    if args.command is None:
        build_parser().print_help()
        return 0

    print(f"'{args.command}' is not implemented yet -- skeleton only.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
