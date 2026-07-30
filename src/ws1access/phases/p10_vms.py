"""Phase 10 -- Deploy the node VMs via ovftool.

The command builder lives in ovftool.py (password URL-encoded into the vi://
target, verified in the lab). This phase runs one ovftool per node LOCALLY
(ovftool talks to vCenter from the tool host, not over SSH) and confirms the
result against the vCenter REST API.

Done-probe: every configured VM exists and is POWERED_ON in vCenter.
"""

from __future__ import annotations

import atexit
import re
import subprocess
import sys
import threading
from pathlib import Path

from .. import ovftool
from ..context import Context, clean_tail
from ..vcenter import VCenter, VCenterError
from . import Probe

NAME = "10_vms"
DEPS = ("00_preflight",)

# ovftool runs LOCALLY; aborting mid-upload can leave a half-deployed VM
# that blocks the next run on a name clash. Do not restart while this runs.
RESTART_SAFE = False
RESTART_NOTE = "an ovftool upload is in flight -- aborting can leave a half-deployed VM"


def _vc(ctx: Context) -> VCenter:
    v = ctx.vcenter
    return VCenter(host=v["host"], user=v["user"], password=v.get("password", ""))


# Every ovftool this process started and has not yet reaped (docs/08 B9).
#
# The deploy engine runs in a DAEMON thread; ovftool is an ordinary child. The
# TUI's exit button ends Python, the daemon thread dies with it -- and ovftool
# keeps uploading, invisibly. The next run then sees a half-deployed VM and
# offers to delete it, while the orphan is still writing into it.
#
# Scope, stated rather than implied: this reaps the ovftool process itself. If
# ovftool spawns children of its own they are NOT covered -- a process group
# kill would reach them, but it needs start_new_session -- and that would also
# detach ovftool from the signals the KERNEL delivers to the whole foreground
# group today: Ctrl-C on the plain path, and SIGHUP when the terminal window is
# closed. Both currently reach ovftool without any help from us. Trading two
# working paths for one unmeasured one is the wrong way round.
_CHILDREN: set[subprocess.Popen] = set()
_CHILDREN_LOCK = threading.Lock()
# How long to let ovftool wind down before insisting. Generous on SIGTERM
# because a clean exit lets it tell vCenter the transfer is over; short on
# SIGKILL because there is nothing left to wait for.
_TERM_WAIT = 10
_KILL_WAIT = 5


def _stop(proc: subprocess.Popen) -> None:
    """SIGTERM, then SIGKILL, in the same shape as the remote stall kill:
    firing a signal and walking away is not the same as the process being gone.

    SIGTERM first, and with a generous wait, is not politeness. ovftool holds a
    transfer lease on vCenter; ending cleanly lets it drop that lease, and
    vCenter then removes the half-written VM itself. Killing outright leaves
    the lease to time out server-side.
    """
    try:
        proc.terminate()
        try:
            proc.wait(timeout=_TERM_WAIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=_KILL_WAIT)
    except (OSError, subprocess.TimeoutExpired):
        # Nothing useful is left to do at interpreter exit, and raising here
        # would replace the operator's real error with this one.
        pass


def _terminate_children() -> None:
    """Stop every ovftool still running. Registered with atexit.

    What this covers, exactly -- the first version of this comment claimed
    more:

      * the TUI's exit button, and Ctrl-C inside the TUI (Textual turns ISIG
        off, so Ctrl-C is a key event that ends the app, not a signal);
      * Ctrl-C on the plain path -- though there the kernel has already sent
        SIGINT to the whole foreground group, ovftool included, so this is the
        belt to that braces;
      * a normal end of the program for any other reason.

    What it does NOT cover: SIGKILL, a hard crash, and -- worth naming because
    it looks covered -- a plain `kill <pid>` or SIGHUP aimed at Python alone.
    Those run no handler. An exception inside the ENGINE THREAD does not end
    the interpreter either; the case where ovftool is still running and its
    reader dies is handled in _run_ovftool, not here.
    """
    with _CHILDREN_LOCK:
        running = [p for p in _CHILDREN if p.poll() is None]
    if running:
        # The last thing the deploy log says is "uploading NN%". Say that it
        # stopped, or the operator learns it from the next run's error.
        print(f"\naXs: stopping {len(running)} running ovftool upload(s) — "
              "the VM(s) being written will be incomplete.", file=sys.stderr)
    for proc in running:
        _stop(proc)


atexit.register(_terminate_children)


# Two kinds of ovftool noise the operator does not want in the live-log box:
#
#  1. "Disk progress: NN%", printed hundreds of times (each overwriting the last
#     via a carriage return; clean_tail splits on \r too). The top progress bar
#     already shows that percentage.
#  2. The OVA's signing CERTIFICATE, which ovftool dumps as a block of base64 --
#     the wall of random-looking text that pops up mid-upload. Pure internals.
#
# Both are dropped. Everything else survives: Opening OVA, Deploying to VI,
# Transfer Completed, and crucially any Error/Warning (those carry words and
# colons, so they never match the base64 shape) -- so a stalled or complaining
# ovftool is still visible, which is the whole reason this phase streams it.
# `^Disk`, not `^Disk progress:`: a read chunk can cut a progress line, leaving a
# partial "Disk p" that the exact prefix would miss. ovftool prints nothing else
# starting with "Disk", so matching the word is safe and catches every fragment.
# Bare "NN%" continuations too.
_UPLOAD_PROGRESS = re.compile(r"^\s*(Disk\b|\d{1,3}%\s*$)")
# A markerless base64 line, as a fallback -- the certificate BLOCK is dropped
# whole below (which also gets its short last line), so this only needs to catch
# stray base64 that arrives without BEGIN/END around it.
_BASE64_LINE = re.compile(r"^\s*[A-Za-z0-9+/]{40,}={0,2}\s*$")
_CERT_BEGIN = "-----BEGIN CERTIFICATE"
_CERT_END = "-----END CERTIFICATE"


def _quiet_upload(text: str) -> str:
    """ovftool output for the live-log box, minus the noise the operator does
    not want during an upload:

      * "Disk progress: NN%" (the top bar already shows the percentage), and
      * the OVA's signing CERTIFICATE, which ovftool dumps as a base64 block --
        the wall of random-looking text that pops up mid-upload.

    Everything else survives, in particular any Error/Warning line (those carry
    words and colons, so they never look like base64) -- a stalled or complaining
    ovftool must still be visible, which is why this phase streams it at all.

    The certificate is dropped as a whole BLOCK between its BEGIN/END markers, so
    its short last line goes too; an unterminated block (a chunk that cut mid
    certificate) drops to the end, which is base64 anyway.
    """
    out: list[str] = []
    in_cert = False
    for ln in text.splitlines():
        stripped = ln.strip()
        if in_cert:
            if stripped.startswith(_CERT_END):
                in_cert = False
            continue                              # drop the body and the END line
        if stripped.startswith(_CERT_BEGIN):
            in_cert = True
            continue                              # drop the BEGIN line
        if _UPLOAD_PROGRESS.match(ln) or _BASE64_LINE.match(ln):
            continue
        out.append(ln)
    return "\n".join(out)


def _run_ovftool(argv: list[str], on_pct, on_out=None) -> tuple[int, str]:
    """Run ovftool streaming its output, reporting upload percent via on_pct.

    ovftool prints progress as 'Disk progress: NN%' separated by carriage
    returns, so the stream is read in chunks (not lines) and scanned for the
    last percentage. on_pct is only called when the value changes.

    on_out receives the accumulated output whenever a line completes, so the
    live-log box shows what ovftool is saying WHILE it runs -- the long remote
    phases have had that all along; this one only ever showed a percentage, and
    a stalled or complaining ovftool looked identical to a working one.

    The child is registered while it runs so the exit handler can reach it.
    """
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=0)
    with _CHILDREN_LOCK:
        _CHILDREN.add(proc)
    try:
        buf: list[str] = []
        last_pct = -1
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(256)
            if not chunk:
                break
            buf.append(chunk)
            hits = re.findall(r"(\d{1,3})%", chunk)
            if hits:
                pct = min(int(hits[-1]), 100)
                if pct != last_pct:
                    last_pct = pct
                    on_pct(pct)
            if on_out and "\n" in chunk:
                on_out("".join(buf))
        proc.wait()
        return proc.returncode, "".join(buf)
    finally:
        # Deregister in a finally, not after the return: an exception on the
        # read loop would otherwise leave a finished process in the set for the
        # rest of the run, and the exit handler would poll a stale entry.
        with _CHILDREN_LOCK:
            _CHILDREN.discard(proc)
        # Leaving because something went WRONG is not the same as ovftool
        # having finished. Deregistering a child that is still uploading and
        # then walking away recreates the exact orphan this mechanism exists to
        # prevent -- and it is reachable: on the plain path _run_ovftool runs
        # in the main thread, so a KeyboardInterrupt lands right here. So stop
        # it before letting go of the only handle to it. On the normal path
        # proc.wait() has already returned and this is a no-op.
        if proc.poll() is None:
            _stop(proc)
        # And close the pipe. It was never closed, so every VM leaked one
        # descriptor -- six per small cluster. Harmless at that count, but it
        # is the kind of thing that is only harmless until it is not.
        if proc.stdout is not None:
            proc.stdout.close()


def is_done(ctx: Context) -> Probe:
    names = [n["hostname"] for n in ctx.nodes]
    # Scoped to the configured folder as well as the datacenter: a same-named
    # leftover VM in another folder used to report this phase done, and the node
    # was then never built. When no folder is configured the VMs go to the
    # datacenter root and the folder scope does not apply -- same as run().
    folder = (ctx.vcenter.get("folder") or "").strip() or None
    try:
        states = _vc(ctx).power_states(names, ctx.vcenter.get('datacenter'),
                                       folder=folder)
    except VCenterError as e:
        return Probe(False, detail=str(e))
    missing = [n for n in names if states.get(n) != "POWERED_ON"]
    detail = ", ".join(f"{n}={states.get(n, 'MISSING')}" for n in names)
    return Probe(not missing, detail=detail)


def _ensure_folder(ctx: Context) -> None:
    """Make sure the configured VM folder exists -- creating it if not.

    ovftool only complains about a missing folder AFTER uploading the disk, so
    a typo used to cost a full upload. Checked (and created) up front instead.
    Nothing happens when no folder is configured: then the VMs go to the
    datacenter root, which is ovftool's own default."""
    vc = ctx.vcenter
    folder = (vc.get("folder") or "").strip()
    if not folder:
        return
    client = _vc(ctx)
    dc = vc["datacenter"]
    existing = client.vm_folders(dc)
    if folder in existing:
        return
    if "/" in folder:
        raise RuntimeError(
            f"The VM folder {folder!r} does not exist in {dc}, and aXs only "
            "creates a single folder under the datacenter -- not a nested "
            "path. Create it in vCenter, or use a plain folder name.")
    ctx.report(f"VM folder {folder!r} does not exist in {dc} — creating it ...")
    client.create_vm_folder(dc, folder)
    ctx.report(f"VM folder {folder!r} created ✔")


def run(ctx: Context) -> None:
    profile = ovftool.load_profile()
    vc = ctx.vcenter
    _ensure_folder(ctx)
    target = ovftool.VCenter(
        host=vc["host"], user=vc["user"], datacenter=vc["datacenter"],
        compute=vc["compute"], datastore=vc["datastore"], network=vc["network"],
        folder=vc.get("folder"), resource_pool=vc.get("resource_pool"),
    )
    net = ctx.network
    network = ovftool.Network(
        netmask=net["netmask"], gateway=net["gateway"],
        dns=net.get("dns", []), search_domains=net.get("search_domains", []),
    )
    # Lab: root and configuser share the appliance password.
    secrets = ovftool.Secrets(root_password=ctx.configuser_password,
                              configuser_password=ctx.configuser_password)

    # Scoped to the folder, exactly as is_done -- and not optionally. If run()
    # asks datacenter-wide while is_done asks folder-scoped, the leftover VM
    # is_done ignored is the one run() sees: it skips the node as "already
    # deployed", the node is never built, and is_done never goes done. Worse for
    # a leftover that is POWERED_OFF: run() raises "delete the VM in vCenter" --
    # pointing at another cluster's machine. Both are the "repaired in one place,
    # not the call site" defect the whole codebase keeps guarding against.
    folder = (ctx.vcenter.get("folder") or "").strip() or None
    already = _vc(ctx).power_states([n["hostname"] for n in ctx.nodes],
                                ctx.vcenter.get("datacenter"), folder=folder)
    total = len(ctx.nodes)
    done_names = [n["hostname"] for n in ctx.nodes
                  if already.get(n["hostname"]) == "POWERED_ON"]
    for i, n in enumerate(ctx.nodes, 1):
        state = already.get(n["hostname"])
        if state == "POWERED_ON":
            ctx.report(f"[{len(done_names)}/{total} up] {n['hostname']}: "
                       "already deployed, skipping")
            continue  # idempotent: skip VMs that already exist
        if state is not None:
            # The VM EXISTS but is not running -- an interrupted upload, a
            # failed power-on, or someone shut it down. Deploying over it makes
            # ovftool fail on the duplicate name, which reads like a tool bug.
            # Say what is actually there and what to do about it instead.
            raise RuntimeError(
                f"{n['hostname']} already exists in vCenter but is {state}, not "
                "POWERED_ON.\n"
                "  - If the previous deploy was interrupted, delete the VM in "
                "vCenter and retry -- aXs will redeploy it.\n"
                "  - If it is intact, power it on and retry; aXs will skip it.\n"
                "  - aXs does not delete or power on VMs by itself.")
        ctx.report(f"[{len(done_names)}/{total} up] deploying {n['hostname']} "
                   f"({n['ip']}) ...")
        role = "bootstrap" if n["role"] == "bootstrap" else n["role"]
        node = ovftool.Node(role=role, vm_name=n["hostname"],
                            hostname=n["hostname"], ip=n["ip"])
        argv = ovftool.build(
            ova=Path(ctx.ova_path), vcenter=target,
            vcenter_password=vc.get("password", ""), node=node, network=network,
            secrets=secrets, size=ctx.size, profile=profile,
        )
        # argv[0] is the literal "ovftool"; use the vendored binary.
        argv[0] = str(Path("input/ovftool/ovftool").resolve())
        rc, out = _run_ovftool(
            argv,
            lambda pct: ctx.report(
                f"[{len(done_names)}/{total} up] {n['hostname']}: "
                f"uploading {pct}% ..."),
            on_out=lambda text: ctx.report_log(clean_tail(_quiet_upload(text), 60)),
        )
        if rc != 0:
            masked = ovftool.render(argv, secrets=secrets)
            # CAUSE FIRST. The UI truncates this message, and it used to start
            # with the (long) command line -- so the one line that says what
            # actually went wrong was always cut off. ovftool's own "Error:"
            # lines lead now; the command follows for the record.
            raise RuntimeError(
                f"ovftool failed for {n['hostname']} (exit {rc}).\n"
                f"{ovftool_reason(out)}\n---\n{masked}\n---\n{out[-1500:]}"
            )
        done_names.append(n["hostname"])
        ctx.report(f"[{len(done_names)}/{total} up] {n['hostname']} deployed ✔")


# ovftool prints its diagnosis as "Error: ..." near the end, after possibly
# thousands of lines (it dumps the OVA's signing certificate on the way). These
# are the lines worth putting in front of the operator.
_ERR_LINE = re.compile(r"^(Error|Warning):.*$", re.MULTILINE)


def ovftool_reason(out: str) -> str:
    """ovftool's own error lines, or its last meaningful line as a fallback."""
    hits = [m.group(0).strip() for m in _ERR_LINE.finditer(out or "")
            if m.group(0).startswith("Error")]
    if hits:
        return "\n".join(dict.fromkeys(hits))      # de-duplicated, order kept
    tail = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    return tail[-1] if tail else "(ovftool produced no output)"


# Known ovftool failures and what to do about them. Keyed on a lowercase
# substring of the real message -- only entries seen in an actual run are here,
# nothing guessed.
_HINTS: tuple[tuple[str, str], ...] = (
    ("invalid vm folder",
     "The VM folder from `vcenter.folder` does not exist in this datacenter.\n"
     "  - aXs creates a single LEAF folder for you, but not a nested path.\n"
     "    For a nested folder, create it under 'VMs and Templates' first, or\n"
     "    clear vcenter.folder to deploy into the datacenter root.\n"
     "  - A nested folder needs its inventory path, not just the leaf name."),
)


def explain_failure(ctx: Context, exc: Exception) -> str:
    reason = ovftool_reason(str(exc))
    low = str(exc).lower()
    for needle, hint in _HINTS:
        if needle in low:
            return f"{reason}\n{hint}"
    return str(exc)
