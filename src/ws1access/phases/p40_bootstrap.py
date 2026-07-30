"""Phase 40 -- Bootstrap node and assets.

Documented procedure (Omnissa install guide, verified end-to-end in the lab on
2026-07-22):

    ssh configuser@<bootstrap> ; sudo su ; cd /root
    mkdir -p <cluster>/assets
    scp <bundle>.zip -> /root/<cluster>/assets/
    cd /root/<cluster>/assets && unzip <bundle>.zip
    cp cli-distribution/linux/wso /usr/bin/
    wso version
    wso eula --accept true
    wso configure /root/<cluster>/assets/

Done-probe: `wso version` reports the CP/CPS image versions. Before `wso
configure` it instead prints "Please run the configure command", so an "Image
Version" line is an exact, live signal that the phase is complete. (The real
output pads the label -- "CP  Image Version" with two spaces -- so match on the
stable "Image Version" substring, not on "CP ".)
"""

from __future__ import annotations

from ..context import Context, RemoteError, WSO_BUSY
from . import Probe

NAME = "40_bootstrap"
DEPS = ("20_nodes_ready",)

# The done-probe only checks `wso version`; it cannot tell a half-finished
# `wso configure` (image load) from a complete one. Do not restart mid-run.
RESTART_SAFE = False
RESTART_NOTE = "installing wso / loading images -- a restart could skip an incomplete load"

_DONE_MARKER = "Image Version"


def is_done(ctx: Context) -> Probe:
    r = ctx.bootstrap_run("wso version")
    # A COMPLETE `wso configure` loads BOTH images, so `wso version` prints TWO
    # 'Image Version' lines -- CP and CPS (verified at the lab 2026-07-23). ONE
    # line = a half-finished image load (interrupted configure) that must NOT be
    # skipped on resume; ZERO = configure never ran. Require both -- checking a
    # single marker would falsely accept a partial load and make p60/p70 fail
    # later and cryptically (backlog [H]).
    n = r.output.count(_DONE_MARKER)
    return Probe(r.ok and n >= 2, detail=r.output.strip())


def run(ctx: Context) -> None:
    # These phases write on the bootstrap -- the asset bundle and `wso
    # configure` here, the inventory and profile.yml there. Doing that while
    # another wso operation is running means two writers on one cluster, and
    # unlike phases 60/70/80 there was no guard at all: a single failed SSH
    # probe is enough to make a completed phase look "todo" again.
    if ctx.bootstrap_run(WSO_BUSY).ok:
        raise ctx.busy_error()

    if not ctx.bundle_path:
        raise RuntimeError(
            "No asset bundle configured (assets.bundle). Phase 40 needs the "
            "Omnissa Access asset bundle .zip."
        )
    ctx.stage_bundle(ctx.bundle_path)
    ctx.bootstrap_step("verify wso CLI", "wso version")
    ctx.bootstrap_step("accept EULA", "wso eula --accept true")
    ctx.bootstrap_step("load images (wso configure)",
                       f"wso configure {ctx.cluster_dir}/assets/")


def explain_failure(ctx: Context, exc: Exception) -> str:
    if isinstance(exc, RemoteError):
        out = exc.result.output.lower()
        if exc.step == "install wso CLI" and "no such file" in out:
            return (
                "The wso binary was not found in the unpacked bundle.\n"
                "  - Is input/assets the real Omnissa Access asset bundle?\n"
                "  - Expected cli-distribution/linux/wso inside the .zip."
            )
        if exc.step == "load images (wso configure)":
            return (
                "wso configure failed to load the images.\n"
                "  - Check free space on the bootstrap (the bundle unpacks to ~26 GB).\n"
                "  - Check that docker is running: `sudo systemctl status docker`.\n"
                f"  - wso said:\n{exc.result.output}"
            )
        if "sudo" in out and "password" in out:
            return (
                f"'{exc.step}' could not sudo on the bootstrap.\n"
                "  - configuser needs passwordless sudo on the appliance."
            )
        return (
            f"Phase 40 step '{exc.step}' failed on the bootstrap "
            f"(exit {exc.result.rc}):\n{exc.result.output}"
        )
    return str(exc)
