"""Prove the NFS backup target actually works -- before the cluster needs it.

`wso cp deploy` says it plainly: "For production deployments, NFS is required
for disaster recovery." But nothing verifies the target. A typo in the export
path, a missing `rw` in /etc/exports, root_squash against a service writing as
root -- all of that stays invisible until a restore is attempted, which is the
worst possible moment to find out.

So this mounts the export, writes a file, reads it back, deletes it, and
unmounts again -- and it does that WHERE THE MOUNT WILL ACTUALLY HAPPEN.

That last part is docs/08 B8. The check used to run on the bootstrap only, but
the bootstrap never mounts this share: `wso cp deploy` puts the NFS volume in
the Nomad job definitions, and those run on the PLATFORM nodes (docs/08 C1, C4
-- the bootstrap carries no service containers at all). An export limited to
specific hosts, or a firewall rule that lets the bootstrap through and not the
platform nodes, therefore passed the test and broke the deploy afterwards.
Which is the exact shape of the failure that cost a day on 2026-07-28: a check
that tested a convenient approximation instead of the thing itself.

Nowhere near the operator's laptop either -- that sits in another network with
other firewall rules and would prove nothing about anything.

Read-only in spirit -- the one file it writes is uniquely named and removed
again, and the mount is always undone, including on failure.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from typing import Protocol

from .ssh import SshResult


class Runner(Protocol):
    def __call__(self, command: str, **kwargs) -> SshResult: ...


@dataclass
class NfsResult:
    ok: bool
    stage: str          # tools | export | mount | write | read | cleanup | ok
    detail: str

    def __str__(self) -> str:
        return f"[{self.stage}] {self.detail}"


def _q(s: str) -> str:
    return shlex.quote(str(s))


def check(run: "Runner", host: str, path: str, version: str | int = 4,
          *, mountpoint: str = "/tmp/axs-nfscheck",
          where: str = "the bootstrap") -> NfsResult:
    """Mount, write, read, delete, unmount. Returns the first stage that failed.

    `run` is a callable taking a shell command and returning an SshResult, so
    the same check can be pointed at the bootstrap or at any platform node.
    Passing a runner rather than the Context is what makes "run it where the
    mount really happens" a one-line change at the call site instead of a
    second copy of this function.

    The source is host + ":" + path, UNCONDITIONALLY -- because that is what
    wso produces. It hands docker's local volume driver device=":<nfs_path>"
    with o=addr=<nfs_host>, so a leading colon in nfs_path arrives as "::" and
    the mount asks for an export that does not exist.

    Proven the hard way (2026-07-28): the vendor's own example writes
    ":/controlplanenfs/us04pA", we copied that faithfully, and phase 70 died
    within four seconds on "permission denied" from a "::" mount. The earlier
    version of this function special-cased the leading colon and so produced a
    working mount from a broken config -- it passed, and the deploy failed.
    Never make this function kinder to the input than wso is.
    """
    src = f"{host}:{path}"
    mp = _q(mountpoint)

    # 0. Can we act as root here at ALL? Passwordless sudo is established for
    #    the bootstrap and merely ASSUMED for the platform nodes -- collect's
    #    own node probe hedges with `sudo -n ... || ...` for exactly that
    #    reason. Without this step, a sudo that wants a password produced
    #    "mount.nfs is not installed", which is the wrong cause, and the caller
    #    then blamed the customer's export for an access list it never had.
    #    "We could not ask" and "the answer is no" are different diagnoses.
    r = run("id -u")
    if (r.output or "").strip().splitlines()[-1:] != ["0"]:
        return NfsResult(False, "access",
                         f"could not run as root on {where}, so the NFS target "
                         f"was NOT tested from there — this says nothing about "
                         f"the target itself. ({(r.output or '').strip()[-120:]})")

    # 1. Can this appliance mount NFS at all? AlmaLinux minimal may not ship
    #    nfs-utils -- and if mount.nfs is missing here, the backup service has
    #    the same problem. Worth knowing before anything else.
    r = run("command -v mount.nfs >/dev/null 2>&1 && echo yes || echo no")
    if "yes" not in r.output:
        return NfsResult(False, "tools",
                         f"mount.nfs is not installed on {where} "
                         "(nfs-utils missing) -- the NFS target cannot be "
                         "verified from there, and the backup service may hit "
                         "the same wall.")

    # 2. What does the server offer? Advisory only: many servers block
    #    showmount (rpcbind firewalled) while NFSv4 mounts fine.
    exports = run(f"showmount -e {_q(host)} 2>&1 || true").output.strip()

    # 3. Mount, write, CHOWN, read, delete -- then ALWAYS unmount. The trap makes
    #    the unmount survive any failure in between; a leftover mount on the
    #    bootstrap would be a nasty parting gift.
    #
    #    The chown is the one that matters and the one this check used to miss.
    #    Docker chowns a volume's directory when it creates the container, so an
    #    export that forbids chown kills every container that uses it -- while
    #    writing a file still works perfectly. Live on 2026-07-28 this check
    #    passed against an export with `-mapall`, and postgres then failed on
    #    "failed to chown ...: operation not permitted", over and over.
    # The test file is created INSIDE the customer's backup target, so the trap
    # must remove it -- not just unmount. Only the success path used to delete
    # it, so every failure after the write (read, chown, cleanup) left a stray
    # .axs-write-test.<pid> behind on the customer's export, invisibly. The
    # chown failure is not hypothetical: it is what happened on 2026-07-28.
    # A leftover mount from a killed run is also unmounted up front, since the
    # trap cannot run if the remote shell is killed outright.
    probe = (
        f"umount -f {mp} 2>/dev/null || true; mkdir -p {mp}; "
        f"f={mp}/.axs-write-test.$$; d={mp}/.axs-chown-test.$$; "
        f"set -e; "
        f"trap 'rm -f \"$f\" 2>/dev/null || true; rmdir \"$d\" 2>/dev/null || true; "
        f"umount -f {mp} 2>/dev/null || true; rmdir {mp} 2>/dev/null || true' EXIT; "
        f"mount -t nfs -o vers={_q(version)},soft,timeo=50,retrans=2 {_q(src)} {mp} "
        f"  || {{ echo AXS_STAGE=mount; exit 10; }}; "
        f"echo axs-nfs-check > $f 2>/dev/null || {{ echo AXS_STAGE=write; exit 11; }}; "
        f"grep -q axs-nfs-check $f || {{ echo AXS_STAGE=read; exit 12; }}; "
        f"mkdir -p $d 2>/dev/null || {{ echo AXS_STAGE=write; exit 11; }}; "
        f"chown 26:26 $d 2>/dev/null || {{ rmdir $d 2>/dev/null; "
        f"    echo AXS_STAGE=chown; exit 14; }}; "
        f"rmdir $d 2>/dev/null || true; "
        f"rm -f $f || {{ echo AXS_STAGE=cleanup; exit 13; }}; "
        f"echo AXS_STAGE=ok"
    )
    r = run(probe)
    out = r.output or ""

    if "AXS_STAGE=ok" in out:
        return NfsResult(True, "ok",
                         f"{src} mounted, written, read back, chowned and "
                         "cleaned up.")
    if "AXS_STAGE=chown" in out:
        return NfsResult(False, "chown",
                         f"{src} mounts and is writable, but ownership cannot be "
                         "changed on it. Docker chowns a volume's directory when "
                         "it creates a container, so every service using this "
                         "target will fail with 'operation not permitted' -- "
                         "postgres first, and with no useful error in the deploy "
                         "log.\n"
                         "  The export maps remote users to a local account. "
                         "Allow root to stay root instead:\n"
                         "    Linux/NetApp:  no_root_squash\n"
                         "    macOS exports: -maproot=root  (NOT -mapall=<user>)")
    if "AXS_STAGE=mount" in out:
        if path.startswith(":"):
            # The single most likely cause, and the one the vendor's own
            # example leads you into. Say it before anything else.
            return NfsResult(False, "mount",
                             f"could not mount {src} -- note the DOUBLE COLON. "
                             f"nfs_path is {path!r}, and wso prepends a colon of "
                             "its own, so the mount asks for an export that does "
                             "not exist. Drop the leading colon: use "
                             f"{path.lstrip(':')!r}. (The vendor's example file "
                             "shows a leading colon; following it breaks the "
                             "services deploy.)")
        hint = (f"\n  server offers:\n{exports}" if exports and "clnt" not in exports
                else "\n  (showmount gave nothing usable -- it is often firewalled; "
                     "that alone is not the problem)")
        return NfsResult(False, "mount",
                         f"could not mount {src} (NFSv{version}). Check the export "
                         f"path, the server's allow list and the firewall.{hint}")
    if "AXS_STAGE=write" in out:
        return NfsResult(False, "write",
                         f"{src} mounts but is NOT writable. The export is "
                         "probably read-only, or root_squash maps the writer to "
                         "nobody. Backups would fail.")
    if "AXS_STAGE=read" in out:
        return NfsResult(False, "read",
                         f"{src} accepted a write but the content did not come "
                         "back -- suspect the export or a caching layer.")
    if "AXS_STAGE=cleanup" in out:
        return NfsResult(False, "cleanup",
                         f"{src} is writable but the test file could not be "
                         "removed. Please delete .axs-write-test.* by hand.")
    return NfsResult(False, "mount", f"NFS check gave no verdict:\n{out.strip()[-500:]}")
