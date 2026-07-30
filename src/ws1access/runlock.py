"""One deploy per cluster at a time.

There was no lock of any kind. Two aXs runs against one cluster is not a
theoretical worry: the CLI hands an interactive terminal to the TUI and a piped
one to the plain path (see cli.cmd_deploy), so `axs deploy` in one window and
`axs deploy -c same | tee log` in another is an easy accident. Both would probe
the same phase as "todo", both would pass the remote busy-check before either
started, and two `wso cp deploy` runs would meet on one cluster. Phases 00-50
have no remote guard at all -- two phase-10 runs would call ovftool for the
same VM names, and what ovftool does then is not established.

The remote guard in context.start_detached_once stays: it catches the case a
local lock cannot see -- a wso operation someone started by hand on the
bootstrap. This one catches the case the remote guard cannot: two aXs
processes racing between check and act.

flock is advisory and released by the kernel when the process dies, so a
crashed run leaves nothing to clean up by hand -- which matters more here than
strictness, because a stale lock file that outlives its owner is its own
support call.
"""

from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path


class AlreadyRunning(RuntimeError):
    """Another aXs process holds this cluster's lock."""


class ClusterLock:
    """Hold an exclusive, non-blocking lock on clusters/<name>/.lock."""

    def __init__(self, cluster: str) -> None:
        self.path = Path("clusters") / cluster / ".lock"
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            holder = ""
            try:
                holder = os.read(fd, 64).decode(errors="replace").strip()
            except OSError:
                pass
            os.close(fd)
            if e.errno in (errno.EACCES, errno.EAGAIN):
                raise AlreadyRunning(
                    f"another aXs process is already working on this cluster"
                    + (f" (pid {holder})" if holder else "")
                    + ".\n  Two runs against one cluster corrupt each other -- "
                    "wait for it to finish, or stop it first.\n"
                    f"  Lock: {self.path}") from None
            raise
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "ClusterLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
