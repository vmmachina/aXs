"""Command execution with live output.

Every command the tool runs -- local, over SSH, or a long-running remote
deployment -- streams to the console as it happens and is mirrored to a log
file under clusters/<name>/logs/.

The long phases (`wso cp deploy`, 30-60 min; `wso services deploy`, ~40 min)
follow the pattern the Omnissa documentation itself recommends: start the
command detached under nohup on the bootstrap node, then follow its log. That
decoupling is what makes the step survivable -- if the local connection drops
mid-deployment, the remote command keeps running and the tool re-attaches to
the same log on the next invocation instead of starting over.

SSH is delegated to the system `ssh`/`scp` binaries rather than paramiko. This
keeps the dependency set free of compiled extensions and means ~/.ssh/config,
ProxyJump, agent forwarding and known_hosts all work the way the operator
already has them configured.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Sequence

# A line observer may be attached to derive progress from output without
# interfering with the raw stream (e.g. counting "Deployment of service X
# complete" during `wso services deploy`).
LineObserver = Callable[[str], None]


@dataclass
class Result:
    """Outcome of a command, including everything it printed."""

    rc: int
    lines: list[str] = field(default_factory=list)
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def output(self) -> str:
        return "\n".join(self.lines)

    def tail(self, n: int = 20) -> str:
        """Last n lines -- what an error message should quote."""
        return "\n".join(self.lines[-n:])


class Runner:
    """Runs commands, echoing live and mirroring to a log file.

    `echo` defaults to True on purpose. During a 60-minute deployment the
    operator needs to see what is happening; hiding it behind a verbosity flag
    would be the wrong default for a tool whose failures are expensive.
    """

    def __init__(self, log_path: Path | None = None, echo: bool = True):
        self.log_path = log_path
        self.echo = echo
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    # -- internals ---------------------------------------------------------

    def _emit(self, line: str, log) -> None:
        stamped = f"{datetime.now():%H:%M:%S}  {line}"
        if self.echo:
            # Raw lines, not a scrolling rich panel: panels look tidy but
            # scroll errors out of view, which is exactly what must not be
            # lost here.
            print(stamped, flush=True)
        if log:
            log.write(stamped + "\n")
            log.flush()  # survive a kill -9 mid-deployment

    def _stream(self, argv: Sequence[str], observer: LineObserver | None) -> Result:
        started = time.monotonic()
        lines: list[str] = []
        log = open(self.log_path, "a", encoding="utf-8") if self.log_path else None
        try:
            if log:
                log.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} :: {shlex.join(argv)}\n")
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # interleave, preserving ordering
                text=True,
                bufsize=1,  # line buffered
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.rstrip("\n")
                lines.append(line)
                self._emit(line, log)
                if observer:
                    observer(line)
            rc = proc.wait()
        finally:
            if log:
                log.close()
        return Result(rc=rc, lines=lines, duration=time.monotonic() - started)

    # -- public API --------------------------------------------------------

    def local(self, argv: Sequence[str], observer: LineObserver | None = None) -> Result:
        """Run a command on the operator's machine (ovftool, openssl, dig)."""
        return self._stream(list(argv), observer)

    def ssh(
        self,
        host: str,
        command: str,
        user: str = "configuser",
        observer: LineObserver | None = None,
        timeout_connect: int = 10,
    ) -> Result:
        """Run a command on a cluster node and stream its output back."""
        return self._stream(self._ssh_argv(host, user, command, timeout_connect), observer)

    def _ssh_argv(self, host: str, user: str, command: str, timeout_connect: int) -> list[str]:
        return [
            "ssh",
            "-o", f"ConnectTimeout={timeout_connect}",
            "-o", "BatchMode=yes",           # never block on a password prompt
            "-o", "StrictHostKeyChecking=accept-new",
            f"{user}@{host}",
            command,
        ]

    def reachable(self, host: str, user: str = "configuser", timeout: int = 10) -> bool:
        """Cheap liveness probe used by phase is_done() checks."""
        quiet = Runner(log_path=self.log_path, echo=False)
        return quiet.ssh(host, "true", user=user, timeout_connect=timeout).ok


class DetachedRemoteCommand:
    """A long-running remote command that outlives the local process.

    Mirrors the documented pattern:

        cd /root/<cluster> && nohup wso cp deploy > <log> 2>&1 &

    The command is started once and identified by its log file plus a marker
    file holding the remote PID. `follow()` tails the log until the process
    exits, so an interrupted local run can simply call `follow()` again rather
    than re-running a deployment that is already 40 minutes in.
    """

    def __init__(
        self,
        runner: Runner,
        host: str,
        workdir: str,
        command: str,
        name: str,
        user: str = "configuser",
    ):
        self.runner = runner
        self.host = host
        self.workdir = workdir
        self.command = command
        self.name = name
        self.user = user
        self.remote_log = f"{workdir}/.ws1access/{name}.log"
        self.pid_file = f"{workdir}/.ws1access/{name}.pid"
        self.rc_file = f"{workdir}/.ws1access/{name}.rc"

    def is_running(self) -> bool:
        probe = Runner(log_path=None, echo=False)
        res = probe.ssh(
            self.host,
            f"test -f {self.pid_file} && kill -0 $(cat {self.pid_file}) 2>/dev/null",
            user=self.user,
        )
        return res.ok

    def has_finished(self) -> bool:
        probe = Runner(log_path=None, echo=False)
        return probe.ssh(self.host, f"test -f {self.rc_file}", user=self.user).ok

    def exit_code(self) -> int | None:
        probe = Runner(log_path=None, echo=False)
        res = probe.ssh(self.host, f"cat {self.rc_file} 2>/dev/null", user=self.user)
        if not res.ok or not res.lines:
            return None
        try:
            return int(res.lines[0].strip())
        except ValueError:
            return None

    def start(self) -> None:
        """Launch detached. No-op if it is already running or already done."""
        if self.is_running() or self.has_finished():
            return
        # setsid detaches from the SSH session's process group so the command
        # is not killed when the connection closes. The rc file is written by
        # the wrapper so the exit status survives our disconnection too.
        launch = (
            f"mkdir -p {self.workdir}/.ws1access && cd {self.workdir} && "
            f"rm -f {self.rc_file} && "
            f"setsid nohup sh -c '{self.command}; echo $? > {self.rc_file}' "
            f"> {self.remote_log} 2>&1 < /dev/null & echo $! > {self.pid_file}"
        )
        probe = Runner(log_path=None, echo=False)
        res = probe.ssh(self.host, launch, user=self.user)
        if not res.ok:
            raise RuntimeError(
                f"Could not start '{self.name}' on {self.host}.\n{res.tail()}"
            )

    def follow(self, observer: LineObserver | None = None, poll: float = 2.0) -> Result:
        """Stream the remote log from the beginning until the command exits.

        Safe to call repeatedly: it always replays from line 1, so a
        reconnecting operator sees the full history, not just the tail.
        """
        started = time.monotonic()
        lines: list[str] = []
        log = open(self.runner.log_path, "a", encoding="utf-8") if self.runner.log_path else None
        try:
            # `tail -f --pid` would be GNU-specific on the remote side; the
            # cluster nodes are AlmaLinux, so it is available -- but we stop on
            # the rc file instead, which also works if tail is killed.
            argv = self.runner._ssh_argv(
                self.host,
                self.user,
                f"tail -n +1 -f {self.remote_log} 2>/dev/null",
                timeout_connect=10,
            )
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            assert proc.stdout is not None
            try:
                for raw in proc.stdout:
                    line = raw.rstrip("\n")
                    lines.append(line)
                    self.runner._emit(line, log)
                    if observer:
                        observer(line)
                    if self.has_finished() and not self.is_running():
                        break
            finally:
                proc.terminate()
        finally:
            if log:
                log.close()

        rc = self.exit_code()
        return Result(
            rc=rc if rc is not None else 1,
            lines=lines,
            duration=time.monotonic() - started,
        )

    def run(self, observer: LineObserver | None = None) -> Result:
        """Start if needed, then follow to completion."""
        self.start()
        return self.follow(observer=observer)


def service_progress(total_hint: int | None = None) -> tuple[LineObserver, Callable[[], int]]:
    """Observer that counts completed services during `wso services deploy`.

    The deploy prints 'Deployment of service <name> complete' per service; the
    documented full run covers ~38 of them. Returns the observer and a getter
    so a status line can show '23/38' alongside the raw stream.
    """
    count = {"n": 0}

    def observe(line: str) -> None:
        if line.startswith("Deployment of service ") and line.endswith(" complete"):
            count["n"] += 1

    return observe, lambda: count["n"]
