"""SSH access to cluster nodes.

Two authentication phases exist, and the tool needs both:

  * Before phase 50, only the configuser password set via OVF properties exists.
    Phase 20 must verify freshly deployed nodes using that password.
  * After phase 50 distributes a key with ssh-copy-id, everything uses key auth
    and the password is never needed again.

Password authentication is driven through a pty around the system `ssh` binary
rather than paramiko. That keeps the dependency set free of compiled extensions
(see pyproject.toml) and preserves ~/.ssh/config, ProxyJump and known_hosts.
The password is written to the pty, never to the command line, so it does not
appear in the process list.
"""

from __future__ import annotations

import os
import pty
import re
import select
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass

PASSWORD_PROMPT = re.compile(rb"(?i)(password:|passphrase for)")
DENIED = re.compile(rb"(?i)permission denied")

# Printed by the remote shell as the FIRST thing the command emits, so the
# password path can tell "the command is now running" from "ssh is prompting
# again". See run_with_password: a second password prompt means a refusal, but
# command OUTPUT can legitimately contain the word "password:" (profile.yml
# does), and a time window alone could not tell the two apart when the output
# arrived within the window. Once this marker is seen, auth is done and every
# later prompt-looking line is data. It carries no "password:"/"passphrase for"
# so it can never itself look like a prompt.
_AUTH_SENTINEL = "__AXS_AUTH_STARTED__"


def _sentinel_seen(tail: bytes, data: bytes, sentinel: bytes) -> tuple[bool, bytes]:
    """Has `sentinel` appeared, given the running `tail` and the next read?

    Returns (seen, new_tail). The tail ACCUMULATES the last (len-1) bytes of
    everything seen so far, so a sentinel fragmented across any number of reads
    is still found -- a pty/network can split 20 bytes over several reads.
    Searching only the current read (or only the last read's tail) missed a
    sentinel spread over three-plus reads, and the whole fix collapsed back to
    the bug it cures. len-1 is exactly how far a split can straddle a boundary.
    """
    hay = tail + data
    return sentinel in hay, hay[-(len(sentinel) - 1):]


@dataclass
class SshResult:
    rc: int
    output: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def _reap(pid: int, into: list[int]) -> bool:
    """Non-blocking waitpid that KEEPS the exit status.

    Discarding it was a genuine bug: the child was reaped here, the finally
    block's blocking waitpid then raised ChildProcessError, and the exit code
    was GUESSED as "success if the password went out". A remote command that
    failed could therefore be reported as rc=0 -- and on the resume path that
    turns into a phase wrongly marked done.
    """
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        into.append(status)
        return True
    return False


def _rc_from(reaped: list[int], pid: int, fallback: int) -> int:
    """Exit code of the child: the status caught by _reap if we have it, else
    a blocking wait. `fallback` is used only when the status is genuinely
    unobtainable -- and it is a FAILURE, never a guessed success."""
    if reaped:
        return os.waitstatus_to_exitcode(reaped[0])
    try:
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    except (ChildProcessError, ValueError):
        return fallback


def _base_opts(connect_timeout: int) -> list[str]:
    # Deploy connections target freshly deployed VMs whose host keys change on
    # every redeploy (same IP, new key). Verifying against ~/.ssh/known_hosts
    # would make a rebuild fail with "REMOTE HOST IDENTIFICATION HAS CHANGED"
    # forever. So the tool does NOT persist or verify host keys for these
    # connections (UserKnownHostsFile=/dev/null + StrictHostKeyChecking=no) --
    # the same stance Ansible takes by default for provisioning. This leaves the
    # operator's own ~/.ssh/known_hosts completely untouched.
    return [
        "-o", f"ConnectTimeout={connect_timeout}",
        # ConnectTimeout only covers dialling. Once connected, a link that goes
        # away silently (VPN drop, laptop suspend, vSphere network maintenance)
        # leaves ssh waiting forever -- and the deploy with it, mid-phase, with
        # no output. These make the client notice within ~1 minute and exit.
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    ]


def run_with_key(
    host: str, command: str, user: str = "configuser", connect_timeout: int = 10,
    run_timeout: int = 600, stdin: str | None = None,
) -> SshResult:
    """Key-based, non-interactive. Used from phase 50 onwards.

    `stdin` feeds the remote command's standard input. It exists so file
    CONTENT does not have to travel in argv: a command line is visible in `ps`
    on both machines, and `cp-cluster.ini`, `profile.yml` and the customer's
    TLS private key all went that way (docs/08 B2, which recorded the first two
    -- the key was found later). Base64 was never protection there, only
    quoting.

    Only this path can offer it. `run_with_password` drives ssh through a pty,
    which is stdin, stdout and stderr of the child at once, so there is no free
    channel beside the password prompt -- see context.write_file.
    """
    argv = ["ssh", *_base_opts(connect_timeout), "-o", "BatchMode=yes",
            f"{user}@{host}", command]
    # Hard backstop under the ServerAlive settings: a remote command that never
    # returns (a hung `wso`, a stuck mount) would otherwise stall the phase for
    # good. Long-running work is never run this way -- it is detached and polled
    # (context.start_detached_once), so a bounded wait here is safe.
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=run_timeout, input=stdin)
    except subprocess.TimeoutExpired as e:
        got = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) \
            else (e.stdout or "")
        return SshResult(rc=124, output=(
            f"no answer from {host} after {run_timeout}s -- the connection or the "
            f"remote command is stuck.\n{got}".strip()))
    return SshResult(rc=p.returncode, output=(p.stdout + p.stderr).strip())


def run_with_password(
    host: str,
    command: str,
    password: str,
    user: str = "configuser",
    connect_timeout: int = 15,
    idle_timeout: int = 600,
    auth_window: float = 60.0,
) -> SshResult:
    """Password-based, via a pty. Used by phase 20, before keys exist.

    The password goes to the pty in response to ssh's own prompt, so it never
    reaches argv and cannot be read out of the process list.

    Three things this has to get right. The first two were found in the field on
    2026-07-29 when `axs status` hung on a node with no output at all; the third
    on 2026-07-30 when phase 50's `cat profile.yml` was reported unreadable
    because the file itself contains a "password:" key.

    A SECOND prompt means the first answer was refused. `NumberOfPasswordPrompts=1`
    caps the `password` METHOD; when that is exhausted ssh moves on to
    keyboard-interactive, which asks again in its own words:

        configuser@10.10.50.1's password:      <- password method
        (configuser@10.10.50.1) Password:      <- keyboard-interactive

    Answering only the first and then falling silent left ssh waiting for input
    forever. Answering the second instead would be worse: it spends a second
    failed attempt against a configuser account that faillock can lock out, and
    six nodes make that twelve. So the second prompt ENDS the attempt with the
    only conclusion it supports -- the password was not accepted.

    But a "password:" in the COMMAND's own output is not a prompt, and telling
    the two apart by content is impossible -- so the command prints a sentinel
    as its first line, and once that is seen we stop watching for prompts
    entirely (see the sentinel wrap below). A refusal re-prompts BEFORE the
    command runs, so before the sentinel; a real read finishes after it. An
    idle window remains as a backstop, but the sentinel is the actual signal --
    the old window alone missed a `cat` whose "password:" arrived inside it.

    And a deadline -- an IDLE one, not a total one. This path is the only one
    phase 40 has before the keys exist, and phase 40 unzips a 13.5 GB bundle
    and loads container images; a total cap would cut those off mid-way, on a
    phase that is explicitly not safe to restart. Both talk while they work, so
    the honest question is not "how long has this run" but "how long has it
    said nothing". `run_with_key` has had a total cap all along; this path had
    nothing at all, and the module comment promised the opposite ("leaves ssh
    waiting forever -- and the deploy with it, mid-phase, with no output").
    """
    # Emit a sentinel as the command's first output. Auth happens before the
    # command runs, so the sentinel appears only AFTER a successful login --
    # never before a second prompt (a refusal). Seeing it is proof the command
    # is running, which is what lets a "password:" in the command's own output
    # (profile.yml has one) stop being mistaken for a re-prompt. The sentinel is
    # printed by the remote login shell, before `command`, so `command`'s exit
    # code is still what ssh returns (`;` yields the last command's status).
    remote = f"printf '%s\\n' {_AUTH_SENTINEL}; {command}"
    argv = [
        "ssh",
        *_base_opts(connect_timeout),
        "-o", "PubkeyAuthentication=no",       # go straight to the password
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "NumberOfPasswordPrompts=1",     # fail fast instead of retrying
        f"{user}@{host}",
        remote,
    ]

    # pty.fork() rather than Popen with a pty pair: ssh reads the password from
    # its CONTROLLING terminal, and only fork() makes the pty controlling for
    # the child. Wiring a pty to stdin/stdout leaves ssh without a /dev/tty and
    # the prompt is never answered.
    pid, fd = pty.fork()
    if pid == 0:                       # child
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    reaped: list[int] = []      # exit status caught by _reap
    chunks: list[bytes] = []
    prompts = 0
    refused = False
    expired = False
    authed = False              # the command-start sentinel has been seen
    tail = b""                  # rolling buffer so a split sentinel is still found
    sentinel = _AUTH_SENTINEL.encode()
    deadline = time.monotonic() + idle_timeout
    auth_deadline = time.monotonic() + auth_window
    try:
        while True:
            if time.monotonic() > deadline:
                expired = True
                _terminate(pid)
                break
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                if _reap(pid, reaped):
                    break
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:            # pty closes with EIO when the child exits
                break
            if not data:
                break
            chunks.append(data)
            deadline = time.monotonic() + idle_timeout   # it spoke; keep waiting
            if not authed:
                # Once the command-start sentinel is seen, auth is done and
                # everything after is the command's own output (see _sentinel_seen
                # for why the carry-over accumulates across reads).
                authed, tail = _sentinel_seen(tail, data, sentinel)
            if authed or time.monotonic() > auth_deadline:
                # The command is running (sentinel seen), or we are past the
                # authentication window. Either way everything from here is the
                # COMMAND's output, which may legitimately contain "password:":
                # a remote step printing "retrieving admin password: ok", or a
                # `cat profile.yml` (which has a password: key), was read as a
                # second prompt and a working session killed as refused. The
                # sentinel is the reliable signal; the window is a backstop for
                # a command that somehow emits nothing before its first prompt.
                continue
            if PASSWORD_PROMPT.search(data):
                prompts += 1
                if prompts == 1:
                    os.write(fd, password.encode() + b"\n")
                else:
                    # Asked again -> the answer did not get us in. Stop here
                    # rather than spend another attempt (see the docstring).
                    refused = True
                    _terminate(pid)
                    break

    finally:
        os.close(fd)
        # Fallback 1, not "0 if sent": an unobtainable status must never be
        # reported as success -- a phase would be skipped on the strength of it.
        rc = _rc_from(reaped, pid, 1)

    raw = b"".join(chunks)
    text = raw.decode(errors="replace")
    marker = text.find(_AUTH_SENTINEL)
    if marker != -1:
        # Auth succeeded and the command ran. Everything after the sentinel and
        # its line terminator is the command's OWN output, kept VERBATIM -- a
        # per-line "password:" filter here would delete real content, and
        # profile.yml has an `admin_password:` key. The prompt/banner before the
        # sentinel is dropped wholesale.
        rest = text[marker + len(_AUTH_SENTINEL):]
        # splitlines()+join normalises the pty's \r\n to \n (the contract every
        # caller has always had) and drops the sentinel's own trailing line; the
        # leading blank falls away in the final strip.
        text = "\n".join(rest.splitlines()).strip()
    else:
        # No sentinel: auth never completed (refusal, stall or timeout). Strip
        # ssh's echoed prompt lines so the caller sees only the failure text.
        text = "\n".join(
            line for line in text.splitlines()
            if not PASSWORD_PROMPT.search(line.encode())
        ).strip()
    if refused:
        # "Permission denied" verbatim, because context.password_refused()
        # recognises a refusal by that wording (DENIED) and fails the deploy
        # fast instead of letting phase 20 spin. Spinning is also ASSUMED to be
        # what racks up faillock lockouts -- this appliance's PAM setup has
        # never been measured, so treat that as a reason to be careful, not as
        # a known fact.
        return SshResult(rc=5, output=(
            f"{user}@{host}: Permission denied -- the node asked for the "
            "password a second time.\n"
            "  Usually the password is wrong. It can also mean the password is "
            "correct but EXPIRED and the node wants a new one (the configuser "
            "password expires 60 days after the OVA deploy); the node's own "
            f"words are below.\n{text}".strip()))
    if expired:
        return SshResult(rc=124, output=(
            f"{host} said nothing for {idle_timeout}s -- the connection or the "
            f"remote command is stuck.\n{text}".strip()))
    return SshResult(rc=rc, output=text)


def _terminate(pid: int) -> None:
    """Stop the ssh child we are giving up on, and do not leave it behind."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except OSError:
            return
        for _ in range(20):
            try:
                if os.waitpid(pid, os.WNOHANG)[0]:
                    return
            except ChildProcessError:
                return
            time.sleep(0.05)


def run_interactive_multi(
    host: str,
    command: str,
    password: str,
    user: str = "configuser",
    connect_timeout: int = 20,
) -> SshResult:
    """Run a remote command that itself prompts for passwords, answering each.

    Phase 50 runs ssh-copy-id ON the bootstrap: the tool's own ssh answers the
    bootstrap prompt, then each inner ssh-copy-id prompts again for the target
    node. Because bootstrap and nodes share the configuser password, every
    "password:" prompt gets the same answer. `-tt` forces a remote pty so the
    inner ssh-copy-id has a terminal to prompt on.

    A short cooldown after each answer avoids replying twice to one prompt that
    arrives split across two reads.
    """
    argv = [
        "ssh", "-tt",
        *_base_opts(connect_timeout),
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        f"{user}@{host}",
        command,
    ]

    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    reaped: list[int] = []      # exit status caught by _reap
    chunks: list[bytes] = []
    cooldown_until = 0.0
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                if _reap(pid, reaped):
                    break
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
            now = time.time()
            if now >= cooldown_until and PASSWORD_PROMPT.search(data):
                os.write(fd, password.encode() + b"\n")
                cooldown_until = now + 0.5
    finally:
        os.close(fd)
        rc = _rc_from(reaped, pid, 1)

    text = b"".join(chunks).decode(errors="replace")
    text = "\n".join(
        line for line in text.splitlines()
        if not PASSWORD_PROMPT.search(line.encode())
    ).strip()
    return SshResult(rc=rc, output=text)


def scp_to(
    local_path: str,
    host: str,
    remote_path: str,
    password: str,
    user: str = "configuser",
    connect_timeout: int = 30,
) -> SshResult:
    """Copy a local file to a node with scp, password over the pty.

    scp reads its password from the controlling terminal exactly like ssh, so
    the same pty.fork mechanism answers the prompt. Used for the one laptop->node
    transfer the design allows: the asset bundle onto the bootstrap.
    """
    argv = [
        "scp",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "NumberOfPasswordPrompts=1",
        local_path,
        f"{user}@{host}:{remote_path}",
    ]

    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    reaped: list[int] = []      # exit status caught by _reap
    chunks: list[bytes] = []
    sent = False
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 5.0)
            if not ready:
                if _reap(pid, reaped):
                    break
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
            if not sent and PASSWORD_PROMPT.search(data):
                os.write(fd, password.encode() + b"\n")
                sent = True
    finally:
        os.close(fd)
        # Fallback 1, not "0 if sent": an unobtainable status must never be
        # reported as success -- a phase would be skipped on the strength of it.
        rc = _rc_from(reaped, pid, 1)

    text = b"".join(chunks).decode(errors="replace")
    text = "\n".join(
        line for line in text.splitlines()
        if not PASSWORD_PROMPT.search(line.encode())
    ).strip()
    return SshResult(rc=rc, output=text)


def explain_failure(host: str, result: SshResult, user: str = "configuser") -> str:
    """Turn an SSH failure into something a third party can act on."""
    out = result.output
    if DENIED.search(out.encode()):
        return (
            f"Login to {user}@{host} was refused.\n"
            f"  - Is the configuser password the one set during OVA deployment?\n"
            f"  - It expires 60 days after deployment; if it has, reset it on the\n"
            f"    node with 'sudo passwd {user}' and use the same password on every node."
        )
    if "connection refused" in out.lower():
        return (
            f"{host} refused the connection on port 22.\n"
            f"  - The VM may still be booting -- the appliance needs a few minutes.\n"
            f"  - Check in vCenter that the VM is powered on."
        )
    if "timed out" in out.lower() or "no route to host" in out.lower():
        return (
            f"{host} did not answer.\n"
            f"  - Did the OVF network properties apply? A wrong IP or gateway makes\n"
            f"    the node unreachable even though ovftool reported success.\n"
            f"  - Verify in vCenter whether VMware Tools reports the expected address."
        )
    return f"SSH to {host} failed (exit {result.rc}):\n{out}"


def copy_id(pubkey_file: str, host: str, password: str,
            user: str = "configuser", connect_timeout: int = 20) -> SshResult:
    """Install a public key on `host` with the real system ssh-copy-id.

    This is the docs' key-distribution tool, run from here DIRECTLY to each node
    (one ssh layer, not nested through the bootstrap), so the single password
    prompt comes back reliably through the pty. ssh-copy-id also fixes the
    node's SELinux context (restorecon) and de-duplicates, so nothing has to be
    replicated by hand. The password is written to the pty, never on the argv."""
    argv = [
        "ssh-copy-id",
        # -f: we pass only the .pub file (the private key stays on the bootstrap);
        # without -f ssh-copy-id insists on finding the private key next to it and
        # aborts with "failed to open ID file". -f installs the .pub contents
        # directly. (Trade-off: -f skips the "already installed?" check, so a
        # re-run can append a duplicate identical line -- harmless; sshd matches
        # the first.)
        "-f",
        "-i", pubkey_file,
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        f"{user}@{host}",
    ]
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    reaped: list[int] = []      # exit status caught by _reap
    chunks: list[bytes] = []
    cooldown_until = 0.0
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                if _reap(pid, reaped):
                    break
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
            now = time.time()
            if now >= cooldown_until and PASSWORD_PROMPT.search(data):
                os.write(fd, password.encode() + b"\n")
                cooldown_until = now + 0.5
    finally:
        os.close(fd)
        rc = _rc_from(reaped, pid, 1)

    return SshResult(rc=rc, output=b"".join(chunks).decode(errors="replace").strip())
