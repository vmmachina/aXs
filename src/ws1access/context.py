"""Execution context handed to every phase.

A phase never opens an SSH connection or remembers where the working directory
is -- it asks the context. Two facts about this deployment are encoded here once
so no phase can get them wrong:

  * All Linux orchestration runs FROM the bootstrap node, as root. The appliance
    disables root SSH, so we log in as configuser and `sudo` up. `bootstrap_run`
    wraps that.
  * Every `wso` command must run from /root/<cluster>/ or it errors with "the
    cluster work directory does not seem to be initialized". `bootstrap_run`
    therefore cd's into the cluster directory by default.

Node access (phases 00-30) goes directly to each node with `node_run`, which
prefers the key and falls back to the configuser password -- the same two-phase
auth the collector uses.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# control_plane.log lines look like
#   2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| TASK [platform : ...] ***
# Strip that logger prefix and surface the human-meaningful part (the current
# ansible TASK/PLAY), so the live progress reads plainly instead of cryptically.
# Kept as a bare fragment because redact() needs it too -- see _SECRET_COLON.
# It deliberately ENDS at the pipe, with no trailing `\s*`: _SECRET_COLON already
# has `\s*[{,]?\s*` right after it, and a third adjacent whitespace run made the
# engine try every way of splitting one run of spaces across three quantifiers.
# Measured on a line with 1200 trailing spaces: 10.7 s, from ~0. Fable review.
_CP_PREFIX = r"\d{4}-\d\d-\d\d[ T][\d:,]+\s+p=\d+\s+u=\S+\s+n=\S+\s+\w+\|"
_LOG_PREFIX = re.compile("^" + _CP_PREFIX + r"\s*")
_TASK = re.compile(r"^(?:TASK|PLAY|RUNNING HANDLER)\s+\[(.+?)\]")
_TIMING = re.compile(r"^\w+day\s+\d")   # "Thursday 23 July 2026 ..." -- noise
_MARK = "===LOG==="                     # separator between tailed log files
# Written by start_detached before each run, so an appended log can be sliced
# back into per-run segments. Logs are appended rather than truncated (phase
# 80's reset link must survive a re-run), so EVERY reader that means "this run"
# has to cut here -- p60 read `tail -40` and p70 `grep | tail -1` across runs
# and drew conclusions from a previous one.
RUN_MARK = "===== aXs start"
# Liveness markers. They exist so a poll can say "the process is gone" and
# "the bootstrap did not answer" as DIFFERENT things -- an exit status alone
# cannot, because pgrep's rc 1, a dropped connection and an SSH timeout all
# arrive as the same "not ok".
_ALIVE_MARK = "AXS_ALIVE"
_DEAD_MARK = "AXS_DEAD"
# ssh's own vocabulary for "I could not authenticate you", as opposed to "your
# command failed". write_file needs the difference: only the first justifies
# falling back to a transport that puts the file content in the process list.
_AUTH_FAILED = re.compile(
    r"(?i)permission denied|no supported authentication|authentication failed|"
    r"host key verification failed")


def _is_auth_failure(result: "SshResult") -> bool:
    """True only for an ssh-level authentication refusal.

    rc 255 alone is not enough -- ssh uses it for every connection-level
    problem, including a network drop, and a network drop is not a reason to
    downgrade the transport.
    """
    return result.rc == 255 and bool(_AUTH_FAILED.search(result.output or ""))
# Consecutive unanswered polls before we stop guessing and say so. At the
# 30 s default poll that is two and a half minutes of silence.
_UNREACHABLE_LIMIT = 5

# Every long-running wso step we know how to start, plus the worker that
# outlives its CLI wrapper. Used by start_detached_once as a "is the bootstrap
# busy with something else?" guard -- see there for why.
#
# '[w]so ...' keeps pgrep from matching its own command line (p60 explains it in
# full). Patterns are deliberately exact: this list only ever GATES a start, so
# a false positive costs a re-run, while a missing entry costs a collision.
WSO_BUSY = " || ".join(
    f"pgrep -f {p!r} >/dev/null" for p in (
        "[w]so cp deploy",
        "[w]so services deploy",
        "[w]so access create-tenant",
        "[d]eploy_services.py",          # survives `wso services deploy` being killed
    )
)

# Anything sent to the progress sink is mirrored into clusters/<name>/deploy.log
# by the deploy TUI, so a credential that surfaces in a tailed remote log would
# be persisted. The reset-password link is the real case: `wso access
# create-tenant` prints it into create-tenant.log, which wait_while_running
# tails while the phase is still running -- so it can become the "current line"
# of a progress report. It is single-use and expires, but it IS the way to set
# the first admin password, so it does not belong on disk. The KEY stays
# visible (the operator should see that it appeared); only the value is masked.
# The onboarding block shown at the end goes through a different path
# (p80.onboarding_info -> the screen), so the operator still gets the real link.
_RESET_LINK = re.compile(r"(?i)(reset\s+password\s+link\s*[:=]\s*)(\S+)")
# `[:=]`, not just `=`: profile.yml is written by yaml.safe_dump, so its secrets
# appear as `password: value` -- the colon form was not matched at all.
# `.+$`, not `(\S+)`: a password containing a space was masked only up to the
# first space and leaked the rest. Nothing forbids spaces in these passwords.
# Two forms, deliberately different, because one pattern for both was wrong in
# both directions:
#
#   `=`  env/ini style. Broad keyword set including `token` -- NOMAD_TOKEN=,
#        ansible_password=. The keyword must END the key, so `secretsmanager=`
#        is not a credential assignment.
#   `:`  YAML/JSON style. NO bare `token` here: an Access service is literally
#        named `token`, and masking `"token": "READY"` would destroy the
#        readiness output we diagnose with. The key must sit at the start of
#        the line (optionally quoted), so prose like
#        `could not read password: permission denied` keeps its reason.
#
# Both take `.+$`: a password may contain spaces, and stopping at the first one
# leaked the rest.
_SECRET_EQ = re.compile(
    r"(?i)^(.*?\b[\w.-]*(?:token|secret|passphrase|password)\s*=\s*).+$", re.M)
# The token rule is deliberately asymmetric. A PREFIXED token key is always a
# credential (`vault_token:`, `x-vault-token:`, `root_token:`) and wso prints
# those while initialising Vault, straight into the log we tail. A BARE `token:`
# is not: an Access service is named `token`, and masking `"token": "READY"`
# would destroy the readiness output we diagnose with. Dropping `token` from
# this form entirely -- the first attempt -- leaked the prefixed ones.
# `[\s{,]*` so a single-line JSON object (`{"password": "x"}`) is covered too;
# without it the anchor broke on the brace. ONE character class, not the
# `\s*[{,]?\s*` it started as: two whitespace runs either side of an optional
# character are ambiguous, and with the prefix in front of them the engine tried
# every way of splitting one run of spaces between them -- 7 s on a 20 kB line.
# A single class cannot be split, so there is nothing to backtrack through.
# The optional cp_logger prefix is the third thing this rule got wrong. Anchoring
# at the start of the line is right -- it is what keeps `could not read password:
# permission denied` readable -- but wso stamps EVERY control_plane.log line with
# that prefix, and p60 hands a raw `tail -n 40` of that file to a RemoteError
# which tui_deploy writes to clusters/<name>/deploy.log. A `vault_token:` line
# wso prints while initialising Vault therefore survived onto DISK. Allowing one
# MEASURED prefix shape (not "anything before the key", which would re-open the
# prose hole) closes that without loosening the rule anywhere else.
_SECRET_COLON = re.compile(
    r"""(?i)^((?:""" + _CP_PREFIX + r""")?[\s{,]*['"]?"""
    r"""(?:[\w.-]*(?:passphrase|password|secret)|[\w.-]+[_.-]token)"""
    r"""['"]?\s*:\s*).+$""", re.M)
# ovftool takes the vCenter password inside its target URL. ovftool.render()
# masks it on the way to argv logging, but any OTHER path that quotes a vi://
# target -- an error tail, a traceback -- would not have been covered.
# The user part must be allowed to contain '@': the standard vCenter SSO account
# IS administrator@vsphere.local. VCenter.locator URL-encodes it, so aXs's own
# targets were covered by accident -- but a hand-typed one, or a vendor error
# quoting the target verbatim, was not. The password must then stop at '/' too,
# exactly as ovftool._VI_CRED already does: without that, a credential-LESS
# locator `vi://admin@vc.local:443/dc/host@cluster` matched from the port to a
# later '@' in the path and masked port and path -- the parts worth diagnosing.
# A real password never carries a bare '/' here; VCenter.locator encodes it.
_VI_CRED = re.compile(r"(vi://[^:/\s]+):([^@/\s]+)@")
_MASK = "••••••••"


def redact(text: str) -> str:
    """Mask credential values in a line before it can reach a log file or a UI."""
    text = _RESET_LINK.sub(lambda m: m.group(1) + _MASK, text)
    text = _VI_CRED.sub(lambda m: m.group(1) + ":" + _MASK + "@", text)
    text = _SECRET_EQ.sub(lambda m: m.group(1) + _MASK, text)
    return _SECRET_COLON.sub(lambda m: m.group(1) + _MASK, text)


def humanize_log(text: str) -> str:
    """Pick the most meaningful line from a remote log tail and clean it up.

    Prefers the last ansible TASK/PLAY name (what is running now); otherwise the
    last non-trivial line. Returns '' if nothing useful is present."""
    lines = [_LOG_PREFIX.sub("", ln).strip() for ln in text.splitlines()]
    lines = [ln for ln in lines
             if ln and ln != _MARK and not ln.startswith(RUN_MARK)]
    for ln in reversed(lines):
        m = _TASK.match(ln)
        if m:
            return m.group(1).strip()
    for ln in reversed(lines):
        if not _TIMING.match(ln):
            return ln[:120]
    return lines[-1][:120] if lines else ""


def last_segment(text: str) -> str:
    """Only the newest run's part of an appended log.

    Returns everything after the last RUN_MARK, or the whole text if no marker
    is present (logs written before this existed, or by wso itself)."""
    idx = text.rfind(RUN_MARK)
    if idx < 0:
        return text
    nl = text.find("\n", idx)
    return text[nl + 1:] if nl >= 0 else ""


def clean_tail(text: str, n: int = 10, width: int = 200) -> str:
    """The last `n` meaningful lines of a remote log tail, for the live log box.

    Strips the cp_logger prefix, drops blank + pure-timing lines, trims width.
    Keeps original order so the box reads like a normal `tail -f`."""
    out = []
    for ln in text.splitlines():
        s = _LOG_PREFIX.sub("", ln).rstrip()
        if (not s.strip() or s.strip() == _MARK
                or s.strip().startswith(RUN_MARK) or _TIMING.match(s.strip())):
            continue
        out.append(s[:width])
    return "\n".join(out[-n:])

from .ssh import (
    DENIED,
    SshResult,
    copy_id,
    run_with_key,
    run_with_password,
    scp_to,
)


class RemoteError(RuntimeError):
    """A remote command returned non-zero. Carries the output for explain_failure."""

    def __init__(self, step: str, result: SshResult):
        self.step = step
        self.result = result
        super().__init__(f"{step} failed (exit {result.rc}):\n{result.output}")


@dataclass
class Context:
    bootstrap_ip: str
    # REMOTE name: cluster.name from config.yml -> the wso working directory
    # /root/<cluster_name> on the bootstrap node.
    cluster_name: str
    # LOCAL name: the folder clusters/<local_name>/ this run was started with
    # (`axs ... -c <local_name>`). The two are independent and may differ, so
    # any command we suggest to the operator must use the right one.
    local_name: str = ""
    configuser_password: str = field(default="", repr=False)
    user: str = "configuser"
    bundle_path: str = ""           # local asset bundle .zip (config: assets.bundle)
    size: str = "small"             # small | medium | large (config: cluster.size)
    auth: str = "key"               # key | password (config: cluster.auth)
    platform_ips: list[str] = field(default_factory=list)
    access_ips: list[str] = field(default_factory=list)
    access: dict = field(default_factory=dict)   # config `access` section (phase 70)
    # config `deployment_settings` -- NTP / NFS / logging / Nomad bridge, all
    # optional. Empty means: leave the profile.yml wso generated untouched.
    deployment_settings: dict = field(default_factory=dict)
    # Logging backend passwords, collected at deploy time. Kept apart from
    # deployment_settings so the settings dict stays free of secrets and can be
    # reported or logged without care.
    logging_passwords: dict = field(default_factory=dict, repr=False)
    vcenter: dict = field(default_factory=dict)  # config `vcenter` (+ resolved password)
    ova_path: str = ""                           # config `ova.path` (phase 10)
    nodes: list = field(default_factory=list)    # all nodes: {hostname, ip, role}
    network: dict = field(default_factory=dict)  # config `network` (phase 10)
    loadbalancer: dict = field(default_factory=dict)  # config `loadbalancer` (phase 30)
    reverse_proxies: list = field(default_factory=list)  # config `reverse_proxies` (XFF)
    # Optional live-progress sink (set by the deploy TUI). Phases call
    # ctx.report("...") for sub-steps; without a sink it is a no-op, so the
    # plain CLI path is unaffected.
    progress: object = field(default=None, repr=False)
    # Optional live LOG-tail sink (set by the deploy TUI): the last N lines of
    # the long remote steps (wso cp/services deploy, create-tenant), so the
    # operator sees the raw log, not just a one-line summary. No-op without it.
    log_sink: object = field(default=None, repr=False)

    def report(self, msg: str) -> None:
        if self.progress:
            try:
                self.progress(redact(msg))
            except Exception:
                pass

    def report_log(self, text: str) -> None:
        # Redacted like report(), and for a concrete reason: this sink carries
        # raw remote log tails. Phase 80 tails create-tenant.log, where wso
        # prints the single-use admin reset link -- it was reaching the live log
        # box unmasked, and on a phase-80 failure the box stays on screen until
        # the operator quits. Not written to disk (that sink redacts), but a
        # screen is not nothing.
        if self.log_sink:
            try:
                self.log_sink(redact(text))
            except Exception:
                pass

    def password_refused(self) -> bool:
        """True only if the bootstrap actively REFUSES the configuser password.

        A wrong password would otherwise let every phase-20 node probe fail and
        make the phase spin for 20 minutes -- and rack up faillock lockouts. So
        the deploy checks this once up front and fails fast with a clear message.
        Network errors return False (not a password problem) -- reachability is
        the engine's job; only an actual "Permission denied" is caught here.
        """
        r = run_with_password(self.bootstrap_ip, "true", self.configuser_password,
                              user=self.user, connect_timeout=10)
        if r.ok:
            return False
        return bool(DENIED.search(r.output.encode()))

    @property
    def cluster_dir(self) -> str:
        """The wso working directory on the bootstrap: /root/<cluster>."""
        return f"/root/{self.cluster_name}"

    def node_run(self, ip: str, command: str, *,
                 stdin: str | None = None) -> SshResult:
        """Run a command on a node. Key first, password fallback.

        `stdin` only reaches the KEY path -- the password path drives ssh
        through a pty that is stdin, stdout and stderr at once. And with stdin
        set there is NO password fallback: retrying a command that reads its
        input (`cat > file`) over a pty would leave it waiting for an EOF that
        never comes, turning a failed key auth into a hang. The caller gets the
        key-path failure and decides; write_file, the only such caller, has its
        own fallback that needs no stdin.
        """
        r = run_with_key(ip, command, user=self.user, stdin=stdin)
        if not r.ok and stdin is None and self.configuser_password:
            r = run_with_password(ip, command, self.configuser_password, user=self.user)
        return r

    def bootstrap_run(
        self, command: str, *, become: bool = True, in_cluster_dir: bool = True,
        stdin: str | None = None,
    ) -> SshResult:
        """Run a command on the bootstrap node.

        By default it becomes root (`sudo`) and runs inside /root/<cluster>/ --
        the only correct way to invoke `wso`. Set in_cluster_dir=False for the
        few commands that must run elsewhere (e.g. creating the directory), and
        become=False for something that genuinely should stay configuser.
        """
        inner = command
        if in_cluster_dir:
            inner = f"cd {shlex.quote(self.cluster_dir)} && {command}"
        wrapped = f"sudo -n bash -lc {shlex.quote(inner)}" if become else inner
        return self.node_run(self.bootstrap_ip, wrapped, stdin=stdin)

    def node_root_run(self, ip: str, command: str) -> SshResult:
        """Run a command as root on ANY node, the way bootstrap_run does for
        the bootstrap.

        It exists because some checks have to happen where the thing under test
        actually happens. The NFS target is the case: the containers that mount
        it run on the platform nodes, not on the bootstrap, so a check that
        only ever asked the bootstrap was asking the wrong machine (docs/08 B8).

        No `cd` into the cluster directory -- that is a wso requirement and
        wso does not run on these nodes.
        """
        return self.node_run(ip, f"sudo -n bash -lc {shlex.quote(command)}")

    def bootstrap_step(self, step: str, command: str, **kw) -> SshResult:
        """Like bootstrap_run but raises RemoteError on non-zero -- for run().

        Reports the step name to the live-progress sink, so every phase narrates
        its sub-steps without any per-phase wiring."""
        self.report(f"{step} ...")
        r = self.bootstrap_run(command, **kw)
        if not r.ok:
            raise RemoteError(step, r)
        return r

    def stage_bundle(self, local_zip: str) -> None:
        """Get the asset bundle onto the bootstrap, unpacked, wso installed.

        Mirrors the documented procedure exactly (ssh configuser -> sudo su ->
        mkdir /root/<cluster>/assets -> scp -> unzip -> cp wso /usr/bin). root
        SSH is disabled, so the bundle lands in configuser's home and is moved
        into place as root.
        """
        name = Path(local_zip).name
        assets = f"{self.cluster_dir}/assets"
        staged = f"/home/{self.user}/{name}"

        self.bootstrap_step("create working dir", f"mkdir -p {shlex.quote(assets)}",
                            in_cluster_dir=False)
        self._check_space(local_zip, staged, assets)
        size_gb = Path(local_zip).stat().st_size / 1e9
        self.report(f"copying asset bundle to bootstrap ({size_gb:.1f} GB via scp "
                    "-- takes a while) ...")
        r = scp_to(local_zip, self.bootstrap_ip, staged, self.configuser_password,
                   user=self.user)
        if not r.ok:
            raise RemoteError("upload bundle", r)
        self.bootstrap_step("move bundle into assets",
                            f"mv {shlex.quote(staged)} {shlex.quote(assets)}/",
                            in_cluster_dir=False)
        self.bootstrap_step("unzip bundle",
                            f"cd {shlex.quote(assets)} && unzip -o {shlex.quote(name)}",
                            in_cluster_dir=False)
        self.bootstrap_step("install wso CLI",
                            f"cp {shlex.quote(assets)}/cli-distribution/linux/wso /usr/bin/",
                            in_cluster_dir=False)

    def free_bytes(self, remote_dir: str) -> int | None:
        """Free space on the filesystem holding `remote_dir`, or None.

        None means "could not tell" -- a missing directory, an unreachable
        bootstrap, a df that answered something unexpected. Callers must not
        read that as "plenty": guessing in either direction is how a check ends
        up more confident than the thing it checks.
        """
        r = self.bootstrap_run(f"df -Pk {shlex.quote(remote_dir)} 2>/dev/null",
                               in_cluster_dir=False)
        if not r.ok:
            return None
        lines = [ln for ln in (r.output or "").splitlines() if ln.strip()]
        # POSIX `df -P` gives one line per filesystem with Available in the 4th
        # column, in 1K blocks; -P is also what stops a long device name from
        # wrapping onto a second line, which plain `df` does.
        #
        # Scanned from the END for a line that actually parses, rather than
        # taking the last one: bootstrap_run goes through a LOGIN shell and
        # ssh returns stdout and stderr concatenated, so a chatty profile can
        # append a line after df's. Taking the last line blindly turned that
        # into "could not tell" and quietly disabled the check for good.
        for line in reversed(lines):
            parts = line.split()
            if len(parts) >= 4 and parts[3].isdigit():
                return int(parts[3]) * 1024
        return None

    # What phase 40 needs where. The archive is scp'd into the operator's home,
    # moved into <cluster>/assets, unpacked there, and then `wso configure`
    # loads the images -- which lands in docker's storage, very likely the same
    # filesystem.
    #
    # 26 GB is the figure phase 40's own failure text has always quoted. Note
    # WHERE it quotes it: in the branch for `wso configure` failing, not for
    # the unzip. So it is a rough number for everything after the upload, and
    # nothing states whether it includes the archive or the image storage. It
    # is therefore added ON TOP of the archive and only ever WARNS -- a
    # requirement invented too high would refuse a deploy that would have
    # worked, which is the same class of harm as not checking. That the archive
    # itself has to fit is certain, so THAT part refuses.
    _AFTER_UPLOAD_BYTES = 26 * 1000 ** 3

    def _check_space(self, local_zip: str, staged: str, assets: str) -> None:
        """Refuse before a 13.5 GB upload that cannot land, warn about the rest.

        Failing on a full disk at 90% of the transfer costs the whole transfer,
        and the error arrives as whatever scp says about a partial write --
        nowhere near "the bootstrap is out of space" (docs/08 B10).
        """
        need = Path(local_zip).stat().st_size
        home = str(Path(staged).parent)
        for where, path in (("staging directory", home), ("cluster directory", assets)):
            free = self.free_bytes(path)
            if free is None:
                self.report(f"WARNING — could not read free space on {path}; "
                            "skipping the disk check for it.")
                continue
            if free < need:
                raise RemoteError(
                    "not enough disk space on the bootstrap",
                    SshResult(1,
                        f"The {where} {path} has {free / 1e9:.1f} GB free, and "
                        f"the asset bundle alone is {need / 1e9:.1f} GB.\n"
                        "  The upload would fail partway through and report it "
                        "as a broken transfer, not as a full disk.\n"
                        "  Most often the space is taken by the partial bundle "
                        f"of an earlier, interrupted upload -- look in {home} "
                        "first.\n"
                        "  Free space there and re-run; nothing has been "
                        "uploaded yet."))
        free_assets = self.free_bytes(assets)
        if free_assets is not None and free_assets < need + self._AFTER_UPLOAD_BYTES:
            self.report(
                f"WARNING — {assets} has {free_assets / 1e9:.1f} GB free. The "
                f"bundle is {need / 1e9:.1f} GB, and unpacking it plus loading "
                f"the images needs roughly {self._AFTER_UPLOAD_BYTES / 1e9:.0f} GB "
                "more -- an estimate, and it is not known whether that figure "
                "already counts the archive. There is room for the upload "
                "itself; what follows it may not fit. Continuing.")

    def write_file(self, remote_path: str, content: str) -> None:
        """Write a file on the bootstrap as root, content over stdin.

        These files carry secrets: `cp-cluster.ini` has `ansible_password`,
        `profile.yml` the logging passwords, and phase 70 stages the customer's
        TLS PRIVATE KEY through here. Sending the content in the command line
        put every one of them in `ps` -- on the Mac AND on the bootstrap.
        Base64 was never protection, only quoting (docs/08 B2).

        The plaintext file ON the bootstrap is a different question: that is a
        documented vendor format, unavoidable, and it is stated on the
        credentials screen. The argv transport was ours.

        Written via a temp file and checked by SIZE before `mv`. The size check
        is the part that matters: without a pty there is no SIGHUP when the
        connection drops, so `cat` simply reads EOF, exits 0, and `mv` would
        install a TRUNCATED cp-cluster.ini that still parses -- surfacing as an
        ansible error much later, against a file nobody suspects. Comparing the
        byte count closes that; temp+mv alone does not, and the first version
        of this comment claimed it did.

        `umask 077` because the destination holds a private key, and it works
        because `mv` creates a NEW inode -- writing over an existing file would
        keep the old mode. `trap` because a half-written temp file must not
        stay on the customer's machine (docs/08 A16 was exactly that).
        """
        self.report(f"writing {remote_path} ...")
        r = self._write_via_stdin(remote_path, content)
        if r.ok:
            return
        # The password path cannot carry stdin: run_with_password drives ssh
        # through a pty which IS stdin/stdout/stderr, so there is no free
        # channel beside the password prompt. Falling back keeps that mode
        # working rather than breaking it -- the exposure stays, documented,
        # until the ControlMaster work lands.
        #
        # Gated on the failure being an AUTH failure, not merely non-zero. A
        # full disk, a denied sudo or a timeout would otherwise put the secret
        # back into argv on a cluster whose key auth is perfectly healthy --
        # reintroducing the exact exposure this method exists to remove, on the
        # path that did not need it, and reporting "password mode" about a key
        # cluster while doing it.
        if not (self.configuser_password and _is_auth_failure(r)):
            raise RemoteError(f"write {remote_path}", r)
        self.report(f"  {remote_path}: key auth unavailable — writing via the "
                    "command line (password mode; the content is briefly "
                    "visible in the process list)")
        r = self._write_via_argv(remote_path, content)
        if not r.ok:
            raise RemoteError(f"write {remote_path}", r)

    def _write_paths(self, remote_path: str) -> tuple[str, str, str]:
        """(destination, temp file, parent) -- all shell-quoted exactly once."""
        return (shlex.quote(remote_path),
                shlex.quote(remote_path + ".axs-tmp"),
                shlex.quote(str(Path(remote_path).parent)))

    def _write_via_stdin(self, remote_path: str, content: str) -> SshResult:
        dest, tmp, parent = self._write_paths(remote_path)
        # The cleanup command is quoted AS A WHOLE. Embedding an already-quoted
        # path inside `trap '...'` closed the trap's own quotes on any path
        # containing a space: the command fell apart, and the word-split `rm
        # -f` deleted an unrelated file whose name was a prefix of the path.
        # The customer's certificate is named by the operator, so "WS1 Access
        # cert.pem" reached exactly this.
        cleanup = shlex.quote(f"rm -f {tmp}")
        size = len(content.encode())
        return self.bootstrap_run(
            f"umask 077 && install -d {parent} && "
            f"trap {cleanup} EXIT && "
            f"cat > {tmp} && "
            f"[ \"$(wc -c < {tmp})\" -eq {size} ] && "
            f"mv {tmp} {dest} && trap - EXIT",
            in_cluster_dir=False, stdin=content)

    def _write_via_argv(self, remote_path: str, content: str) -> SshResult:
        """The pre-2026-07-29 transport, kept for the password path only.

        Same temp-file shape as the stdin path so `umask 077` actually applies:
        writing straight onto an existing profile.yml would have kept whatever
        mode wso left on it.
        """
        dest, tmp, parent = self._write_paths(remote_path)
        cleanup = shlex.quote(f"rm -f {tmp}")
        b64 = base64.b64encode(content.encode()).decode()
        return self.bootstrap_run(
            f"umask 077 && install -d {parent} && "
            f"trap {cleanup} EXIT && "
            f"echo {b64} | base64 -d > {tmp} && "
            f"mv {tmp} {dest} && trap - EXIT",
            in_cluster_dir=False)

    def establish_trust(self, node_ips: list[str], *, key: str = "id_ed25519") -> None:
        """Phase-50 SSH trust: the bootstrap's configuser key is authorized on
        every node -- the docs' outcome, with the docs' own tool (ssh-copy-id).

        The bootstrap generates the key (the private key never leaves it). Its
        PUBLIC key is then installed on each node with the real system
        ssh-copy-id -- but run from HERE, directly to each node, rather than
        nested through the bootstrap. The docs run ssh-copy-id on the bootstrap
        interactively; nesting it for full automation hangs, because its inner
        ssh's password prompt doesn't come back reliably through the layered pty.
        One ssh layer per node fixes that, and ssh-copy-id still does everything
        itself: authorized_keys, 700/600 perms, SELinux restorecon, de-dup.
        """
        self.report(f"SSH trust: generating bootstrap key + ssh-copy-id to "
                    f"{len(node_ips)} nodes ...")
        # 1. Generate the key AS CONFIGUSER (node_run, no sudo) and read its
        #    PUBLIC part. This is critical: the docs do `su configuser;
        #    ssh-keygen`, and phase 50 later copies /home/configuser/.ssh/<key>
        #    into private-key/. bootstrap_step runs via sudo (root), which would
        #    create ROOT's key (comment root@…, in /root/.ssh) -- configuser's
        #    ssh never uses that, so the passwordless login is refused.
        kr = self.node_run(
            self.bootstrap_ip,
            f"test -f ~/.ssh/{key} || ssh-keygen -t ed25519 -N '' "
            f"-f ~/.ssh/{key} >/dev/null; cat ~/.ssh/{key}.pub",
        )
        if not kr.ok:
            raise RemoteError("generate/read bootstrap key (as configuser)", kr)
        pub = kr.output.strip().splitlines()[-1].strip()
        if "ssh-" not in pub:
            raise RemoteError("read bootstrap public key",
                              SshResult(1, f"unexpected pubkey output: {pub[:120]}"))

        # 2. ssh-copy-id the bootstrap PUBLIC key onto each node, from here.
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as f:
            f.write(pub + "\n")
            pubfile = f.name
        try:
            for ip in node_ips:
                self.report(f"SSH trust: ssh-copy-id to {ip} ...")
                r = copy_id(pubfile, ip, self.configuser_password, user=self.user)
                if not r.ok:
                    raise RemoteError(f"ssh-copy-id to {ip}", r)
        finally:
            try:
                os.unlink(pubfile)
            except OSError:
                pass

        # 3. Verify: passwordless login from the bootstrap to every node.
        self.report("SSH trust: verifying passwordless login from the bootstrap ...")
        # '&&', not ';': a ';'-joined compound returns the exit status of the
        # LAST command, so trust could be broken on four of five nodes and this
        # would still be green. ssh-copy-id -f skips its own verification
        # (see ssh.py), which makes this the only check there is -- and the
        # failure surfaces an hour later as an ansible "unreachable", nowhere
        # near its cause. Print the node that fails, not just a status.
        check = " && ".join(
            f"{{ ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
            f"configuser@{shlex.quote(ip)} hostname >/dev/null "
            f"|| {{ echo 'NO passwordless login to {ip}'; false; }}; }}"
            for ip in node_ips
        )
        v = self.node_run(self.bootstrap_ip, check)
        if not v.ok:
            raise RemoteError("verify passwordless login from bootstrap", v)

    def scan_host_keys(self, node_ips: list[str]) -> None:
        """Populate root's known_hosts with the nodes' host keys.

        wso runs ansible as root (in a container). With an empty root
        known_hosts the key-based SSH connection is rejected on the unknown host
        key -- the likely reason the key path failed while password worked. This
        pre-seeds them so the key connection is accepted non-interactively.
        """
        ips = " ".join(shlex.quote(ip) for ip in node_ips)
        cmd = (
            "install -d -m 700 /root/.ssh && "
            f"ssh-keyscan -H {ips} >> /root/.ssh/known_hosts 2>/dev/null; "
            "sort -u /root/.ssh/known_hosts -o /root/.ssh/known_hosts"
        )
        self.bootstrap_step("scan host keys into root known_hosts", cmd,
                            in_cluster_dir=False)

    def start_detached(self, logname: str, command: str) -> None:
        """Start a long-running command on the bootstrap, fully detached.

        setsid + redirect + stdin from /dev/null so it survives the tool
        disconnecting -- the "nohup wso cp deploy &" pattern from the guide.
        Output is APPENDED to <cluster_dir>/<logname>, behind a marker.

        Appending, not truncating, and the reason is not tidiness. Phase 80's
        log holds the admin reset-password link -- the only way to set the
        first admin password, deliberately stored nowhere else. Its done-probe
        goes through the customer's load balancer, so one LB hiccup makes the
        phase look unfinished; truncating on the re-run would destroy that link
        with no way to get it back. The same applies to diagnosis: phase 70
        retries up to three times, and truncating meant the failure you wanted
        to understand was gone by the time you looked.
        """
        marker = f'echo "{RUN_MARK} $(date -Is) =====" >> {logname}'
        launch = (
            f"{marker}; "
            f"setsid bash -lc {shlex.quote(command + f' >> {logname} 2>&1 < /dev/null')} & "
            f"echo started"
        )
        self.bootstrap_step(f"start {logname}", launch)

    def start_detached_once(self, logname: str, command: str, alive_cmd: str,
                            *, busy_cmd: str | None = None) -> None:
        """Start `command` detached, but ONLY if it is not already running.

        This makes the detached phases (60/70/80) safe to re-run: if the tool is
        restarted while `wso cp deploy` is still going on the bootstrap, the phase
        re-attaches to the running process (just resumes waiting) instead of
        launching a second, conflicting one.

        `busy_cmd` guards the case alive_cmd cannot see: a DIFFERENT wso
        operation in progress. Observed live 2026-07-28 -- a restart during
        `wso services deploy` found phase 60's done-probe unhappy, and phase 60
        launched `wso cp deploy` alongside it. It happened to be a no-op that
        time; with real work to do, two wso operations would have been writing
        to one cluster. Refusing is the only safe answer: these steps are
        sequential by design, and the operator can re-run once the other
        finishes."""
        state = self.probe_alive(alive_cmd)
        if state == "alive":
            self.report("already running on the bootstrap — re-attaching, not restarting")
            return
        if state == "unknown":
            # We could not ASK. Treating that as "not running" is how a network
            # blip turns into a second deploy against a cluster the first one is
            # still working on -- the failure this whole guard exists to prevent.
            raise RemoteError(
                "cannot tell whether a deploy is already running",
                SshResult(1, "The bootstrap did not answer the liveness check, "
                             "so starting now could launch a second deploy "
                             "alongside a running one.\n"
                             "  Check the connection to the bootstrap and re-run."))
        if busy_cmd and self.bootstrap_run(busy_cmd).ok:
            raise self.busy_error()
        self.start_detached(logname, command)

    def probe_alive(self, alive_cmd: str) -> str:
        """'alive' | 'dead' | 'unknown' -- and the third one is the point.

        `bootstrap_run` returns the same "not ok" for pgrep finding nothing
        (rc 1), for a dropped connection (rc 255) and for the SSH run timeout
        (rc 124). Reading all three as "the process is gone" means one VPN blip
        makes the tool announce a finished deploy that is still running -- and
        phase 60 then reports "no new Folder Hash" about a perfectly healthy
        run. So ask in a way that separates the transport from the answer: the
        markers only appear if the remote shell actually executed.
        """
        r = self.bootstrap_run(
            f"if {alive_cmd}; then echo AXS_ALIVE; else echo AXS_DEAD; fi")
        out = r.output or ""
        if "AXS_ALIVE" in out:
            return "alive"
        if "AXS_DEAD" in out:
            return "dead"
        return "unknown"

    def busy_error(self) -> "RemoteError":
        """The refusal raised when another wso step is already running.

        Naming the process and its PID is the whole point. Refusing is right --
        wso steps are sequential -- but "wait for the running step to finish"
        is a dead end for anyone who does not know the internals: if that step
        is genuinely wedged, there is nothing to wait for and no stated way
        back. So show what is running and what to do about it.
        """
        running = self.bootstrap_run(
            "pgrep -fal '[w]so cp deploy|[w]so services deploy|"
            "[w]so access create-tenant|[d]eploy_services.py' 2>/dev/null "
            "| head -5").output.strip()
        return RemoteError(
            "another wso operation is running on the bootstrap",
            SshResult(1,
                "Refusing to start a second one -- wso steps are sequential "
                "and must not overlap.\n"
                f"  Running now:\n{running or '  (could not list it)'}\n"
                "  Normally: wait for it to finish, then re-run.\n"
                "  If it is genuinely wedged (no new output for a long time), "
                "stop it ON THE BOOTSTRAP:\n"
                "      pkill -f '[p]ython[0-9.]* /scripts/deploy_services.py'"
                "   # then -9 if needed"))

    def _stop_stalled(self, on_stall: str, alive_cmd: str, label: str) -> None:
        """Kill a stalled remote step -- and VERIFY it died.

        Firing the kill and returning is not the same as the process being
        gone, and the difference is dangerous: the caller then treats a live
        process as finished, the next attempt re-attaches to it, stalls again,
        and finally raises "stuck" -- whose remediation tells the operator to
        run `wso services deploy -s <svc>` by hand. That manual command has no
        busy guard, so a silent failure to kill ends in exactly the concurrent
        deploy the guard exists to prevent.

        SIGTERM first (the caller's command), then SIGKILL, then give up
        loudly. A process wedged in uninterruptible I/O -- an NFS hang, the
        failure family this repo has already paid for twice -- survives both,
        and the only honest answer then is to say so and stop.
        """
        answered = False

        def _gone() -> bool:
            # Only an explicit "dead" counts. `not ok` would mean "dead OR the
            # bootstrap did not answer" -- the very confusion probe_alive
            # exists to remove, and here it cuts both ways: a blip would skip
            # the SIGKILL escalation and leave the worker running, or make us
            # raise "could not stop it, reboot the bootstrap" about a process
            # that died on the first signal.
            nonlocal answered
            for _ in range(3):
                time.sleep(3)
                state = self.probe_alive(alive_cmd)
                if state != "unknown":
                    answered = True
                if state == "dead":
                    return True
            return False

        self.bootstrap_run(on_stall)
        if _gone():
            return
        self.report(f"{label} — it ignored the stop signal; escalating ...")
        self.bootstrap_run(on_stall.replace("pkill -f", "pkill -9 -f"))
        if _gone():
            return
        if not answered:
            # We never got a single answer, so we never SAW it survive anything.
            # Claiming "it is wedged in the kernel, reboot the bootstrap" here
            # would be the same misattribution probe_alive exists to prevent --
            # on a plain network outage that advice is both false and harmful.
            raise RemoteError(
                "lost contact with the bootstrap while stopping the stalled step",
                SshResult(1,
                    "Every liveness check went unanswered, so aXs cannot say "
                    "whether the step stopped.\n"
                    "  Fix the connection and re-run -- the phase re-attaches "
                    "if the step is still going."))
        still = self.bootstrap_run(
            "pgrep -fal '[w]so |[d]eploy_services.py' 2>/dev/null | head -5").output
        raise RemoteError(
            "could not stop the stalled step on the bootstrap",
            SshResult(1,
                "It survived SIGTERM and SIGKILL, so it is wedged in the "
                "kernel -- typically uninterruptible I/O on an unresponsive "
                "NFS server.\n"
                "  Do NOT start another wso step: it would run alongside this "
                "one.\n"
                f"  Still running:\n{still}\n"
                "  Fix the underlying I/O (check the NFS target), then reboot "
                "the bootstrap if the process still will not die."))

    def wait_while_running(
        self,
        alive_cmd: str,
        *,
        poll: int = 30,
        timeout: int = 6 * 3600,
        label: str = "remote step",
        logfile: "str | list[str] | None" = None,
        stall_after: int | None = None,
        on_stall: str | None = None,
    ) -> None:
        """Block until a detached bootstrap process ends (via alive_cmd, e.g.
        pgrep). Raises on timeout. Success/failure of the WORK is judged
        afterwards by the phase's own probe (e.g. wso healthcheck) -- not by log
        string-matching, which is brittle across wso builds (the "New Folder
        Hash:" success line the guide shows does not appear in every build).

        The timeout is deliberately generous (6 h). The guide quotes ~30-60 min
        for `wso cp deploy` and ~40 min for `wso services deploy`, but on slow or
        large environments these run much longer; a real operator must not have
        the tool abort a legitimate deployment. Failure is detected by the
        process ENDING, not by the clock -- the timeout is only a last-resort
        backstop against a truly hung process.

        `stall_after` covers the case the 6 h backstop is useless for: a process
        that is alive, so pgrep keeps saying yes, but has stopped doing anything.
        Seen live on 2026-07-28 -- `wso services deploy` submitted the postgres
        job, Nomad never placed it on any node, and the deploy sat there. The
        tool cheerfully reported "running 53:30" for 72 minutes; only killing it
        by hand let the built-in retry take over, and the retry is where the
        recovery lives. If the tail stops changing for `stall_after` seconds we
        run `on_stall` (a kill) and return, so the caller's acceptance check
        fails and its normal retry path runs.

        Keep the threshold well clear of legitimate quiet: `wso cp deploy` sits
        on one ansible task ("Hydrate Asset Server") for minutes at a time.
        Off by default -- a phase must opt in, having thought about its own
        rhythm.
        """
        # One ssh per poll answers BOTH "still alive?" and "what do the last log
        # lines say?" -- the latter feeds the live progress AND the log box, so
        # the operator always sees what the remote step is doing.
        logs = [logfile] if isinstance(logfile, str) else list(logfile or [])
        if logs:
            # Tail every candidate log, newest-relevant last: a phase passes
            # [stdout, ansible_log] -- the stdout exists immediately (so the box
            # is never empty during warm-up), the ansible log arrives later with
            # the real TASK names and, being last, dominates the tail once present.
            tails = "; ".join(
                f"echo {shlex.quote(_MARK)}; tail -n 120 {shlex.quote(lf)} 2>/dev/null"
                for lf in logs
            )
            probe_cmd = (f"if {alive_cmd}; then echo {_ALIVE_MARK}; "
                         f"else echo {_DEAD_MARK}; fi; {tails}")
        else:
            probe_cmd = (f"if {alive_cmd}; then echo {_ALIVE_MARK}; "
                         f"else echo {_DEAD_MARK}; fi")
        waited = 0
        last_body: str | None = None
        last_change = 0
        unreachable = 0
        while waited <= timeout:
            r = self.bootstrap_run(probe_cmd)
            body = r.output or ""

            # Separate "the process is gone" from "we could not ask". Both used
            # to look identical (bootstrap_run returns not-ok for pgrep's rc 1,
            # for a dropped connection and for the SSH run timeout alike), so a
            # single VPN blip made the tool announce a finished deploy that was
            # still running -- and phase 60 then reported "no new Folder Hash"
            # about a healthy run.
            if _DEAD_MARK in body:
                return
            if _ALIVE_MARK not in body:
                unreachable += 1
                if unreachable >= _UNREACHABLE_LIMIT:
                    raise RemoteError(
                        "lost contact with the bootstrap",
                        SshResult(1,
                            f"{_UNREACHABLE_LIMIT} consecutive liveness checks "
                            "got no answer. The remote step may still be "
                            "running; aXs cannot tell.\n"
                            "  Fix the connection and re-run -- the phase will "
                            "re-attach if the step is still going.\n"
                            f"  Last output: {body.strip()[-200:] or '(none)'}"))
                self.report(f"{label} — bootstrap did not answer "
                            f"({unreachable}/{_UNREACHABLE_LIMIT}), retrying ...")
                time.sleep(poll)
                waited += poll
                continue
            unreachable = 0
            # The marker is our bookkeeping, not part of the remote log. Drop it
            # before anything displays or compares the tail.
            body = "\n".join(ln for ln in body.splitlines()
                             if ln.strip() != _ALIVE_MARK)

            mins, secs = divmod(waited, 60)
            human = humanize_log(body) if logs else ""
            tail = f"  ·  {human}" if human else ""
            self.report(f"{label} — running {mins:d}:{secs:02d}{tail}")
            if logs:
                # Send a generous buffer; the UI decides how many lines it shows
                # (live-adjustable with +/-), slicing from what it receives here.
                self.report_log(clean_tail(body, 60))

            # Stall watch. Compare the whole tail, not the humanised one-liner:
            # two different ansible tasks can humanise to the same string, and a
            # process that is genuinely working still moves SOMETHING in 120
            # lines of log.
            if body != last_body:
                last_body, last_change = body, waited
            elif stall_after and waited - last_change >= stall_after:
                self.report(
                    f"{label} — no new output for {stall_after // 60} min; "
                    "the process is alive but idle. Stopping it so the retry "
                    "can take over.")
                if on_stall:
                    self._stop_stalled(on_stall, alive_cmd, label)
                return

            time.sleep(poll)
            waited += poll
        raise RemoteError("timeout waiting for detached process",
                          SshResult(1, f"still running after {timeout}s"))
