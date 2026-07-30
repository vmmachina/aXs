"""write_file -- content over stdin, not over the command line.

docs/08 B2: the content was base64-encoded into `echo <b64> | base64 -d >
path`, so it stood in `ps` on the Mac AND on the bootstrap. Base64 is not
protection, only quoting. What travels this way: `cp-cluster.ini` with
`ansible_password`, `profile.yml` with the logging passwords, and -- found
while planning this fix, not recorded in B2 -- the customer's TLS PRIVATE KEY,
staged by phase 70.

The plaintext file ON the bootstrap is a separate matter: a documented vendor
format, unavoidable, and stated on the credentials screen. Only the transport
was ours to fix.

The password path keeps the old behaviour on purpose. `run_with_password`
drives ssh through a pty which is stdin, stdout and stderr at once, so there is
no free channel beside the password prompt. Breaking that mode to close the
hole would trade a documented exposure for a broken auth path.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from ws1access.context import Context, RemoteError
from ws1access.ssh import SshResult

SECRET = "ansible_password=Str0ng Pass!word"


class _Ctx:
    """A Context stand-in for write_file: it uses node_run, report and the
    password only."""

    def __init__(self, *, key_works: bool = True, password: str = "",
                 key_rc: int = 255,
                 key_error: str = "Permission denied (publickey).",
                 password_works: bool = True) -> None:
        self.key_works = key_works
        self.key_rc = key_rc
        self.key_error = key_error
        self.password_works = password_works
        self.configuser_password = password
        self.user = "configuser"
        self.bootstrap_ip = "192.168.10.10"
        self.cluster_name = "lab"
        self.calls: list[tuple[str, str | None]] = []
        self.reports: list[str] = []

    # Everything write_file needs comes from the REAL Context, bound to this
    # stand-in: the sudo/cd wrapping, the key-first rule, the quoting helpers.
    # Delegating by name rather than listing them means a new helper is
    # exercised automatically instead of becoming an AttributeError that
    # tempts someone to reimplement it here.
    def __getattr__(self, name):
        attr = getattr(Context, name, None)
        if attr is None:
            raise AttributeError(name)
        return attr.__get__(self, type(self))

    def report(self, message):
        self.reports.append(message)

    # Stand in for the ssh layer, recording what would have been executed.
    # Key auth either works or it does not -- whether the command carries
    # stdin has nothing to do with it. Tying the two together made the
    # fallback succeed on the key path and the password path was never
    # reached, so the test that claimed to exercise it exercised nothing.
    def _ssh(self, command, stdin):
        self.calls.append((command, stdin))
        if self.key_works:
            return SshResult(0, "")
        return SshResult(self.key_rc, self.key_error)


def _run(ctx, remote_path, content):
    """Call the real write_file with the ssh layer swapped out."""
    import ws1access.context as mod

    real_key, real_pw = mod.run_with_key, mod.run_with_password

    def fake_key(host, command, user="configuser", stdin=None, **kw):
        return ctx._ssh(command, stdin)

    def fake_pw(host, command, password, user="configuser", **kw):
        ctx.calls.append(("PASSWORD-PATH: " + command, None))
        if ctx.password_works:
            return SshResult(0, "")
        return SshResult(1, "sudo: a password is required")

    mod.run_with_key, mod.run_with_password = fake_key, fake_pw
    try:
        return Context.write_file(ctx, remote_path, content)
    finally:
        mod.run_with_key, mod.run_with_password = real_key, real_pw


class TestKeyPath(unittest.TestCase):
    def setUp(self):
        self.ctx = _Ctx(key_works=True)
        _run(self.ctx, "/root/lab/cp-cluster/cp-cluster.ini", SECRET)
        self.commands = [c for c, _ in self.ctx.calls]
        self.stdins = [s for _, s in self.ctx.calls]

    def test_the_secret_is_not_in_any_command_line(self):
        for command in self.commands:
            self.assertNotIn("Str0ng", command)
            self.assertNotIn("ansible_password", command)

    def test_the_secret_is_not_base64_encoded_into_the_command_line(self):
        # The old form. Encoding is not hiding: anyone reading `ps` can decode.
        import base64
        b64 = base64.b64encode(SECRET.encode()).decode()
        for command in self.commands:
            self.assertNotIn(b64, command)
            self.assertNotIn("base64 -d", command)

    def test_the_content_travels_on_stdin(self):
        self.assertIn(SECRET, self.stdins)

    def test_it_is_written_through_a_temp_file(self):
        # A dropped connection mid-write would otherwise leave a TRUNCATED
        # cp-cluster.ini that still parses -- surfacing much later as an
        # ansible error against a file nobody suspects.
        command = self.commands[0]
        self.assertIn(".axs-tmp", command)
        self.assertIn("mv ", command)

    def test_the_temp_file_is_removed_on_failure(self):
        # docs/08 A16: a previous fix was exactly about not leaving files on
        # the customer's machine.
        self.assertIn("trap", self.commands[0])
        self.assertIn("rm -f", self.commands[0])

    def test_the_file_is_created_with_a_tight_umask(self):
        # The destination holds a TLS private key on the phase-70 path.
        self.assertIn("umask 077", self.commands[0])

    def test_only_one_round_trip(self):
        self.assertEqual(len(self.ctx.calls), 1, self.commands)


class TestPasswordPathStillWorks(unittest.TestCase):
    """The pty has no free stdin. Falling back keeps that mode working; the
    exposure stays there, documented, until ControlMaster lands."""

    def setUp(self):
        self.ctx = _Ctx(key_works=False, password="configuser-pw")
        _run(self.ctx, "/root/lab/profile.yml", SECRET)
        self.commands = [c for c, _ in self.ctx.calls]

    def test_it_falls_back_rather_than_failing(self):
        self.assertTrue(any("PASSWORD-PATH" in c for c in self.commands),
                        self.commands)

    def test_the_fallback_does_not_reuse_the_stdin_command(self):
        # Re-running `cat > file` over a pty would wait for an EOF that never
        # comes -- a failed key auth would become a hang, not an error.
        fallback = [c for c in self.commands if "PASSWORD-PATH" in c][0]
        self.assertNotIn("cat > ", fallback)
        self.assertIn("base64 -d", fallback)

    def test_the_operator_is_told_which_path_was_used(self):
        # The exposure is real in this mode; saying nothing would make it
        # invisible exactly where it applies.
        self.assertTrue(any("password mode" in r for r in self.ctx.reports),
                        self.ctx.reports)

    def test_the_fallback_still_uses_a_tight_umask(self):
        fallback = [c for c in self.commands if "PASSWORD-PATH" in c][0]
        self.assertIn("umask 077", fallback)

    def test_the_fallback_also_writes_through_a_temp_file(self):
        # Not tidiness: `> dest` on an EXISTING file keeps the old mode, so
        # umask 077 would be decorative. profile.yml always exists -- wso
        # access init wrote it. `mv` creates a new inode, so the mode holds.
        fallback = [c for c in self.commands if "PASSWORD-PATH" in c][0]
        self.assertIn(".axs-tmp", fallback)
        self.assertIn("mv ", fallback)
        self.assertIn("trap", fallback)


class TestRunWithKeyActuallyForwardsStdin(unittest.TestCase):
    """The tests above replace run_with_key, so they cannot see whether it
    hands the content to ssh at all. Without this, dropping `input=stdin`
    passes the whole suite and every file is written empty."""

    def call(self, **kw):
        import subprocess

        import ws1access.ssh as ssh

        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            return subprocess.CompletedProcess(argv, 0, "", "")

        real = ssh.subprocess.run
        ssh.subprocess.run = fake_run
        try:
            ssh.run_with_key("10.0.0.1", "cat > /tmp/x", **kw)
        finally:
            ssh.subprocess.run = real
        return seen

    def test_stdin_reaches_subprocess(self):
        seen = self.call(stdin=SECRET)
        self.assertEqual(seen["kwargs"].get("input"), SECRET)

    def test_the_content_is_not_in_argv(self):
        seen = self.call(stdin=SECRET)
        self.assertNotIn(SECRET, " ".join(seen["argv"]))

    def test_no_stdin_is_still_no_stdin(self):
        # Passing input="" instead of None would close stdin for every
        # ordinary remote command -- a different behaviour for the 99% case.
        seen = self.call()
        self.assertIsNone(seen["kwargs"].get("input"))


class TestTheFallbackIsOnlyForAuth(unittest.TestCase):
    """The fallback puts the secret back in argv. It may therefore only be
    reachable for the ONE reason it exists: key auth is not available.

    Gating it on "the command failed" instead meant a full disk, a denied
    sudo or a dropped connection downgraded the transport on a cluster whose
    key auth was perfectly healthy -- and announced "password mode" while
    doing it. The exposure would have come back on the path that never needed
    it, invisibly.
    """

    def attempt(self, rc, error):
        ctx = _Ctx(key_works=False, password="configuser-pw",
                   key_rc=rc, key_error=error)
        raised = None
        try:
            _run(ctx, "/root/lab/profile.yml", SECRET)
        except RemoteError as exc:
            raised = exc
        return ctx, raised

    def assert_no_downgrade(self, rc, error):
        ctx, raised = self.attempt(rc, error)
        self.assertIsNotNone(raised, "a non-auth failure must be reported")
        for command, _ in ctx.calls:
            self.assertNotIn("base64 -d", command,
                             f"downgraded to argv on: {error}")

    def test_a_full_disk_does_not_downgrade(self):
        self.assert_no_downgrade(1, "cat: write error: No space left on device")

    def test_a_denied_sudo_does_not_downgrade(self):
        self.assert_no_downgrade(1, "sudo: a password is required")

    def test_a_timeout_does_not_downgrade(self):
        self.assert_no_downgrade(124, "no answer from 10.0.0.1 after 600s")

    def test_a_dropped_connection_does_not_downgrade(self):
        # rc 255 too, like an auth refusal -- but not an auth refusal.
        self.assert_no_downgrade(255, "ssh: connect to host port 22: "
                                      "Operation timed out")

    def test_an_actual_auth_refusal_does_downgrade(self):
        # The counterpart: the gate must not be so tight that the password
        # mode stops working.
        ctx, raised = self.attempt(255, "Permission denied (publickey).")
        self.assertIsNone(raised)
        self.assertTrue(any("base64 -d" in c for c, _ in ctx.calls), ctx.calls)


class TestPathsWithSpaces(unittest.TestCase):
    """The customer's certificate is named by the operator.

    With the cleanup command built as `trap 'rm -f <already-quoted>' EXIT`, a
    path containing a space closed the trap's own quotes: the command fell
    apart, every write to that path failed, and the word-split `rm -f` deleted
    an unrelated file whose name was a prefix of the path.
    """

    def command_for(self, path):
        ctx = _Ctx(key_works=True)
        _run(ctx, path, SECRET)
        return ctx.calls[0][0]

    def test_the_temp_file_belongs_to_the_destination(self):
        command = self.command_for("/root/lab/certs/WS1 Access cert.pem")
        self.assertIn("WS1 Access cert.pem.axs-tmp", command)


class TestTheCommandActuallyRuns(unittest.TestCase):
    """Executed by a real /bin/sh, not inspected as a string.

    Checking the command with shlex was not enough: the broken `trap '...'`
    form still SPLIT cleanly, so string tests passed while the real shell said
    `invalid signal specification` and the word-split `rm -f` deleted an
    unrelated file. Only running it tells the difference. No network and no
    cluster -- /bin/sh is on every machine this tool runs on.
    """

    def write(self, directory, name, content, *, truncate=False):
        import subprocess

        import ws1access.context as mod

        path = os.path.join(directory, name)

        class Local:
            cluster_name = "lab"

            def __getattr__(inner, attr):
                got = getattr(Context, attr, None)
                if got is None:
                    raise AttributeError(attr)
                return got.__get__(inner, type(inner))

            def bootstrap_run(inner, command, *, become=True,
                              in_cluster_dir=True, stdin=None):
                # Simulate a connection dropping mid-transfer: without a pty
                # there is no SIGHUP, `cat` just sees EOF early and exits 0.
                if truncate and stdin:
                    stdin = stdin[:len(stdin) // 2]
                p = subprocess.run(["/bin/sh", "-c", command], input=stdin,
                                   capture_output=True, text=True)
                return SshResult(p.returncode, p.stdout + p.stderr)

            def report(inner, message):
                pass

        return path, mod.Context._write_via_stdin(Local(), path, content)

    def test_a_path_with_a_space_is_written_correctly(self):
        with tempfile.TemporaryDirectory() as d:
            path, result = self.write(d, "WS1 Access cert.pem", "KEY\n")
            self.assertEqual(result.rc, 0, result.output)
            with open(path) as f:
                self.assertEqual(f.read(), "KEY\n")

    def test_a_path_with_an_apostrophe_is_written_correctly(self):
        with tempfile.TemporaryDirectory() as d:
            path, result = self.write(d, "it's.pem", "KEY\n")
            self.assertEqual(result.rc, 0, result.output)

    def test_the_mode_is_0600(self):
        # umask 077 only holds because `mv` creates a new inode.
        with tempfile.TemporaryDirectory() as d:
            path, _ = self.write(d, "profile.yml", "x")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_an_unrelated_file_is_not_deleted(self):
        # The broken trap deleted a file whose name was a PREFIX of the path.
        with tempfile.TemporaryDirectory() as d:
            bystander = os.path.join(d, "WS1")
            with open(bystander, "w") as f:
                f.write("INNOCENT")
            self.write(d, "WS1 Access cert.pem", "KEY\n")
            self.assertTrue(os.path.exists(bystander),
                            "the cleanup deleted an unrelated file")

    def test_a_truncated_transfer_leaves_no_destination_file(self):
        with tempfile.TemporaryDirectory() as d:
            path, result = self.write(d, "cp-cluster.ini",
                                      "ansible_password=s\n" * 50,
                                      truncate=True)
            self.assertNotEqual(result.rc, 0)
            self.assertFalse(os.path.exists(path),
                             "a truncated file was installed as the real one")

    def test_a_truncated_transfer_leaves_no_temp_file(self):
        # docs/08 A16: nothing of ours stays on the customer's machine.
        with tempfile.TemporaryDirectory() as d:
            self.write(d, "cp-cluster.ini", "ansible_password=s\n" * 50,
                       truncate=True)
            self.assertEqual([f for f in os.listdir(d) if "axs-tmp" in f], [])


class TestTruncationIsDetected(unittest.TestCase):
    """Without a pty there is no SIGHUP when the connection drops: `cat` reads
    EOF, exits 0, and `mv` would install a truncated file that still parses.
    temp+mv alone does not catch that -- comparing the byte count does."""

    def test_the_byte_count_is_checked_before_the_move(self):
        ctx = _Ctx(key_works=True)
        content = "a" * 40 + "ü"          # 41 characters, 42 bytes
        _run(ctx, "/root/lab/profile.yml", content)
        command = ctx.calls[0][0]
        self.assertIn("wc -c", command)
        self.assertIn(str(len(content.encode())), command)

    def test_the_check_comes_before_the_mv(self):
        ctx = _Ctx(key_works=True)
        _run(ctx, "/root/lab/profile.yml", SECRET)
        command = ctx.calls[0][0]
        self.assertLess(command.index("wc -c"), command.index("mv "))


class TestNoSilentSuccess(unittest.TestCase):
    def test_key_failure_without_a_password_raises(self):
        # There is no third way. Reporting success here would leave a phase
        # believing it wrote a file that does not exist.
        ctx = _Ctx(key_works=False, password="")
        with self.assertRaises(RemoteError):
            _run(ctx, "/root/lab/profile.yml", SECRET)

    def test_a_failing_password_fallback_raises_too(self):
        # The last branch. Returning quietly here would leave a phase believing
        # it wrote cp-cluster.ini when nothing was written.
        ctx = _Ctx(key_works=False, password="configuser-pw",
                   password_works=False)
        with self.assertRaises(RemoteError):
            _run(ctx, "/root/lab/cp-cluster/cp-cluster.ini", SECRET)


if __name__ == "__main__":
    unittest.main()
