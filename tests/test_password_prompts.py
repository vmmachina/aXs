"""The password path must never wait forever.

Found in the field on 2026-07-29: `axs status` stopped after `10_vms` and hung
with no output at all. `ps` showed the ssh for node 10.10.50.1 sitting there.
By hand, that node asks TWICE:

    configuser@10.10.50.1's password:      <- the `password` method
    (configuser@10.10.50.1) Password:      <- keyboard-interactive

`NumberOfPasswordPrompts=1` caps the first METHOD; when it is exhausted ssh
moves on to keyboard-interactive, which asks again in its own words. aXs
answered once and then fell silent, so ssh waited for input that never came --
and this path, unlike run_with_key, had no deadline at all.

Two decisions the tests pin:

  * A second prompt ENDS the attempt as refused. Answering it would spend a
    second failed attempt against an account faillock can lock out, and six
    nodes make that twelve. The second prompt only supports one conclusion
    anyway: the first answer was not accepted.
  * There is a deadline. run_with_key has had one all along.

These run a real pty against a real child, because that is what the code does.
os.execvp is patched so the child becomes a small script instead of ssh; the
fork inherits the patch, so the parent's loop is exercised unchanged.

The child sleeps 15 s, not 60: with the fix reverted these tests would WAIT for
it, and a regression that hangs the suite is worse than one that fails it. At
15 s against a 5 s bar they fail in seconds and the whole file still runs in
about three.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

from ws1access import ssh

# A stand-in for sshd. Prints prompts on the tty, records what it is told.
CHILD = r"""
import os, sys, time
record = open(sys.argv[1], "w")
record.write("PID %d\n" % os.getpid())
record.flush()
sys.stdout.write("configuser@node's password: ")
sys.stdout.flush()
record.write(sys.stdin.readline())
record.flush()
mode = sys.argv[2]
sentinel = sys.argv[3] if len(sys.argv) > 3 else "__AXS_AUTH_STARTED__"
real_remote = sys.argv[4] if len(sys.argv) > 4 else ""
if mode == "exec-real":
    # Auth is done (the prompt above was answered). Now run the REAL command
    # the production code built -- argv[-1], the `printf SENTINEL; <cmd>` wrap --
    # through /bin/sh, and stream its output the way the real remote would. The
    # sentinel therefore comes from the production wrap; delete the wrap and this
    # prints none, so a "password:" in the command's own output is misread as a
    # refusal again. This is what makes the wrap itself testable.
    import subprocess
    done = subprocess.run(["/bin/sh", "-c", real_remote],
                          capture_output=True, text=True)
    sys.stdout.write("\n" + done.stdout)
    sys.stdout.flush()
    record.close()
    raise SystemExit(done.returncode)
if mode == "ask-again":
    # Ask a second time and RECORD whether anything is sent for it, so a
    # change that answers the second prompt cannot pass unnoticed.
    sys.stdout.write("\n(configuser@node) Password: ")
    sys.stdout.flush()
    import select as _sel
    if _sel.select([sys.stdin], [], [], 5.0)[0]:
        record.write(sys.stdin.readline())
        record.flush()
    time.sleep(8)
    record.close()
    raise SystemExit(0)
if mode == "accept":
    sys.stdout.write("\nHELLO-FROM-NODE\n")
    sys.stdout.flush()
elif mode == "stall":
    time.sleep(8)                  # connected, then nothing
elif mode == "chatty":
    for _ in range(5):             # ~3 s of work, a line every 0.6 s
        time.sleep(0.6)
        sys.stdout.write("STILL-GOING\n")
        sys.stdout.flush()
elif mode == "late-word":
    # Authenticated fine, then the COMMAND says the word later on.
    time.sleep(1.0)
    sys.stdout.write("\nwso: retrieving admin password: ok\nDONE-ANYWAY\n")
    sys.stdout.flush()
record.close()
"""


class _Child:
    """Replace the ssh the child execs with the script above."""

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def __enter__(self):
        self.dir = tempfile.mkdtemp()
        self.record = os.path.join(self.dir, "given")
        open(self.record, "w").close()
        real_execvp = os.execvp

        def fake_execvp(_file, _argv):
            # _argv[-1] is the REAL remote command the PRODUCTION code built --
            # the `printf SENTINEL; <cmd>` wrap. The exec-real mode runs it for
            # real, so the sentinel comes from production, not from the test.
            real_execvp(sys.executable,
                        [sys.executable, "-c", CHILD, self.record, self.mode,
                         ssh._AUTH_SENTINEL, _argv[-1]])

        self.real = ssh.os.execvp
        ssh.os.execvp = fake_execvp
        return self

    def __exit__(self, *exc):
        ssh.os.execvp = self.real

    def answers(self) -> list[str]:
        with open(self.record) as f:
            return [ln for ln in f.read().splitlines()
                    if ln and not ln.startswith("PID ")]

    def pid(self) -> int:
        with open(self.record) as f:
            return int(f.readline().split()[1])


class TestTheHappyPath(unittest.TestCase):
    def test_one_prompt_is_answered_and_the_output_comes_back(self):
        with _Child("accept") as child:
            result = ssh.run_with_password("node", "true", "s3cret")
        self.assertIn("HELLO-FROM-NODE", result.output)
        self.assertEqual(child.answers(), ["s3cret"])

    def test_the_prompt_line_is_not_shown_to_the_caller(self):
        with _Child("accept"):
            result = ssh.run_with_password("node", "true", "s3cret")
        self.assertNotIn("password:", result.output.lower())


class TestASecondPromptMeansRefused(unittest.TestCase):
    """The defect: asked twice, aXs answered once and then waited forever."""

    def run_it(self):
        start = time.monotonic()
        with _Child("ask-again") as child:
            result = ssh.run_with_password("node", "true", "wrong-password")
        return result, child.answers(), time.monotonic() - start

    def test_it_returns_instead_of_hanging(self):
        result, _, took = self.run_it()
        self.assertLess(took, 5, "it waited for the second prompt")
        self.assertFalse(result.ok)

    def test_it_names_both_readings_of_a_second_prompt(self):
        # "the first answer was refused" is the usual one but not the only
        # one: a CORRECT but expired password also produces a second prompt,
        # because PAM then wants a new one. Claiming only the first would send
        # the operator hunting for a password that is fine.
        result, _, _ = self.run_it()
        self.assertIn("Usually the password is wrong", result.output)
        self.assertIn("EXPIRED", result.output)

    def test_the_wording_is_the_one_password_refused_looks_for(self):
        # context.password_refused matches on "permission denied" to fail the
        # deploy fast -- which is also what keeps phase 20 from spinning and
        # racking up faillock lockouts.
        from ws1access.ssh import DENIED
        result, _, _ = self.run_it()
        self.assertTrue(DENIED.search(result.output.encode()), result.output)

    def test_it_does_not_spend_a_second_attempt(self):
        # Six nodes times two attempts is twelve failures against an account
        # faillock can lock out.
        _, given, _ = self.run_it()
        self.assertEqual(given, ["wrong-password"])


class TestOutputThatMerelyMentionsThePassword(unittest.TestCase):
    """A working session must not be killed by its own output.

    Every chunk used to be checked for the prompt, forever. A remote step
    printing "retrieving admin password: ok" was therefore read as a second
    prompt: the session was terminated mid-command and reported to the operator
    as a wrong password. Phase 40 runs `wso configure` over exactly this path
    and is explicitly not safe to restart.
    """

    def test_a_late_mention_is_not_a_prompt(self):
        with _Child("late-word"):
            result = ssh.run_with_password("node", "true", "s3cret",
                                           auth_window=0.3)
        self.assertTrue(result.ok, result.output)
        self.assertIn("DONE-ANYWAY", result.output)

    def test_the_window_is_generous_by_default(self):
        # ssh authenticates within seconds of connecting; the default must not
        # be so tight that a slow node's real prompt falls outside it.
        import inspect
        default = inspect.signature(ssh.run_with_password).parameters
        self.assertGreaterEqual(default["auth_window"].default, 30)


class TestCommandOutputWithAPasswordKey(unittest.TestCase):
    """A command whose OWN output contains "password:" must not look refused.

    Found in the field 2026-07-30: phase 50's `cat profile.yml` reported "could
    not read profile.yml on the bootstrap". profile.yml has an `admin_password:`
    key; that line, arriving immediately -- well inside the auth window -- was
    read as a second prompt and the read killed as refused. The window alone
    could not save it because the output came WITHIN the window; the command's
    first-line sentinel does, because it proves the command is already running.

    This is the read path phase 50's drift check AND `_apply_profile` (the
    rollout the whole B1 feature turns on) both take, so the same defect would
    have silently blocked the patch, not just the status line.
    """

    # The command's OWN output: a profile.yml-shaped blob carrying a password:
    # key. The child runs the real production wrap, so the sentinel that saves
    # this is the production one -- delete the wrap and the test goes red.
    OUTPUT_WITH_A_PASSWORD_KEY = (
        "printf 'admin_password: hunter2\\nsyslog_cert_passphrase:\\n'")

    def test_a_password_key_in_the_output_is_not_a_prompt(self):
        with _Child("exec-real") as child:
            # DEFAULT auth_window (generous): the "password:" is well inside it,
            # so only the sentinel -- not the window -- can save this read.
            result = ssh.run_with_password(
                "node", self.OUTPUT_WITH_A_PASSWORD_KEY, "s3cret")
        self.assertTrue(result.ok, result.output)
        self.assertIn("admin_password: hunter2", result.output)
        self.assertIn("syslog_cert_passphrase:", result.output)
        # Answered once, not terminated as refused and not a second attempt.
        self.assertEqual(child.answers(), ["s3cret"])

    def test_the_sentinel_itself_is_not_shown_to_the_caller(self):
        with _Child("exec-real"):
            result = ssh.run_with_password("node", "printf 'ok\\n'", "s3cret")
        self.assertNotIn(ssh._AUTH_SENTINEL, result.output)
        self.assertEqual(result.output, "ok")   # command output, verbatim



class TestSentinelDetectionAcrossReads(unittest.TestCase):
    """The command-start sentinel must be found however the pty fragments it.

    A pty/network can split the 20-byte sentinel over several reads. If the
    carry-over between reads does not accumulate, a sentinel spread over three
    or more reads is never seen, `authed` never flips, and the next "password:"
    in the command's output is misread as a refusal -- the exact bug this fix
    cures, re-introduced (found in review). Tested as a pure function so it is
    deterministic: no timing, no flake.
    """

    def setUp(self):
        self.s = ssh._AUTH_SENTINEL.encode()

    def feed_all(self, chunks):
        tail, seen = b"", False
        for c in chunks:
            got, tail = ssh._sentinel_seen(tail, c, self.s)
            seen = seen or got
        return seen

    def test_in_a_single_read(self):
        self.assertTrue(self.feed_all([b"noise " + self.s + b" more"]))

    def test_split_one_byte_per_read(self):
        # The strongest fragmentation: every byte its own read. Only an
        # accumulating carry-over finds it; `hay = data` alone never would.
        self.assertTrue(self.feed_all([bytes([b]) for b in self.s]))

    def test_split_with_leading_and_trailing_output(self):
        stream = b"log\n" + self.s + b"\nadmin_password: x\n"
        self.assertTrue(self.feed_all([bytes([b]) for b in stream]))

    def test_absent_sentinel_is_not_seen_and_the_tail_stays_bounded(self):
        tail, seen = b"", False
        for c in [b"admin_password: hunter2\n" * 50]:
            got, tail = ssh._sentinel_seen(tail, c, self.s)
            seen = seen or got
        self.assertFalse(seen)
        # The carry-over must not grow without bound -- len-1 is all it needs.
        self.assertLessEqual(len(tail), len(self.s) - 1)

    def test_a_near_miss_does_not_trip_it(self):
        # One byte short of the sentinel must NOT count as seen.
        self.assertFalse(self.feed_all([self.s[:-1]]))


class TestTheDeadline(unittest.TestCase):
    """run_with_key has had run_timeout all along; this path had nothing."""

    def test_a_stalled_command_gives_up(self):
        start = time.monotonic()
        with _Child("stall"):
            result = ssh.run_with_password("node", "true", "s3cret",
                                           idle_timeout=1)
        took = time.monotonic() - start
        self.assertLess(took, 5, "the deadline did not fire")
        self.assertEqual(result.rc, 124)
        self.assertIn("stuck", result.output)

    def test_it_is_an_idle_timeout_not_a_total_one(self):
        # Phase 40 unzips a 13.5 GB bundle and loads images over THIS path --
        # it has no key yet -- and both take longer than any sane total cap,
        # on a phase that is explicitly not safe to restart. They do talk while
        # they work, so the question is how long it has been SILENT.
        import inspect
        parameters = inspect.signature(ssh.run_with_password).parameters
        self.assertIn("idle_timeout", parameters)
        self.assertGreaterEqual(parameters["idle_timeout"].default, 600)

    def test_a_talkative_command_is_not_cut_off(self):
        # Runs longer than the timeout, but never falls silent for that long.
        with _Child("chatty"):
            result = ssh.run_with_password("node", "true", "s3cret",
                                           idle_timeout=2)
        self.assertTrue(result.ok, result.output)
        self.assertIn("STILL-GOING", result.output)
        # It ran ~3 s with a 2 s cap: only an IDLE cap lets that through.


class TestNoChildIsLeftBehind(unittest.TestCase):
    """Giving up on the wait must not leave the ssh running -- it would sit
    on the node holding a half-finished authentication."""

    def assert_gone(self, pid: int) -> None:
        for _ in range(40):                    # up to 2 s for the reap
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(0.05)
        self.fail(f"the ssh child {pid} was left running")

    def test_the_child_is_gone_after_a_refusal(self):
        with _Child("ask-again") as child:
            ssh.run_with_password("node", "true", "wrong")
            self.assert_gone(child.pid())

    def test_the_child_is_gone_after_a_timeout(self):
        with _Child("stall") as child:
            ssh.run_with_password("node", "true", "s3cret", idle_timeout=1)
            self.assert_gone(child.pid())


if __name__ == "__main__":
    unittest.main()
