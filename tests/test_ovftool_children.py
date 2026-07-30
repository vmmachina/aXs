"""No ovftool outlives the tool that started it.

docs/08 B9: the deploy engine runs in a DAEMON thread, ovftool is an ordinary
child. The TUI's exit button ends Python and the daemon thread with it -- and
ovftool keeps uploading, invisibly. The next run then finds a half-deployed VM
and refuses to continue while the orphan is still writing into it.

These tests start real (harmless) child processes, because the property under
test is about actual process lifetime. `sleep` is on every machine this runs
on, and nothing here touches vCenter.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import unittest

from ws1access.phases import p10_vms


def spawn(seconds: str = "30") -> subprocess.Popen:
    """A stand-in for a long ovftool upload."""
    return subprocess.Popen(["sleep", seconds])


def terminate_quietly() -> str:
    """_terminate_children, with its stderr line captured.

    The line is deliberate -- the operator has to learn that an upload was
    aborted. It is just not something a test run should print three times.
    """
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        p10_vms._terminate_children()
    return captured.getvalue()


def reap(proc: subprocess.Popen) -> None:
    for stream in (proc.stdout, proc.stderr, proc.stdin):
        if stream is not None:
            stream.close()
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)


class _Registered:
    """Register a real child the way _run_ovftool does, and clean up hard."""

    def __init__(self, seconds: str = "30") -> None:
        self.seconds = seconds

    def __enter__(self) -> subprocess.Popen:
        self.proc = spawn(self.seconds)
        with p10_vms._CHILDREN_LOCK:
            p10_vms._CHILDREN.add(self.proc)
        return self.proc

    def __exit__(self, *exc):
        with p10_vms._CHILDREN_LOCK:
            p10_vms._CHILDREN.discard(self.proc)
        reap(self.proc)


class TestTerminateOnExit(unittest.TestCase):
    def test_a_registered_child_is_stopped(self):
        with _Registered() as proc:
            self.assertIsNone(proc.poll(), "the fixture did not start")
            terminate_quietly()
            self.assertIsNotNone(proc.poll(), "the child survived the exit handler")

    def test_the_operator_is_told_an_upload_was_aborted(self):
        # The deploy log's last line is "uploading NN%". Without this, the
        # abort is only ever learned from the next run's error.
        with _Registered():
            said = terminate_quietly()
        self.assertIn("stopping", said)
        self.assertIn("incomplete", said)

    def test_nothing_is_said_when_there_was_nothing_to_stop(self):
        self.assertEqual(terminate_quietly(), "")

    def test_an_already_finished_child_is_no_problem(self):
        proc = spawn("0")
        proc.wait(timeout=5)
        with p10_vms._CHILDREN_LOCK:
            p10_vms._CHILDREN.add(proc)
        try:
            terminate_quietly()                # must not raise
        finally:
            with p10_vms._CHILDREN_LOCK:
                p10_vms._CHILDREN.discard(proc)
            reap(proc)

    def test_several_children_are_all_stopped(self):
        # One VM per node -- six of them on a small cluster.
        with _Registered() as first, _Registered() as second:
            terminate_quietly()
            self.assertIsNotNone(first.poll())
            self.assertIsNotNone(second.poll())

    def test_sigterm_is_tried_before_sigkill(self):
        # Not politeness: ovftool holds a transfer lease on vCenter, and a
        # clean exit drops it so vCenter removes the half-written VM itself.
        # Going straight to SIGKILL leaves that lease to time out server-side.
        script = ("import signal, sys, time\n"
                  "signal.signal(signal.SIGTERM, lambda *a: (print('TERM', flush=True), sys.exit(0)))\n"
                  "print('ready', flush=True)\n"
                  "time.sleep(60)\n")
        proc = subprocess.Popen([sys.executable, "-c", script],
                                stdout=subprocess.PIPE, text=True)
        proc.stdout.readline()
        with p10_vms._CHILDREN_LOCK:
            p10_vms._CHILDREN.add(proc)
        try:
            terminate_quietly()
            self.assertEqual(proc.stdout.readline().strip(), "TERM",
                             "the child was killed without being asked first")
        finally:
            with p10_vms._CHILDREN_LOCK:
                p10_vms._CHILDREN.discard(proc)
            reap(proc)

    def test_a_child_that_ignores_sigterm_is_killed(self):
        # SIGTERM then SIGKILL, in the shape of the remote stall kill: firing a
        # signal and walking away is not the same as the process being gone.
        # Shorten the production waits: this test exists to prove the
        # escalation happens, not to sit out ten real seconds every run.
        real_term, real_kill = p10_vms._TERM_WAIT, p10_vms._KILL_WAIT
        p10_vms._TERM_WAIT, p10_vms._KILL_WAIT = 0.4, 2
        self.addCleanup(setattr, p10_vms, "_TERM_WAIT", real_term)
        self.addCleanup(setattr, p10_vms, "_KILL_WAIT", real_kill)
        script = ("import signal, time\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "print('ready', flush=True)\n"
                  "time.sleep(120)\n")
        proc = subprocess.Popen([sys.executable, "-c", script],
                                stdout=subprocess.PIPE, text=True)
        proc.stdout.readline()                 # wait until the handler is armed
        with p10_vms._CHILDREN_LOCK:
            p10_vms._CHILDREN.add(proc)
        try:
            terminate_quietly()
            self.assertIsNotNone(proc.poll(),
                                 "a child ignoring SIGTERM was not killed")
        finally:
            with p10_vms._CHILDREN_LOCK:
                p10_vms._CHILDREN.discard(proc)
            reap(proc)


class TestRegistration(unittest.TestCase):
    def test_run_ovftool_registers_and_deregisters(self):
        seen = []

        def watching_pct(_pct):
            with p10_vms._CHILDREN_LOCK:
                seen.append(len(p10_vms._CHILDREN))

        before = len(p10_vms._CHILDREN)
        rc, out = p10_vms._run_ovftool(
            ["sh", "-c", "echo 'Disk progress: 42%'; echo done"], watching_pct)
        self.assertEqual(rc, 0, out)
        self.assertTrue(seen and seen[0] > before,
                        "the child was not registered while it ran")
        self.assertEqual(len(p10_vms._CHILDREN), before,
                         "the child was not deregistered afterwards")

    def test_it_deregisters_even_when_the_reader_raises(self):
        # Leaving a finished process in the set makes the exit handler poll a
        # stale entry for the rest of the run.
        before = len(p10_vms._CHILDREN)

        def exploding_pct(_pct):
            raise RuntimeError("the UI went away")

        with self.assertRaises(RuntimeError):
            p10_vms._run_ovftool(["sh", "-c", "echo '7%'"], exploding_pct)
        self.assertEqual(len(p10_vms._CHILDREN), before)

    def test_a_still_running_child_is_stopped_when_the_reader_raises(self):
        # The defect this class nearly enshrined: deregistering a child that is
        # STILL UPLOADING and walking away is the orphan B9 is about. On the
        # plain path _run_ovftool runs in the main thread, so a Ctrl-C lands
        # exactly here.
        created = []
        real_popen = p10_vms.subprocess.Popen

        def recording_popen(*a, **kw):
            proc = real_popen(*a, **kw)
            created.append(proc)
            return proc

        def exploding_pct(_pct):
            raise KeyboardInterrupt()

        # The reader takes 256 characters at a time, so the child has to emit
        # at least that much before it blocks -- otherwise the callback (and
        # with it this test) waits for EOF, i.e. for the whole sleep.
        script = ("import sys, time\n"
                  "sys.stdout.write('5%' + 'x' * 300)\n"
                  "sys.stdout.flush()\n"
                  "time.sleep(30)\n")
        p10_vms.subprocess.Popen = recording_popen
        try:
            with self.assertRaises(KeyboardInterrupt):
                p10_vms._run_ovftool([sys.executable, "-c", script],
                                     exploding_pct)
        finally:
            p10_vms.subprocess.Popen = real_popen
        proc = created[0]
        try:
            self.assertIsNotNone(proc.poll(),
                                 "the upload was abandoned, still running")
        finally:
            reap(proc)

    def test_the_output_pipe_is_closed(self):
        # It never was: one leaked descriptor per VM, six per small cluster.
        created = []
        real_popen = p10_vms.subprocess.Popen

        def recording_popen(*a, **kw):
            proc = real_popen(*a, **kw)
            created.append(proc)
            return proc

        p10_vms.subprocess.Popen = recording_popen
        try:
            p10_vms._run_ovftool(["sh", "-c", "echo '3%'"], lambda _p: None)
        finally:
            p10_vms.subprocess.Popen = real_popen
        self.assertTrue(created[0].stdout.closed,
                        "the ovftool output pipe was left open")

    def test_the_handler_is_registered_with_atexit(self):
        # Without this the whole mechanism never fires. atexit offers no public
        # way to inspect its callbacks, so this reads the module -- structural,
        # and the only lever available.
        import inspect
        self.assertIn("atexit.register(_terminate_children)",
                      inspect.getsource(p10_vms))


if __name__ == "__main__":
    unittest.main()
