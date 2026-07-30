"""What aXs kills, and what it deliberately refuses to narrow.

`pkill` runs as root on the bootstrap. The loose patterns matched two things
that are not hypothetical (docs/08, B4):

  * `wso services deploy` also matches `wso services deploy -s <service>` --
    the hand repair THIS TOOL prints when it gives up on a stuck deploy.
  * `deploy_services.py` also matches `vim /scripts/deploy_services.py`.

The patterns are pgrep/pkill `-f` extended regexes matched against the whole
command line. `re.search` models the REGEX DIALECT faithfully for patterns this
simple -- it does not model the rest of what pgrep does: that it excludes its
own process but not its parents, and that a process has to be visible in the
first place (docs/08 D3 leaves that open for the worker). The `[w]`/`[p]`
bracket is the usual trick that keeps a pattern from matching the shell that
carries it; as a regex it is just the literal character.
"""

from __future__ import annotations

import re
import unittest

from ws1access.context import WSO_BUSY
from ws1access.phases.p70_services import _ALIVE, _KILL, _WORKER, _WRAPPER

# Command lines as aXs launches them. Only OUR_WRAPPER is anchored in the code
# (context.start_detached wraps the command in `setsid bash -lc`); the worker
# forms are the one recorded in docs/08 A1 plus spellings it must not break on.
OUR_WRAPPER = "bash -lc wso services deploy --type full >> services-deploy.log"
OUR_WORKER = "python3 /scripts/deploy_services.py"
OUR_WORKER_ABS = "/usr/bin/python3 /scripts/deploy_services.py"
OUR_WORKER_VERSIONED = "python3.9 /scripts/deploy_services.py"
OUR_WORKER_FLAGGED = "python3 -u /scripts/deploy_services.py"

# The two false targets from docs/08 B4, plus the worker the first one spawns.
HAND_REPAIR = "wso services deploy -s usergroup"
HAND_REPAIR_WORKER = "python3 /scripts/deploy_services.py -s usergroup"
EDITOR = "vim /scripts/deploy_services.py"


def matches(pattern: str, cmdline: str) -> bool:
    return re.search(pattern, cmdline) is not None


class TestWrapperPattern(unittest.TestCase):
    def test_matches_our_own_invocation(self):
        self.assertTrue(matches(_WRAPPER, OUR_WRAPPER))

    def test_does_not_match_the_hand_repair_we_recommend(self):
        # Killing this is the failure B4 names: the tool tells the operator to
        # run it, then shoots it on the next stall.
        self.assertFalse(matches(_WRAPPER, HAND_REPAIR))

    def test_does_not_match_a_different_wso_step(self):
        self.assertFalse(matches(_WRAPPER, "wso cp deploy"))
        self.assertFalse(matches(_WRAPPER, "wso access create-tenant"))


class TestWorkerPattern(unittest.TestCase):
    def test_matches_the_worker(self):
        self.assertTrue(matches(_WORKER, OUR_WORKER))

    def test_matches_an_absolute_interpreter_path(self):
        self.assertTrue(matches(_WORKER, OUR_WORKER_ABS))

    def test_matches_a_versioned_interpreter(self):
        self.assertTrue(matches(_WORKER, OUR_WORKER_VERSIONED))

    def test_matches_an_interpreter_flag(self):
        # A miss is the dangerous direction: _KILL and the check that VERIFIES
        # the kill share this pattern, so a worker we cannot see reads as dead.
        self.assertTrue(matches(_WORKER, OUR_WORKER_FLAGGED))

    def test_does_not_match_an_editor_on_the_same_file(self):
        self.assertFalse(matches(_WORKER, EDITOR))

    def test_does_not_match_a_grep_for_the_file(self):
        self.assertFalse(matches(_WORKER, "grep -n nfs /scripts/deploy_services.py"))

    def test_still_matches_the_hand_repairs_worker(self):
        # NOT a wanted property -- the honest half of B4. If `wso services
        # deploy -s x` spawns this same script, a stall still kills the repair
        # the tool itself recommended. The wrapper half is closed; this is not,
        # and it is recorded here rather than left to be rediscovered.
        self.assertTrue(matches(_WORKER, HAND_REPAIR_WORKER))


class TestAliveAndKillAgree(unittest.TestCase):
    """The two must name the SAME processes.

    If one is narrowed and the other is not, aXs kills something it does not
    consider alive -- or waits on something it will never kill. That mismatch
    is the shape ("repaired in one place, not in the others") this suite exists
    for, and here the two constants sit ten lines apart.
    """

    def test_both_cover_the_wrapper_and_the_worker(self):
        for probe in (_ALIVE, _KILL):
            self.assertIn(_WRAPPER, probe)
            self.assertIn(_WORKER, probe)

    def test_kill_covers_everything_alive_looks_for(self):
        # Extracted from the actual strings, not restated -- a pattern added to
        # _ALIVE alone has to fail this.
        found = set(re.findall(r"pgrep -f '([^']+)'", _ALIVE))
        killed = set(re.findall(r"pkill -f '([^']+)'", _KILL))
        self.assertEqual(found, killed)

    def test_patterns_keep_the_self_match_bracket(self):
        # `[w]so` / `[p]ython` is not decoration. pgrep excludes its own
        # process but NOT the shell carrying the pattern, so a bare `wso
        # services deploy --type full` matches the very `bash -lc` running the
        # probe: _ALIVE would answer "alive" forever, run() would re-attach to
        # nothing, and _stop_stalled would see its own probe survive SIGKILL
        # and report the bootstrap as wedged in the kernel.
        for pattern in (_WRAPPER, _WORKER):
            self.assertRegex(pattern, r"^\[\w\]",
                             f"{pattern!r} lost its self-match bracket")
        carrier = f"bash -lc pgrep -f '{_WRAPPER}' >/dev/null"
        self.assertFalse(matches(_WRAPPER, carrier))

    def test_alive_is_a_disjunction(self):
        # Either process alive means the step is alive. With `&&` the
        # worker-only state -- the state A1 is entirely about, after the
        # wrapper has exited -- would read as dead and start a second deploy.
        self.assertIn("||", _ALIVE)
        self.assertNotIn("&&", _ALIVE)

    def test_kill_targets_are_independent(self):
        # `;` not `&&`: pkill exits non-zero when it matches nothing, so
        # chaining with && would skip the worker whenever the wrapper had
        # already exited -- again the worker-only state.
        self.assertNotIn("&&", _KILL)
        self.assertTrue(_KILL.rstrip().endswith("true"),
                        "a kill that matched nothing must not fail the step")

    def test_kill_survives_the_sigkill_escalation_rewrite(self):
        # _stop_stalled escalates by rewriting "pkill -f" to "pkill -9 -f".
        # A kill command that stopped spelling it that way would silently lose
        # its escalation and the stall would end in "could not stop it".
        self.assertIn("pkill -f", _KILL)
        escalated = _KILL.replace("pkill -f", "pkill -9 -f")
        self.assertEqual(escalated.count("pkill -9 -f"), 2)


class TestBusyGuardStaysBroad(unittest.TestCase):
    """The deliberate asymmetry, pinned so it is not 'tidied up' later.

    What we KILL is narrowed to what we started. What GATES a start is not:
    there a false positive costs a re-run, while a miss costs two wso
    operations writing to one cluster. The hand repair MUST trip this guard --
    that is the whole point of refusing.
    """

    def guard_patterns(self) -> list[str]:
        return re.findall(r"pgrep -f '([^']+)'", WSO_BUSY)

    def test_the_hand_repair_still_blocks_a_start(self):
        # The exact command we now refuse to KILL must still be one we refuse
        # to start alongside. Both halves of B4 in one assertion.
        self.assertTrue(any(matches(p, HAND_REPAIR) for p in self.guard_patterns()),
                        self.guard_patterns())

    def test_an_editor_also_trips_the_guard_which_is_the_accepted_cost(self):
        # Recorded, not celebrated: an open `vim /scripts/deploy_services.py`
        # makes the guard refuse a start. Broad is still right here -- the
        # refusal names the process and a way out, while a missed collision is
        # two wso operations writing to one cluster. The narrowing went into
        # what we KILL, where the cost runs the other way.
        self.assertTrue(any(matches(p, EDITOR) for p in self.guard_patterns()))

    def test_guard_lists_every_long_step_plus_the_worker(self):
        for pattern in ("[w]so cp deploy", "[w]so services deploy",
                        "[w]so access create-tenant", "[d]eploy_services.py"):
            self.assertIn(pattern, WSO_BUSY)

    def test_guard_is_not_narrowed_to_our_own_invocation(self):
        # If someone copies the --type full narrowing into the guard, a manual
        # `wso services deploy -s x` stops blocking and the collision is back.
        self.assertNotIn("--type full", WSO_BUSY)


if __name__ == "__main__":
    unittest.main()
