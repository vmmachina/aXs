"""Stand-ins for the two things these tests must not touch: a real bootstrap
and a real cluster.

Nothing here mocks a library. `FakeCtx` answers `bootstrap_run` from a lookup
table, which is the only Context method the pure functions under test call --
so the parsing and decision logic is exercised for real and only the SSH round
trip is replaced.
"""

from __future__ import annotations

import json

from ws1access import pending as ws1_pending
from ws1access.health import ACCESS_CORE
from ws1access.ssh import SshResult


class FakeCtx:
    """A Context stand-in for functions that only need `bootstrap_run`.

    `answers` maps a substring of the command to (rc, output). The first match
    wins, so a test can pin `check-service-readiness` and `healthcheck`
    separately. An unmatched command raises rather than silently returning
    empty output -- a test that stops matching after a refactor should fail
    loudly, not quietly assert the unparseable branch.
    """

    def __init__(self, answers: dict[str, tuple[int, str]],
                 cluster_dir: str = "/root/lab",
                 pending: str | None = None) -> None:
        self.cluster_dir = cluster_dir
        self.calls: list[str] = []
        self.reports: list[str] = []
        self.written: dict[str, str] = {}
        # The pending-rollout marker is asked about by every phase-60 probe and
        # by phase 50 when the files agree. `pending=None` means "no marker",
        # which is the ordinary state -- so a test about something else does not
        # have to know this mechanism exists.
        #
        # Inserted FIRST, because a test that answers a generic `cat` needle
        # would otherwise catch this query too and hand back a profile.yml as
        # the marker's contents. A test that names the marker itself still wins:
        # its needle is already in the dict and is not overwritten.
        #
        # Keyed on the READ query's own marker word rather than on the file
        # path: `pending.clear` names the same file, so keying on the path
        # answered the REMOVAL with "AXS_PENDING_NONE" too, and a test about
        # clearing the marker read that as a removal that had failed.
        self.answers: dict[str, tuple[int, str]] = {}
        if not any(ws1_pending.FILENAME in n or "AXS_PENDING" in n
                   for n in answers):
            # rc 0 in BOTH cases: the real command is `cat ... && echo END ||
            # echo NONE`, which exits 0 whenever the shell ran at all. That is
            # the entire point of the marker idiom -- a non-zero rc means "could
            # not ask", a state no healthy bootstrap ever produces here.
            self.answers["AXS_PENDING_NONE"] = (
                (0, "AXS_PENDING_NONE") if pending is None
                else (0, f"{pending}\nAXS_PENDING_END"))
        self.answers.update(answers)

    def bootstrap_run(self, command: str, **_kw) -> SshResult:
        self.calls.append(command)
        for needle, (rc, out) in self.answers.items():
            if needle in command:
                return SshResult(rc, out)
        raise AssertionError(f"FakeCtx has no answer for: {command!r}")

    def report(self, message: str) -> None:
        self.reports.append(message)


def readiness_json(**overrides: str) -> str:
    """A check-service-readiness answer: every Access core service READY,
    minus/plus whatever the test overrides.

    Pass `service=None` to drop it entirely (never deployed) or
    `service="NOT_READY"` to have it listed but not ready -- the two states
    whose difference phase 70 depends on.
    """
    data = {name: "READY" for name in sorted(ACCESS_CORE)}
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return json.dumps(data)


def _member(name: str, *, healthy: bool = True, sealed: bool = False) -> dict:
    m: dict = {"name": name, "healthy": healthy}
    if sealed:
        m["additional"] = {"sealed": True}
    return m


def healthcheck_json(*, vault_healthy: bool = True, vault_sealed: bool = False,
                     consul_reachable: bool = True,
                     service_issues: list[str] | None = None,
                     prefix: str = "Checking cluster ... done\n") -> str:
    """A `wso healthcheck -f json` answer, including the text prefix wso puts
    in front of the JSON (the reason `_json_tail` exists)."""
    data = {
        "vault": {"reachable": True,
                  "servers": [_member("platform1", healthy=vault_healthy,
                                      sealed=vault_sealed)]},
        "consul": ({"reachable": True, "servers": [_member("platform1")]}
                   if consul_reachable
                   else {"reachable": False, "error": "connection refused"}),
        "nomad": {"reachable": True,
                  "servers": [_member("platform1")],
                  "clients": [_member("access1")]},
        "services": {"Result": service_issues or []},
    }
    return prefix + json.dumps(data)
