"""The NFS target is checked where it will actually be mounted.

docs/08 B8: the check ran on the bootstrap and nowhere else. But the bootstrap
never mounts this share -- `wso cp deploy` puts the NFS volume into the Nomad
job definitions, and those run on the PLATFORM nodes; the bootstrap carries no
service containers at all (docs/08 C1, C4).

So an export limited to specific hosts, or a firewall that lets the bootstrap
through and not the platform nodes, passed the check and broke the deploy
afterwards. That is the same shape as the two failures that cost a day on
2026-07-28: a check that tested a convenient approximation instead of the thing
itself, and therefore could not go red where it mattered.
"""

from __future__ import annotations

import unittest

from ws1access import nfscheck
from ws1access.phases import p50_cluster_init
from ws1access.ssh import SshResult

SETTINGS = {"nfs_host": "10.10.225.60", "nfs_path": "/srv/cpbackup",
            "nfs_version": 3}

# What the check's steps look like, so a fake can answer them.
TOOLS_OK = "yes"
EXPORTS = "Export list for 10.10.225.60:\n/srv/cpbackup 10.10.50.0/24"


class _Ctx:
    """A Context stand-in for _verify_nfs: the two runners and report."""

    bootstrap_ip = "10.10.50.30"
    platform_ips = ["10.10.50.1", "10.10.50.2", "10.10.50.3"]
    user = "configuser"

    def __init__(self, *, fails_on: set[str] | None = None,
                 no_root: set[str] | None = None,
                 no_tools: set[str] | None = None) -> None:
        self.fails_on = fails_on or set()
        self.no_root = no_root or set()
        self.no_tools = no_tools or set()
        self.reports: list[str] = []
        self.asked: list[tuple[str, str]] = []      # (machine, command)

    def _answer(self, machine: str, command: str) -> SshResult:
        self.asked.append((machine, command))
        if command == "id -u":
            # Can we act as root there at all? Passwordless sudo is proven for
            # the bootstrap and only assumed for the nodes.
            return (SshResult(1, "sudo: a password is required")
                    if machine in self.no_root else SshResult(0, "0"))
        if "command -v mount.nfs" in command:
            return SshResult(0, "no" if machine in self.no_tools else TOOLS_OK)
        if "showmount" in command:
            return SshResult(0, EXPORTS)
        # The probe reports its verdict with an AXS_STAGE marker; answering
        # with a bare exit code would test the fake, not the check.
        if machine in self.fails_on:
            return SshResult(10, "mount.nfs: access denied by server\n"
                                 "AXS_STAGE=mount")
        return SshResult(0, "AXS_STAGE=ok")

    def bootstrap_run(self, command: str, **_kw) -> SshResult:
        return self._answer(self.bootstrap_ip, command)

    def node_root_run(self, ip: str, command: str) -> SshResult:
        return self._answer(ip, command)

    def report(self, message: str) -> None:
        self.reports.append(message)

    @property
    def said(self) -> str:
        return "\n".join(self.reports)


def verify(**kw) -> _Ctx:
    ctx = _Ctx(**kw)
    p50_cluster_init._verify_nfs(ctx, SETTINGS)
    return ctx


class TestEveryMachineThatWillMountIsAsked(unittest.TestCase):
    def test_all_three_platform_nodes_are_checked(self):
        ctx = verify()
        asked = {machine for machine, _ in ctx.asked}
        for ip in _Ctx.platform_ips:
            self.assertIn(ip, asked, f"{ip} was never asked")

    def test_the_bootstrap_is_checked_too(self):
        ctx = verify()
        self.assertIn(_Ctx.bootstrap_ip, {m for m, _ in ctx.asked})

    def test_the_bootstrap_goes_first(self):
        # It answers fastest and is where showmount is most likely to work, so
        # a plain typo in the path is caught before three nodes repeat it.
        ctx = verify()
        self.assertEqual(ctx.asked[0][0], _Ctx.bootstrap_ip)

    def test_all_green_says_so_once(self):
        ctx = verify()
        self.assertIn("verified from 4 of 4 machines", ctx.said)
        self.assertNotIn("NOT usable", ctx.said)


class TestTheAsymmetryIsNamed(unittest.TestCase):
    """The case B8 is about: reachable from the bootstrap, not from the nodes.

    Before this, that combination was invisible -- the check passed and the
    deploy failed later, pointing at a service instead of at the export.
    """

    def test_a_host_limited_export_is_caught(self):
        ctx = verify(fails_on=set(_Ctx.platform_ips))
        self.assertIn("NOT usable", ctx.said)

    def test_it_names_which_machines_failed(self):
        ctx = verify(fails_on={"10.10.50.2"})
        self.assertIn("10.10.50.2", ctx.said)

    def test_it_says_the_export_is_limited_to_hosts(self):
        # Some reached it, some did not -- that is not a broken server, it is
        # an ACL, and the operator has to be told which of the two it is.
        ctx = verify(fails_on={"10.10.50.1"})
        self.assertIn("limited to certain hosts", ctx.said)
        self.assertIn("PLATFORM nodes", ctx.said)

    def test_a_server_nobody_can_reach_does_not_claim_an_acl(self):
        ctx = verify(fails_on={_Ctx.bootstrap_ip, *_Ctx.platform_ips})
        self.assertIn("NOT usable", ctx.said)
        self.assertNotIn("limited to certain hosts", ctx.said)

    def test_a_failure_never_stops_the_deploy(self):
        # NFS is optional and the server may not be ready yet; refusing to
        # deploy over it would turn an optional setting into a gate.
        verify(fails_on=set(_Ctx.platform_ips))      # must not raise


class TestCouldNotAskIsNotAFailure(unittest.TestCase):
    """The distinction this repo keeps paying for.

    Passwordless sudo is established for the bootstrap and merely ASSUMED for
    the platform nodes -- collect's own node probe hedges with
    `sudo -n ... || ...` for exactly that reason. When it is not there, the
    old shape reported THREE wrong causes at once: "mount.nfs is not
    installed" (wrong cause), "on the bootstrap" (wrong machine), and then an
    export "limited to certain hosts" (an accusation against the customer's
    NFS server that nothing supported).
    """

    def test_no_root_is_reported_as_not_tested(self):
        ctx = verify(no_root=set(_Ctx.platform_ips))
        self.assertIn("NOT TESTED", ctx.said)

    def test_it_does_not_claim_nfs_utils_is_missing(self):
        ctx = verify(no_root=set(_Ctx.platform_ips))
        self.assertNotIn("nfs-utils", ctx.said)

    def test_it_does_not_accuse_the_export(self):
        ctx = verify(no_root=set(_Ctx.platform_ips))
        self.assertNotIn("limited to certain hosts", ctx.said)

    def test_it_says_nothing_follows_about_the_target(self):
        ctx = verify(no_root=set(_Ctx.platform_ips))
        self.assertIn("Nothing follows", ctx.said)

    def test_the_machine_is_named_correctly(self):
        # The message used to say "on the bootstrap" while running on a node.
        ctx = verify(no_root={"10.10.50.1"})
        self.assertIn("10.10.50.1", ctx.said)

    def test_an_untested_machine_is_not_counted_as_verified(self):
        ctx = verify(no_root={"10.10.50.1"})
        self.assertIn("verified from 3 of 4 machines", ctx.said)


class TestTheCauseIsNotInvented(unittest.TestCase):
    """"Some machines yes, some no" has more than one explanation.

    An access list is only ONE of them, and only when the failures are mounts
    being REFUSED. nfs-utils missing on a single node, or a node whose DNS
    resolves nfs_host differently, produce exactly the same split for entirely
    different reasons -- and naming a cause the evidence does not carry is how
    an operator spends a day on exports while the fault is elsewhere.
    """

    def test_a_missing_tool_is_not_called_an_access_list(self):
        ctx = verify(no_tools={"10.10.50.1"})
        self.assertIn("NOT usable", ctx.said)
        self.assertNotIn("limited to certain hosts", ctx.said)

    def test_a_missing_tool_names_the_machine_it_is_missing_on(self):
        # The message used to say "on the bootstrap" whichever machine it ran
        # on, which sends the operator to install a package in the wrong place.
        ctx = verify(no_tools={"10.10.50.1"})
        self.assertIn("mount.nfs is not installed on platform node 10.10.50.1",
                      ctx.said)
        self.assertNotIn("not installed on the bootstrap", ctx.said)

    def test_refused_mounts_on_some_machines_do_name_it(self):
        ctx = verify(fails_on={"10.10.50.1"})
        self.assertIn("limited to certain hosts", ctx.said)


class TestWhoFailedDecidesWhatItMeans(unittest.TestCase):
    """The bootstrap never mounts this share, so it failing is not a backup
    problem. Saying it is would send the operator after the wrong thing."""

    def test_only_the_bootstrap_failing_does_not_condemn_backups(self):
        ctx = verify(fails_on={_Ctx.bootstrap_ip})
        self.assertIn("backups are not affected", ctx.said)
        self.assertNotIn("disaster recovery would not work", ctx.said)

    def test_a_platform_node_failing_does(self):
        ctx = verify(fails_on={"10.10.50.2"})
        self.assertIn("disaster recovery would not work", ctx.said)


class TestNothingConfigured(unittest.TestCase):
    def test_no_nfs_means_no_checks_at_all(self):
        ctx = _Ctx()
        p50_cluster_init._verify_nfs(ctx, {})
        self.assertEqual(ctx.asked, [])
        self.assertEqual(ctx.reports, [])

    def test_half_configured_is_not_checked(self):
        ctx = _Ctx()
        p50_cluster_init._verify_nfs(ctx, {"nfs_host": "10.10.225.60"})
        self.assertEqual(ctx.asked, [])


class TestTheCheckTakesARunner(unittest.TestCase):
    """nfscheck.check is pointed at a machine by its caller.

    Taking a runner rather than the Context is what let "check it where the
    mount happens" be a change at the call site instead of a second copy of
    the function -- and a second copy is how two checks drift apart.
    """

    def test_it_uses_the_runner_it_is_given(self):
        seen = []

        def runner(command, **_kw):
            seen.append(command)
            if command == "id -u":
                return SshResult(0, "0")
            if "command -v mount.nfs" in command:
                return SshResult(0, TOOLS_OK)
            return SshResult(0, "AXS_STAGE=ok")

        result = nfscheck.check(runner, "10.10.225.60", "/srv/cpbackup", 3)
        self.assertTrue(result.ok, result.detail)

    def test_the_colon_is_still_added_unconditionally(self):
        # Never kinder to the input than wso is: it hands docker
        # device=":<nfs_path>", so a leading colon becomes "::" and the mount
        # asks for an export that does not exist (docs/08 A10).
        seen = []

        def runner(command, **_kw):
            seen.append(command)
            if command == "id -u":
                return SshResult(0, "0")
            if "command -v mount.nfs" in command:
                return SshResult(0, TOOLS_OK)
            return SshResult(0, "AXS_STAGE=ok")

        nfscheck.check(runner, "10.10.225.60", ":/srv/cpbackup", 3)
        mounts = [c for c in seen if "mount" in c and "command -v" not in c]
        self.assertTrue(any("10.10.225.60::/srv/cpbackup" in c for c in mounts),
                        mounts)


if __name__ == "__main__":
    unittest.main()
