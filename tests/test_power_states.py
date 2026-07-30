"""`vcenter.power_states` scopes to the datacenter AND the folder.

Phase 10's done-probe asks this "are the nodes already built?". It matches by
NAME, so the scope is what keeps a same-named VM somewhere else from answering
yes for a node that was never created here. The datacenter scope was added for
that; the folder scope closes the same hole one level down -- a leftover VM of
the same name in another folder of the SAME datacenter, which is exactly the
kind of leftover the datacenter scope exists to ignore, just nearer.

Nothing here talks to vCenter. `_call` is the single network boundary -- the
one method that opens a socket -- so faking only that runs the real session
handling, the real URL construction, and the real filtering, and asserts on the
query the code actually built.
"""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from ws1access.vcenter import VCenter, VCenterError


class FakeVC(VCenter):
    """A VCenter whose only faked method is the socket call.

    `responses` maps a path prefix (before the `?`) to the parsed body the real
    `_call` would have returned. The full requested path -- query string and all
    -- is recorded, because the query string is the thing under test.
    """

    def __init__(self, responses):
        super().__init__(host="vc.test", user="u", password="p")
        self._responses = responses
        self.requests: list[str] = []

    def _call(self, method, path, headers=None, body=None):
        self.requests.append(path)
        base = path.split("?", 1)[0]
        if base == "/api/session":
            return "SID-123", {}
        body_out = self._responses.get(base)
        # The datacenter lookup filters by `?names=`; reproduce that so an
        # unknown datacenter really comes back empty instead of matching DC1.
        if base == "/api/vcenter/datacenter" and isinstance(body_out, list):
            q = parse_qs(urlsplit(path).query)
            wanted = q.get("names")
            if wanted is not None:
                body_out = [d for d in body_out if d["name"] in wanted]
        return body_out, {}

    def vm_query(self):
        """The query params of the single /api/vcenter/vm request made."""
        vm = [r for r in self.requests if r.split("?", 1)[0] == "/api/vcenter/vm"]
        assert len(vm) == 1, f"expected one vm query, got {vm}"
        return parse_qs(urlsplit(vm[0]).query)


DCS = [{"name": "DC1", "datacenter": "datacenter-1"}]
VMS = [{"name": "wsa-acc-01", "power_state": "POWERED_ON"},
       {"name": "wsa-acc-02", "power_state": "POWERED_OFF"}]
FOLDERS = [{"name": "aXs", "folder": "group-v42"}]


def vc(**over):
    r = {"/api/vcenter/datacenter": DCS,
         "/api/vcenter/vm": VMS,
         "/api/vcenter/folder": FOLDERS}
    r.update(over)
    return FakeVC(r)


class TestScoping(unittest.TestCase):
    def test_without_a_datacenter_the_search_is_vcenter_wide(self):
        client = vc()
        client.power_states(["wsa-acc-01"])
        self.assertNotIn("datacenters", client.vm_query())
        self.assertNotIn("folders", client.vm_query())

    def test_a_datacenter_scopes_the_query(self):
        client = vc()
        client.power_states(["wsa-acc-01"], "DC1")
        q = client.vm_query()
        self.assertEqual(q["datacenters"], ["datacenter-1"])
        self.assertNotIn("folders", q)

    def test_a_folder_adds_its_moid_to_the_query(self):
        client = vc()
        client.power_states(["wsa-acc-01"], "DC1", folder="aXs")
        q = client.vm_query()
        self.assertEqual(q["datacenters"], ["datacenter-1"])
        self.assertEqual(q["folders"], ["group-v42"])

    def test_a_folder_without_a_datacenter_is_ignored(self):
        # A folder MOID is only resolvable within a datacenter, so a folder with
        # no datacenter cannot scope anything -- and must not silently widen.
        client = vc()
        client.power_states(["wsa-acc-01"], folder="aXs")
        self.assertNotIn("folders", client.vm_query())

    def test_an_unknown_datacenter_raises_rather_than_widening(self):
        client = vc()
        with self.assertRaises(VCenterError):
            client.power_states(["wsa-acc-01"], "Nonexistent")


class TestTheFolderThatDoesNotExistYet(unittest.TestCase):
    """Phase 10's run() creates the folder; is_done runs before that. A probe
    against a not-yet-created folder must say "nothing there", not fall back to a
    wider search that would find the leftover this scoping exists to ignore."""

    def test_a_missing_folder_yields_no_matches(self):
        client = vc(**{"/api/vcenter/folder": []})     # folder not created yet
        self.assertEqual(
            client.power_states(["wsa-acc-01"], "DC1", folder="aXs"), {})

    def test_and_it_did_not_fall_back_to_an_unscoped_query(self):
        client = vc(**{"/api/vcenter/folder": []})
        client.power_states(["wsa-acc-01"], "DC1", folder="aXs")
        # No /api/vcenter/vm request was made at all -- the answer was decided
        # from the empty folder list, not from a wider VM search.
        self.assertFalse(any(r.split("?", 1)[0] == "/api/vcenter/vm"
                             for r in client.requests))


class TestPhase10PassesTheConfiguredFolder(unittest.TestCase):
    """The helper being scoped proves nothing about the phase calling it scoped.

    A mutation dropping `folder=folder` from p10's is_done left every test above
    green -- the exact "repaired in one place, not at the call site" shape this
    suite exists to catch. This drives is_done and records what it asked
    power_states for.
    """

    class _Recorder:
        def __init__(self):
            self.calls = []

        def power_states(self, names, datacenter=None, folder=None):
            self.calls.append({"names": names, "datacenter": datacenter,
                               "folder": folder})
            return {n: "POWERED_ON" for n in names}

    def probe_with(self, vcenter):
        from types import SimpleNamespace

        from ws1access.phases import p10_vms

        rec = self._Recorder()
        ctx = SimpleNamespace(
            nodes=[{"hostname": "wsa-acc-01"}, {"hostname": "wsa-acc-02"}],
            vcenter=vcenter)
        real = p10_vms._vc
        p10_vms._vc = lambda _ctx: rec
        try:
            probe = p10_vms.is_done(ctx)
        finally:
            p10_vms._vc = real
        return probe, rec.calls[-1]

    def test_a_configured_folder_reaches_power_states(self):
        _probe, call = self.probe_with(
            {"host": "vc", "user": "u", "datacenter": "DC1", "folder": "aXs"})
        self.assertEqual(call["folder"], "aXs")
        self.assertEqual(call["datacenter"], "DC1")

    def test_no_folder_configured_passes_none_not_empty_string(self):
        # An empty string is not a folder name; passing it would resolve to no
        # MOID and wrongly report every node missing.
        _probe, call = self.probe_with(
            {"host": "vc", "user": "u", "datacenter": "DC1", "folder": ""})
        self.assertIsNone(call["folder"])

    def test_folder_key_absent_entirely_is_also_none(self):
        _probe, call = self.probe_with(
            {"host": "vc", "user": "u", "datacenter": "DC1"})
        self.assertIsNone(call["folder"])


class TestPhase10RunScopesTheSameWay(unittest.TestCase):
    """is_done being folder-scoped is worthless if run() is not.

    If run() asks datacenter-wide, the leftover VM is_done ignored is the one
    run() sees -- it skips the node as "already deployed", the node is never
    built, and is_done never goes done. This drives the real run() with every
    node reported up (so the deploy loop skips and the method returns) and
    records what run() asked power_states for.
    """

    class _Recorder:
        def __init__(self, states):
            self._states = states
            self.calls = []

        def power_states(self, names, datacenter=None, folder=None):
            self.calls.append({"datacenter": datacenter, "folder": folder})
            return {n: self._states for n in names}

    def run_with(self, vcenter):
        from types import SimpleNamespace

        from ws1access.phases import p10_vms

        rec = self._Recorder("POWERED_ON")
        ctx = SimpleNamespace(
            nodes=[{"hostname": "wsa-acc-01", "role": "access", "ip": "10.0.0.5"}],
            vcenter=vcenter,
            network={"netmask": "255.255.255.0", "gateway": "10.0.0.1"},
            configuser_password="pw", ova_path="x.ova", size="small",
            reports=[], report=lambda *_a, **_k: None,
            report_log=lambda *_a, **_k: None)
        saved = (p10_vms._vc, p10_vms._ensure_folder, p10_vms.ovftool.load_profile)
        p10_vms._vc = lambda _c: rec
        p10_vms._ensure_folder = lambda _c: None
        p10_vms.ovftool.load_profile = lambda: {}
        try:
            p10_vms.run(ctx)
        finally:
            (p10_vms._vc, p10_vms._ensure_folder,
             p10_vms.ovftool.load_profile) = saved
        return rec.calls[-1]

    def test_run_passes_the_configured_folder(self):
        call = self.run_with({"host": "vc", "user": "u", "datacenter": "DC1",
                              "compute": "c", "datastore": "d", "network": "n",
                              "folder": "aXs"})
        self.assertEqual(call["folder"], "aXs")

    def test_run_passes_none_when_no_folder_configured(self):
        call = self.run_with({"host": "vc", "user": "u", "datacenter": "DC1",
                              "compute": "c", "datastore": "d", "network": "n",
                              "folder": ""})
        self.assertIsNone(call["folder"])


class TestAmbiguousFolderNameIsRefused(unittest.TestCase):
    """Two VM folders of the same name in one datacenter: `.get(name)` would have
    picked one arbitrarily. The wrong one silently restores the bug this scoping
    fixes, or reports every node missing. "Could not tell which" is not a guess
    to make."""

    def test_two_folders_of_one_name_raise(self):
        client = vc(**{"/api/vcenter/folder": [
            {"name": "aXs", "folder": "group-v1"},
            {"name": "aXs", "folder": "group-v2"}]})
        with self.assertRaises(VCenterError) as caught:
            client.power_states(["wsa-acc-01"], "DC1", folder="aXs")
        self.assertIn("aXs", str(caught.exception))
        self.assertIn("cannot tell", str(caught.exception))

    def test_a_different_duplicate_name_does_not_trip_it(self):
        # Two folders named "other" must not make a query for "aXs" ambiguous.
        client = vc(**{"/api/vcenter/folder": [
            {"name": "other", "folder": "group-v1"},
            {"name": "other", "folder": "group-v2"},
            {"name": "aXs", "folder": "group-v9"}]})
        q = client.power_states(["wsa-acc-01"], "DC1", folder="aXs")
        self.assertEqual(q, {"wsa-acc-01": "POWERED_ON"})


class TestFiltering(unittest.TestCase):
    def test_only_requested_names_come_back(self):
        client = vc()
        states = client.power_states(["wsa-acc-01"], "DC1", folder="aXs")
        self.assertEqual(states, {"wsa-acc-01": "POWERED_ON"})

    def test_power_state_is_reported_per_name(self):
        client = vc()
        states = client.power_states(["wsa-acc-01", "wsa-acc-02"], "DC1",
                                     folder="aXs")
        self.assertEqual(states, {"wsa-acc-01": "POWERED_ON",
                                  "wsa-acc-02": "POWERED_OFF"})

    def test_a_name_that_is_not_present_is_simply_absent(self):
        client = vc()
        states = client.power_states(["wsa-acc-01", "wsa-acc-99"], "DC1",
                                     folder="aXs")
        self.assertNotIn("wsa-acc-99", states)


if __name__ == "__main__":
    unittest.main()
