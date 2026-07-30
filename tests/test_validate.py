"""validate_config() -- catching bad input in the dialog, not 40 minutes in.

The leading colon in `nfs_path` is the expensive one. Omnissa's own example file
writes `:/controlplanenfs/us04pA`; wso prepends a colon of its own, the doubled
`::` asks for an export that does not exist, and phase 70 died in four seconds
with nothing usable in the log (2026-07-28). A help text alone did not stop it.
"""

from __future__ import annotations

import copy
import unittest

from ws1access.validate import _check_deployment_settings, validate_config

BASE = {
    "cluster": {"name": "lab", "size": "small", "auth": "key"},
    "network": {"gateway": "192.168.10.1", "netmask": "255.255.255.0"},
    "nodes": {
        "bootstrap": {"hostname": "bootstrap", "ip": "192.168.10.10"},
        "platform": [
            {"hostname": "platform1", "ip": "192.168.10.21"},
            {"hostname": "platform2", "ip": "192.168.10.22"},
            {"hostname": "platform3", "ip": "192.168.10.23"},
        ],
        "access": [
            {"hostname": "access1", "ip": "192.168.10.31"},
            {"hostname": "access2", "ip": "192.168.10.32"},
        ],
    },
}


def cfg(**sections) -> dict:
    out = copy.deepcopy(BASE)
    out.update(copy.deepcopy(sections))
    return out


class TestBaseline(unittest.TestCase):
    def test_the_fixture_itself_is_valid(self):
        # Every test below asserts that ONE thing is rejected. That only means
        # something if the surrounding config is otherwise accepted.
        self.assertEqual(validate_config(cfg()), [])


class TestNfsPathColon(unittest.TestCase):
    def test_leading_colon_is_rejected(self):
        errs = _check_deployment_settings({
            "nfs_host": "192.168.10.9", "nfs_path": ":/controlplanenfs/us04pA"})
        self.assertTrue(any("must not start with a colon" in e for e in errs), errs)

    def test_the_message_shows_the_corrected_value(self):
        # Rejecting without saying what to write instead just moves the guessing.
        errs = _check_deployment_settings({
            "nfs_host": "192.168.10.9", "nfs_path": ":/controlplanenfs/us04pA"})
        joined = " ".join(errs)
        self.assertIn("'/controlplanenfs/us04pA'", joined)

    def test_plain_path_is_accepted(self):
        errs = _check_deployment_settings({
            "nfs_host": "192.168.10.9", "nfs_path": "/controlplanenfs/us04pA"})
        self.assertEqual(errs, [])

    def test_reachable_through_the_public_entry_point(self):
        # The dialog calls the per-field functions, a file load calls
        # validate_config. The colon has to be caught on BOTH paths -- the
        # config that broke the 28th came from a file, not from typing.
        errs = validate_config(cfg(deployment_settings={
            "nfs_host": "192.168.10.9", "nfs_path": ":/controlplanenfs/us04pA"}))
        self.assertTrue(any("must not start with a colon" in e for e in errs), errs)

    def test_a_valid_nfs_block_adds_no_errors(self):
        errs = validate_config(cfg(deployment_settings={
            "nfs_host": "192.168.10.9", "nfs_path": "/controlplanenfs/us04pA"}))
        self.assertEqual(errs, [])


class TestNfsPairing(unittest.TestCase):
    """One without the other configures no backup, and wso still reports
    'nfs backup server info is not set'."""

    def test_host_without_path(self):
        errs = _check_deployment_settings({"nfs_host": "192.168.10.9"})
        self.assertTrue(any("must be set together" in e for e in errs), errs)

    def test_path_without_host(self):
        errs = _check_deployment_settings({"nfs_path": "/controlplanenfs"})
        self.assertTrue(any("must be set together" in e for e in errs), errs)

    def test_neither_is_fine(self):
        self.assertEqual(_check_deployment_settings({}), [])

    def test_nfs_version_enum(self):
        errs = _check_deployment_settings({
            "nfs_host": "h", "nfs_path": "/p", "nfs_version": "4.1"})
        self.assertTrue(any("nfs_version" in e for e in errs), errs)
        self.assertEqual(_check_deployment_settings({
            "nfs_host": "h", "nfs_path": "/p", "nfs_version": 4}), [])


class TestNodeIdentity(unittest.TestCase):
    """Claimed by the dialog's validation line but never actually checked until
    the review: a duplicate IP or a bad hostname only surfaced in phase 10/20,
    after the OVAs had been deployed."""

    def test_duplicate_ip_is_rejected(self):
        c = cfg()
        c["nodes"]["access"][1]["ip"] = c["nodes"]["platform"][0]["ip"]
        errs = validate_config(c)
        self.assertTrue(any("duplicate IP" in e for e in errs), errs)

    def test_collision_with_the_bootstrap_counts_too(self):
        c = cfg()
        c["nodes"]["platform"][0]["ip"] = c["nodes"]["bootstrap"]["ip"]
        self.assertTrue(any("duplicate IP" in e for e in validate_config(c)))

    def test_duplicate_hostname_is_rejected(self):
        c = cfg()
        c["nodes"]["access"][1]["hostname"] = "access1"
        self.assertTrue(any("duplicate hostname" in e for e in validate_config(c)))

    def test_hostname_must_be_a_dns_label(self):
        c = cfg()
        c["nodes"]["access"][0]["hostname"] = "Access_1.lab"
        self.assertTrue(any("not a valid DNS label" in e for e in validate_config(c)))

    def test_ip_outside_the_subnet_is_rejected(self):
        c = cfg()
        c["nodes"]["access"][0]["ip"] = "10.99.0.5"
        self.assertTrue(any("not in subnet" in e for e in validate_config(c)))

    def test_node_counts_follow_the_size(self):
        c = cfg()
        c["nodes"]["platform"] = c["nodes"]["platform"][:2]
        self.assertTrue(any("exactly 3 expected" in e for e in validate_config(c)))


if __name__ == "__main__":
    unittest.main()
