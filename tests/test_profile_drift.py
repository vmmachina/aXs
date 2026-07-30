"""profile_yml.drift() -- the minimal answer to docs/08 B1.

Phase 50's done-probe asks `wso access validate`, which validates the files
from the LAST run. An operator who adds an NFS backup target after a successful
deploy -- exactly what wso's own warning asks for -- used to get:

    50_cluster_init: already done      <- profile.yml never patched
    60_platform:     already done      <- off the historical folder hash
    === deploy complete ===            <- green. The backup does not exist.

It would surface at the first restore. This compares per key instead, and the
two properties that make the answer usable are tested here as hard as the
detection: it must be blind to formatting and to wso's own keys, and it must
never touch a secret.
"""

from __future__ import annotations

import unittest

import yaml

from ws1access.profile_yml import UNREADABLE, drift, patch

# What `wso access init` writes: four keys of its own, everything else present
# but commented out. Anything here must stay invisible to the comparison.
WSO_TEMPLATE = """\
# Control Plane profile
cluster_name: lab
datacenter_name: dc1
deployment_size: small
product: access

# Time
#ntp_server: us.pool.ntp.org

# Backup target -- required for disaster recovery
#nfs_host: 10.0.0.9
#nfs_path: /controlplanenfs/us04pA
#nfs_version: 4

#bridge_network_subnet: 172.26.64.0/20
"""

NFS = {"nfs_host": "10.0.0.9", "nfs_path": "/controlplanenfs/us04pA",
       "nfs_version": 4}


class TestNoDriftWhenTheyAgree(unittest.TestCase):
    def test_a_file_aXs_just_wrote_has_no_drift(self):
        # The round trip that matters: patch() then drift() must agree, or
        # every single run would report drift against its own output.
        written = patch(WSO_TEMPLATE, NFS)
        self.assertEqual(drift(written, NFS), [])

    def test_nothing_configured_is_never_drift(self):
        # aXs owns no key here, so wso's own values are not a disagreement
        # with a config.yml that makes no claim.
        self.assertEqual(drift(WSO_TEMPLATE, {}), [])
        self.assertEqual(drift(WSO_TEMPLATE, {"nfs_host": ""}), [])

    def test_nothing_configured_ignores_even_values_axs_itself_wrote(self):
        # The stated cost of that rule, pinned so it is a decision and not an
        # accident: clearing every operational setting out of config.yml is NOT
        # reported as drift, even though the values are still on the cluster.
        # An empty config.yml claims nothing, so there is nothing to disagree
        # with -- and the alternative, treating absence as "remove it", would
        # make the check demand a rollout nobody asked for.
        written = patch(WSO_TEMPLATE, NFS)
        self.assertEqual(drift(written, {}), [])

    def test_wsos_own_keys_are_invisible(self):
        written = patch(WSO_TEMPLATE, NFS)
        meddled = written.replace("cluster_name: lab", "cluster_name: renamed")
        self.assertEqual(drift(meddled, NFS), [])

    def test_comments_and_formatting_are_invisible(self):
        # A byte diff would fire on all of this. That is why it is not one.
        written = patch(WSO_TEMPLATE, NFS)
        reformatted = (written.replace("nfs_host: 10.0.0.9",
                                       "nfs_host:    '10.0.0.9'   # edited by hand")
                       + "\n# a comment someone added\n")
        self.assertEqual(drift(reformatted, NFS), [])

    def test_a_future_key_wso_adds_is_invisible(self):
        written = patch(WSO_TEMPLATE, NFS) + "\nsome_new_vendor_key: whatever\n"
        self.assertEqual(drift(written, NFS), [])

    def test_int_and_string_are_the_same_value(self):
        # wso writes `nfs_version: 4`; config.yml may carry "4". Calling those
        # different would report drift on every run.
        written = patch(WSO_TEMPLATE, NFS)
        self.assertEqual(drift(written, {**NFS, "nfs_version": "4"}), [])

    def test_a_leading_zero_is_not_permanent_drift(self):
        # `nfs_version: "04"` -- _scalar_line writes int("04") = 4, so a raw
        # string comparison reported drift against aXs's OWN output, on every
        # single run. A warning that always fires is one nobody reads.
        settings = {**NFS, "nfs_version": "04"}
        self.assertEqual(drift(patch(WSO_TEMPLATE, settings), settings), [])


class TestDetectsTheCaseThatCostTheDay(unittest.TestCase):
    def test_nfs_added_after_a_successful_deploy(self):
        # The literal docs/08 B1 scenario: cluster deployed without NFS, the
        # operator adds it to config.yml, the probe says "already done".
        diffs = drift(WSO_TEMPLATE, NFS)
        self.assertTrue(diffs)
        named = " ".join(diffs)
        for key in ("nfs_host", "nfs_path", "nfs_version"):
            self.assertIn(key, named)
        self.assertIn("the bootstrap has nothing", named)

    def test_a_changed_value_names_both_sides(self):
        written = patch(WSO_TEMPLATE, NFS)
        diffs = drift(written, {**NFS, "nfs_path": "/exports/corrected"})
        self.assertEqual(len(diffs), 1)
        self.assertIn("nfs_path", diffs[0])
        self.assertIn("/exports/corrected", diffs[0])       # what config wants
        self.assertIn("/controlplanenfs/us04pA", diffs[0])  # what is out there

    def test_a_value_removed_from_config_is_still_drift(self):
        # config.yml is meant to be the single source of truth; a value only
        # the bootstrap has is a disagreement, whichever way it arose.
        written = patch(WSO_TEMPLATE, {**NFS, "ntp_server": "ch.pool.ntp.org"})
        diffs = drift(written, NFS)
        self.assertEqual(len(diffs), 1)
        self.assertIn("ntp_server", diffs[0])
        self.assertIn("not set in config.yml", diffs[0])

    def test_a_hand_edit_on_the_bootstrap_is_drift(self):
        written = patch(WSO_TEMPLATE, NFS).replace(
            "/controlplanenfs/us04pA", "/somewhere/else")
        self.assertTrue(any("nfs_path" in d for d in drift(written, NFS)))


class TestSecretsAreNeverCompared(unittest.TestCase):
    """The comparison must not be able to print a password. The price is
    stated: a change that is ONLY a password is invisible (docs/09 §5.2)."""

    WITH_LOGGING = {
        "nfs_host": "10.0.0.9", "nfs_path": "/exports/cp",
        "logging": {"loki_server": {"url": "https://loki.example.com",
                                    "user": "svc", "password": "hunter2"}},
    }

    def test_a_password_only_change_is_invisible(self):
        written = patch(WSO_TEMPLATE, self.WITH_LOGGING)
        changed = {**self.WITH_LOGGING,
                   "logging": {"loki_server": {"url": "https://loki.example.com",
                                               "user": "svc",
                                               "password": "different"}}}
        self.assertEqual(drift(written, changed), [])

    def test_no_password_can_appear_in_the_output(self):
        # A real difference elsewhere, so the output is non-empty -- and still
        # must not carry either secret.
        written = patch(WSO_TEMPLATE, self.WITH_LOGGING)
        changed = {**self.WITH_LOGGING, "nfs_path": "/exports/moved"}
        out = " ".join(drift(written, changed))
        self.assertTrue(out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("password", out)

    def test_a_key_that_merely_contains_password_is_dropped_too(self):
        # Matched by substring, not by an exact list. `admin_password` was
        # compared and returned by the exact form -- redact() happened to catch
        # it downstream, which is luck, not a rule.
        settings = {"logging": {"loki_server": {"url": "https://l.example.com",
                                                "admin_password": "hunter2"}}}
        changed = {"logging": {"loki_server": {"url": "https://l2.example.com",
                                               "admin_password": "different"}}}
        out = " ".join(drift(patch(WSO_TEMPLATE, settings), changed))
        self.assertIn("loki_server.url", out)     # the real change is seen
        self.assertNotIn("hunter2", out)
        self.assertNotIn("different", out)

    def test_a_nested_dict_value_is_never_printed(self):
        # `auth: {password: ...}` would otherwise be stringified whole and
        # printed verbatim -- and redact() does not mask that shape.
        settings = {"logging": {"loki_server": {
            "url": "https://l.example.com", "auth": {"password": "nested-pw"}}}}
        changed = {"logging": {"loki_server": {
            "url": "https://l2.example.com", "auth": {"password": "other-pw"}}}}
        out = " ".join(drift(patch(WSO_TEMPLATE, settings), changed))
        self.assertNotIn("nested-pw", out)
        self.assertNotIn("other-pw", out)

    def test_an_unknown_secret_shaped_key_is_dropped(self):
        settings = {"logging": {"loki_server": {"url": "https://l.example.com",
                                                "api_key": "sk-live-123"}}}
        changed = {"logging": {"loki_server": {"url": "https://l2.example.com",
                                               "api_key": "sk-live-456"}}}
        out = " ".join(drift(patch(WSO_TEMPLATE, settings), changed))
        self.assertNotIn("sk-live", out)

    def test_a_logging_url_change_is_still_seen(self):
        # Dropping secrets must not drop the block they sit in.
        written = patch(WSO_TEMPLATE, self.WITH_LOGGING)
        changed = {**self.WITH_LOGGING,
                   "logging": {"loki_server": {"url": "https://loki2.example.com",
                                               "user": "svc",
                                               "password": "hunter2"}}}
        diffs = drift(written, changed)
        self.assertTrue(any("loki_server.url" in d for d in diffs), diffs)


class TestUnreadable(unittest.TestCase):
    """"I could not read it" is not "they agree" -- docs/08 A9, again."""

    def test_unparseable_yaml_is_its_own_answer(self):
        self.assertEqual(drift("nfs_host: [unclosed\n", NFS), [UNREADABLE])

    def test_a_yaml_scalar_instead_of_a_mapping_is_unreadable(self):
        self.assertEqual(drift("just a string\n", NFS), [UNREADABLE])

    def test_an_empty_file_reports_every_configured_key_as_absent(self):
        # Empty is readable, and its answer is "none of it is there" -- which
        # is a real finding, not a parse failure.
        diffs = drift("", NFS)
        self.assertNotIn(UNREADABLE, diffs)
        self.assertEqual(len(diffs), 3)

    def test_a_fully_commented_file_is_the_same_as_empty(self):
        diffs = drift("# nothing set\n#nfs_host: 10.0.0.9\n", NFS)
        self.assertNotIn(UNREADABLE, diffs)
        self.assertTrue(any("nfs_host" in d for d in diffs))


class TestHandEditedFileCannotRaise(unittest.TestCase):
    """profile.yml is a file a person edits on the bootstrap.

    An exception out of here is not a warning: the TUI reads a raised probe as
    "not done" and RUNS phase 50 against a healthy cluster, while the plain
    path and `axs status` die on a traceback. Before this, `port: default` and
    `logging: enabled` both raised.
    """

    BROKEN = (
        "logging: enabled\n",
        "logging:\n  loki_server: yes\n",
        "logging:\n  syslog_servers: notalist\n",
        "logging:\n  syslog_servers:\n    - just-a-string\n",
        "logging:\n  syslog_servers:\n    - host: h\n      port: default\n",
        "logging:\n  loki_server:\n    url: https://l\n    port: n/a\n",
        "nfs_host:\n  nested: value\n",
    )

    def test_no_shape_raises(self):
        for text in self.BROKEN:
            with self.subTest(text=text):
                out = drift(text, NFS)          # must not raise
                self.assertIsInstance(out, list)

    def test_a_bad_port_in_config_does_not_raise_either(self):
        # The want side is a hand-editable file too, and neither `axs status`
        # nor deploy runs validate_config first.
        settings = {"logging": {"loki_server": {"url": "https://l"},
                                "syslog_servers": [{"host": "h", "port": ""}]}}
        self.assertIsInstance(drift(WSO_TEMPLATE, settings), list)


class TestDuplicateKeys(unittest.TestCase):
    def test_the_last_value_wins_as_wso_reads_it(self):
        # patch() may leave a stale block behind rather than shred the file;
        # the comparison has to read the file the way wso does.
        text = "nfs_path: /old\nnfs_path: /controlplanenfs/us04pA\n"
        self.assertEqual(yaml.safe_load(text)["nfs_path"],
                         "/controlplanenfs/us04pA")
        self.assertEqual(drift(text, {"nfs_path": "/controlplanenfs/us04pA",
                                      "nfs_host": ""}), [])


if __name__ == "__main__":
    unittest.main()
