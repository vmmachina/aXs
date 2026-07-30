"""A hand-edited config.yml must not crash anything -- and NOT in one place.

Every shape below is a one- or two-character mistake in `deployment_settings.
logging`, the block with the most structure and therefore the most ways to get
wrong. Each used to raise, and where it raised decided how bad it was:

  * `is_configured` is called from phase 50's DONE-PROBE. The TUI reads any
    exception from a probe as "not done" and RUNS the phase against a healthy
    cluster; the plain path printed a traceback that never mentioned logging.
  * `needs_passwords` runs at every deploy start, in `config.context`.
  * `validate_config` is the function whose entire job is to NAME the mistake --
    and it died on it.
  * `answers_from_config` is `axs configure`, the tool the operator would use to
    REPAIR the broken config. It crashed on load.

The first attempt at this guarded the individual syslog ENTRY in three places
and left the CONTAINER unguarded in five, which is this project's signature
defect: repaired in one place, not in the others. So this file tests every shape
against every call site in a loop, rather than one shape per test -- a table
cannot be fixed in three places out of five.
"""

from __future__ import annotations

import unittest

import yaml

from ws1access import profile_yml, tui, validate

# Each entry: what a person plausibly wrote, and why it is easy to write.
SHAPES = {
    "syslog_servers as a mapping (forgot the `-`)":
        {"logging": {"syslog_servers": {"host": "log1", "port": 514}}},
    "a syslog entry as a bare string":
        {"logging": {"syslog_servers": ["log1.example.com"]}},
    "logging as a string":
        {"logging": "enabled"},
    "logging as a list":
        {"logging": ["loki_server"]},
    "loki_server as a bare url":
        {"logging": {"loki_server": "http://loki:3100"}},
    "opensearch as a list":
        {"logging": {"opensearch": ["http://os:9200"]}},
    "syslog_servers as a string":
        {"logging": {"syslog_servers": "log1.example.com"}},
    "a host that is only whitespace":
        {"logging": {"syslog_servers": [{"host": "   "}]}},
    "a nested value where a scalar belongs":
        {"logging": {"loki_server": {"url": "http://l", "auth": {"u": "v"}}}},
    "three syslog entries, the first one junk":
        {"logging": {"syslog_servers": ["junk", {"host": "a"}, {"host": "b"}]}},
}


class TestNothingCrashesOnAnyShape(unittest.TestCase):
    def sites(self, ops: dict):
        """Every place that reads this block. Named, so a failure says which."""
        return {
            "is_configured": lambda: profile_yml.is_configured(ops),
            "patch": lambda: profile_yml.patch("nfs_host: x\n", ops),
            "summary": lambda: profile_yml.summary(ops),
            "needs_passwords": lambda: profile_yml.needs_passwords(ops),
            "with_passwords": lambda: profile_yml.with_passwords(
                ops, {"loki_server": "pw"}),
            "drift": lambda: profile_yml.drift("nfs_host: x\n", ops),
            "drift_keys": lambda: profile_yml.drift_keys("nfs_host: x\n", ops),
            "actionable_keys": lambda: profile_yml.actionable_keys(
                "nfs_host: x\n", ops),
            "orphan_keys": lambda: profile_yml.orphan_keys("nfs_host: x\n", ops),
            "validate_config": lambda: validate.validate_config(
                {"cluster": {"name": "lab"},
                 "deployment_settings": ops}),
            "configure wizard": lambda: tui.answers_from_config(
                {"deployment_settings": ops}),
        }

    def test_every_shape_survives_every_call_site(self):
        for label, ops in SHAPES.items():
            for site, call in self.sites(ops).items():
                with self.subTest(shape=label, site=site):
                    call()      # the assertion is that it does not raise

    def test_what_patch_writes_still_parses_for_every_shape(self):
        # Surviving is not enough -- wso reads this file too.
        for label, ops in SHAPES.items():
            with self.subTest(shape=label):
                out = profile_yml.patch("nfs_host: x\n", ops)
                self.assertIsInstance(yaml.safe_load(out), dict)

    def test_no_shape_produces_permanent_drift(self):
        # aXs's own output compared against aXs's own config must agree, or the
        # operator gets a drift warning on every run that nothing can clear.
        for label, ops in SHAPES.items():
            with self.subTest(shape=label):
                settings = dict(ops, nfs_host="10.0.0.9", nfs_path="/p",
                                nfs_version=4)
                out = profile_yml.patch("nfs_host: x\n", settings)
                self.assertEqual(
                    profile_yml.actionable_keys(out, settings), [])


class TestTheValidatorNamesThemInstead(unittest.TestCase):
    """Surviving is the floor; naming the mistake is the job."""

    def errors(self, logging: object) -> list[str]:
        return validate.validate_config({
            "cluster": {"name": "lab"},
            "deployment_settings": {"logging": logging}})

    def test_a_mapping_where_a_list_belongs_is_named(self):
        errs = self.errors({"syslog_servers": {"host": "log1"}})
        self.assertTrue(any("syslog_servers" in e and "LIST" in e for e in errs),
                        errs)

    def test_a_bare_string_entry_is_named(self):
        errs = self.errors({"syslog_servers": ["log1.example.com"]})
        self.assertTrue(any("syslog_servers" in e and "mapping" in e
                            for e in errs), errs)

    def test_a_backend_given_as_a_bare_url_is_named(self):
        errs = self.errors({"loki_server": "http://loki:3100"})
        self.assertTrue(any("loki_server" in e and "mapping" in e
                            for e in errs), errs)

    def test_a_whitespace_only_host_is_rejected(self):
        # It used to pass validation and be written out to wso as a real entry,
        # while both comparison sides skipped it -- so nothing ever reported the
        # nonsense the tool had handed over.
        errs = self.errors({"syslog_servers": [{"host": "   "}]})
        self.assertTrue(any("host is required" in e for e in errs), errs)

    def test_a_whitespace_host_never_reaches_the_written_file(self):
        # Validation is the first line, not the only one: the plain deploy path
        # never calls validate_config at all, so the writer has to skip it too.
        # It used to be handed to wso as a real syslog entry while both
        # comparison sides skipped it -- so nothing ever reported the nonsense.
        settings = {"logging": {"syslog_servers": [{"host": "   "},
                                                  {"host": "log1"}]}}
        shape = yaml.safe_load(profile_yml.patch("", settings))
        hosts = [s.get("host") for s in
                 (shape.get("logging") or {}).get("syslog_servers") or []]
        self.assertEqual(hosts, ["log1"])

    def test_a_valid_block_produces_no_errors_at_all(self):
        # The guard rails must not start rejecting correct input.
        errs = self.errors({
            "loki_server": {"url": "http://loki:3100", "username": "svc"},
            "syslog_servers": [{"host": "log1", "protocol": "tcp",
                                "port": 601}]})
        self.assertEqual([e for e in errs if "logging" in e], [])


class TestSyslogEntriesIsTheOneHelper(unittest.TestCase):
    """One implementation, so the writer and the comparison cannot diverge --
    which is the whole reason the first fix failed."""

    def test_a_mapping_container_yields_nothing(self):
        self.assertEqual(profile_yml.syslog_entries({"syslog_servers":
                                                     {"host": "x"}}), [])

    def test_non_mapping_entries_are_dropped(self):
        got = profile_yml.syslog_entries(
            {"syslog_servers": ["junk", {"host": "a"}]})
        self.assertEqual(got, [{"host": "a"}])

    def test_the_two_entry_cap_is_applied_before_dropping(self):
        # Consistent with what validate_config reports on, so the writer and the
        # comparison agree about which entries exist even when one is junk.
        got = profile_yml.syslog_entries(
            {"syslog_servers": ["junk", {"host": "a"}, {"host": "b"}]})
        self.assertEqual(got, [{"host": "a"}])

    def test_a_non_mapping_logging_block_yields_nothing(self):
        for logging in ("enabled", ["a"], 7, None):
            self.assertEqual(profile_yml.syslog_entries(logging), [])

    def test_mapping_passes_a_real_mapping_through(self):
        self.assertEqual(profile_yml.mapping({"a": 1}), {"a": 1})
        for junk in ("enabled", ["a"], 7, None):
            self.assertEqual(profile_yml.mapping(junk), {})


class TestScalarPatchingStaysAtTheTopLevel(unittest.TestCase):
    """These keys live at the root of profile.yml. Matching indented lines put an
    unrelated nested key of the same name in scope -- and the duplicate rule
    added for B1 then DELETED it."""

    def patched(self, remote: str, **settings):
        out = profile_yml.patch(remote, settings)
        return out, yaml.safe_load(out)

    def test_a_nested_key_of_the_same_name_after_the_sample_survives(self):
        remote = "custom_block:\n  ntp_server: 1.2.3.4\nnfs_host: old\n"
        _out, shape = self.patched(remote, ntp_server="ntp.example.com")
        self.assertEqual(shape["custom_block"], {"ntp_server": "1.2.3.4"})
        self.assertEqual(shape["ntp_server"], "ntp.example.com")

    def test_a_nested_key_before_a_top_level_one_survives(self):
        # This one used to produce a file that no longer parsed at all.
        remote = "custom_block:\n  ntp_server: 1.2.3.4\nntp_server: old\n"
        _out, shape = self.patched(remote, ntp_server="ntp.example.com")
        self.assertEqual(shape["custom_block"], {"ntp_server": "1.2.3.4"})
        self.assertEqual(shape["ntp_server"], "ntp.example.com")

    def test_a_key_inside_a_block_scalar_is_left_alone(self):
        remote = "doc: |\n  ntp_server: inside\nntp_server: old\n"
        _out, shape = self.patched(remote, ntp_server="ntp.example.com")
        self.assertIn("ntp_server: inside", shape["doc"])

    def test_a_prefix_of_another_key_is_not_touched(self):
        remote = "ntp_server_extra: keep\nntp_server: old\n"
        _out, shape = self.patched(remote, ntp_server="new")
        self.assertEqual(shape["ntp_server_extra"], "keep")
        self.assertEqual(shape["ntp_server"], "new")

    def test_a_commented_sample_is_still_replaced_in_place(self):
        for remote in ("#ntp_server: us.pool.ntp.org\n",
                       "# ntp_server: us.pool.ntp.org\n"):
            with self.subTest(remote=remote):
                out, shape = self.patched(remote, ntp_server="new")
                self.assertEqual(shape["ntp_server"], "new")
                # In place, not appended after the aXs marker.
                self.assertNotIn(profile_yml._MARK, out)

    def test_a_real_top_level_duplicate_is_still_overridden(self):
        # The case the duplicate rule exists for, so narrowing it did not
        # remove it.
        _out, shape = self.patched("ntp_server: a\nntp_server: b\n",
                                   ntp_server="new")
        self.assertEqual(shape["ntp_server"], "new")


if __name__ == "__main__":
    unittest.main()
