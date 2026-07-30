"""parse_readiness() and parse_healthcheck() -- the two acceptance gates.

Both parse wso's JSON rather than trust its exit code: readiness has no verified
rc semantics, and the exit code alone hides the ~30 infrastructure services that
readiness never lists.

The `include_services` split is the fix for a live failure on 2026-07-28 13:18:
phase 60 folded service health into its own verdict, so the moment a phase-70
service came up, phase 60 declared the platform unfinished and launched
`wso cp deploy` alongside the running `wso services deploy`.
"""

from __future__ import annotations

import unittest

from ws1access.health import (
    ACCESS_CORE,
    UNREADABLE,
    is_advisory,
    parse_healthcheck,
    parse_readiness,
    sealed_detected,
)

from ._fakes import healthcheck_json, readiness_json


class TestParseReadiness(unittest.TestCase):
    def test_all_ready(self):
        ok, not_ready, missing = parse_readiness(readiness_json())
        self.assertTrue(ok)
        self.assertEqual(not_ready, [])
        self.assertEqual(missing, [])

    def test_one_service_not_ready(self):
        ok, not_ready, missing = parse_readiness(readiness_json(launcher="NOT_READY"))
        self.assertFalse(ok)
        self.assertEqual(not_ready, ["launcher"])
        self.assertEqual(missing, [])

    def test_one_service_absent_is_missing_not_not_ready(self):
        # Absent means never deployed -- a different diagnosis, and phase 70's
        # retry depends on telling the two apart.
        ok, not_ready, missing = parse_readiness(readiness_json(launcher=None))
        self.assertFalse(ok)
        self.assertEqual(not_ready, [])
        self.assertEqual(missing, ["launcher"])

    def test_unknown_listed_service_not_ready_is_still_critical(self):
        # The doc says 'each service' must be READY, not just the core ones.
        ok, not_ready, missing = parse_readiness(
            readiness_json(**{"some-new-service": "NOT_READY"}))
        self.assertFalse(ok)
        self.assertIn("some-new-service", not_ready)

    def test_unreadable_output_is_its_own_diagnosis(self):
        # "I could not read the answer" reported as "these services do not
        # exist" sent the operator hunting for services that were fine.
        ok, not_ready, missing = parse_readiness("wso: command not found")
        self.assertFalse(ok)
        self.assertEqual(missing, [UNREADABLE])
        self.assertEqual(not_ready, [])

    def test_empty_output_is_unreadable(self):
        _, _, missing = parse_readiness("")
        self.assertEqual(missing, [UNREADABLE])

    def test_json_that_is_not_an_object_is_unreadable(self):
        _, _, missing = parse_readiness("[1, 2, 3]")
        self.assertEqual(missing, [UNREADABLE])

    def test_empty_object_lists_every_core_service_as_missing(self):
        ok, not_ready, missing = parse_readiness("{}")
        self.assertFalse(ok)
        self.assertEqual(missing, sorted(ACCESS_CORE))
        self.assertNotIn(UNREADABLE, missing)

    def test_ready_is_matched_case_insensitively(self):
        ok, _, _ = parse_readiness(readiness_json(token="ready"))
        self.assertTrue(ok)


class TestAdvisory(unittest.TestCase):
    """An explicit allowlist, never the complement: backup/ingress/database are
    data-path or data-safety and must stay critical."""

    def test_logging_and_telegraf_are_advisory(self):
        self.assertTrue(is_advisory("control-plane-logging"))
        self.assertTrue(is_advisory("telegraf-statsd"))

    def test_data_path_services_are_not_advisory(self):
        for name in ("control-plane-backup", "postgres-operations",
                     "opensearch", "nginx-ingress"):
            self.assertFalse(is_advisory(name), name)


class TestParseHealthcheck(unittest.TestCase):
    def test_healthy_cluster(self):
        ok, problems = parse_healthcheck(healthcheck_json())
        self.assertTrue(ok, problems)
        self.assertEqual(problems, [])

    def test_text_prefix_before_the_json_is_tolerated(self):
        # wso prints "Checking ... done" lines first; that is not an error.
        ok, _ = parse_healthcheck(
            healthcheck_json(prefix="Checking vault ... done\n"
                                    "Checking consul ... done\n"))
        self.assertTrue(ok)

    def test_unhealthy_member_is_named(self):
        ok, problems = parse_healthcheck(healthcheck_json(vault_healthy=False))
        self.assertFalse(ok)
        self.assertTrue(any("vault/platform1" in p for p in problems), problems)

    def test_unreachable_component_carries_its_error(self):
        ok, problems = parse_healthcheck(healthcheck_json(consul_reachable=False))
        self.assertFalse(ok)
        self.assertTrue(any("consul: unreachable" in p and "connection refused" in p
                            for p in problems), problems)

    def test_sealed_vault_names_the_repair(self):
        ok, problems = parse_healthcheck(healthcheck_json(vault_sealed=True))
        self.assertFalse(ok)
        self.assertTrue(any("wso cp unseal" in p for p in problems), problems)

    def test_sealed_detected(self):
        self.assertTrue(sealed_detected(healthcheck_json(vault_sealed=True)))
        self.assertFalse(sealed_detected(healthcheck_json()))

    def test_unreadable_output(self):
        ok, problems = parse_healthcheck("Traceback (most recent call last):")
        self.assertFalse(ok)
        self.assertEqual(problems, ["<unparseable healthcheck output>"])


class TestIncludeServices(unittest.TestCase):
    """Phase 60 owns the platform; the services belong to phase 70."""

    def test_service_issue_fails_the_default_gate(self):
        ok, problems = parse_healthcheck(
            healthcheck_json(service_issues=["opensearch: 0/3 allocations"]))
        self.assertFalse(ok)
        self.assertTrue(any("opensearch" in p for p in problems), problems)

    def test_same_input_passes_phase_60s_gate(self):
        # This is the whole fix: a phase-70 service coming up must not make
        # phase 60 flip back to "todo" and start `wso cp deploy` alongside it.
        ok, problems = parse_healthcheck(
            healthcheck_json(service_issues=["opensearch: 0/3 allocations"]),
            include_services=False)
        self.assertTrue(ok, problems)
        self.assertEqual(problems, [])

    def test_platform_problems_still_fail_phase_60s_gate(self):
        # include_services=False must narrow the question, not weaken it.
        ok, problems = parse_healthcheck(
            healthcheck_json(vault_sealed=True,
                             service_issues=["opensearch: 0/3 allocations"]),
            include_services=False)
        self.assertFalse(ok)
        self.assertTrue(any("SEALED" in p for p in problems), problems)
        self.assertFalse(any("opensearch" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
