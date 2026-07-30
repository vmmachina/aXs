"""NodeState.compare() -- the check behind phase 20's promise.

Two failures from the 2026-07-28 review live here:

  * A value the node does NOT report was skipped and counted as a pass. A node
    with no default route at all, or no DNS upstream at all, sailed through the
    one check built to catch exactly that. SSH still works in that state, so
    nothing noticed until wso's ansible had to leave the subnet an hour later.
  * `startswith()` let the expected hostname `access` match the reported
    `access2`, so two nodes with their IPs swapped in config.yml were certified
    as correct and the roles landed on the wrong machines.
"""

from __future__ import annotations

import unittest

from ws1access.collect import NodeState

GW = "192.168.10.1"
DNS = ["192.168.10.53"]
SEARCH = ["lab.example.com"]


def node(**kw) -> NodeState:
    base = dict(ip="192.168.10.21", reachable=True)
    base.update(kw)
    return NodeState(**base)


class TestMissingValues(unittest.TestCase):
    """A node that reports nothing must not pass by reporting nothing."""

    def test_no_default_route_is_a_problem(self):
        n = node(gateway=None, dns_servers=DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("no default route" in p for p in n.problems),
                        n.problems)

    def test_no_dns_at_all_is_a_problem(self):
        n = node(gateway=GW, dns_servers=[], search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("no DNS upstream" in p for p in n.problems),
                        n.problems)

    def test_no_search_domain_is_a_problem(self):
        n = node(gateway=GW, dns_servers=DNS, search_domains=[])
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("no search domain" in p for p in n.problems),
                        n.problems)

    def test_no_hostname_is_a_problem(self):
        n = node(expected_hostname="access1", hostname=None,
                 gateway=GW, dns_servers=DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("no hostname" in p for p in n.problems), n.problems)


class TestHostnameLabel(unittest.TestCase):
    """`access` must not match `access2` -- swapped IPs were certified correct."""

    def test_access_does_not_match_access2(self):
        n = node(expected_hostname="access", hostname="access2.lab.example.com",
                 gateway=GW, dns_servers=DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("hostname is access2" in p for p in n.problems),
                        n.problems)

    def test_exact_label_with_domain_suffix_passes(self):
        # The FQDN is compared by its first label, so lab domains are fine.
        n = node(expected_hostname="access", hostname="access.lab.example.com",
                 gateway=GW, dns_servers=DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertEqual(n.problems, [])

    def test_longer_expected_does_not_match_shorter_reported(self):
        # The reverse direction of the same bug.
        n = node(expected_hostname="access2", hostname="access.lab.example.com",
                 gateway=GW, dns_servers=DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("expected access2" in p for p in n.problems),
                        n.problems)


class TestStubResolver(unittest.TestCase):
    """Cluster nodes answer with the systemd-resolved stub. A healthy-looking
    stub with no upstream behind it means the node resolves nothing."""

    def test_stub_only_is_not_a_dns_upstream(self):
        n = node(gateway=GW, dns_servers=["127.0.0.53"], search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("no DNS upstream" in p for p in n.problems),
                        n.problems)

    def test_stub_alongside_real_upstream_passes(self):
        n = node(gateway=GW, dns_servers=["127.0.0.53"] + DNS,
                 search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertEqual(n.problems, [])

    def test_wrong_upstream_is_reported_with_both_values(self):
        n = node(gateway=GW, dns_servers=["127.0.0.53", "8.8.8.8"],
                 search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("DNS is 8.8.8.8" in p for p in n.problems),
                        n.problems)
        # The stub must not be offered as the node's DNS in the message.
        self.assertFalse(any("127.0.0.53" in p for p in n.problems), n.problems)


class TestCorrectNode(unittest.TestCase):
    def test_fully_correct_node_has_no_problems(self):
        n = node(expected_hostname="platform1",
                 hostname="platform1.lab.example.com",
                 address="192.168.10.21/24", gateway=GW,
                 dns_servers=["127.0.0.53"] + DNS, search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertEqual(n.problems, [])

    def test_wrong_gateway_is_reported(self):
        n = node(gateway="192.168.10.254", dns_servers=DNS,
                 search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("gateway is 192.168.10.254" in p
                            for p in n.problems), n.problems)

    def test_address_inside_a_reserved_range_is_reported(self):
        # 172.26.64.0/20 is nomad's bridge network.
        n = node(address="172.26.64.5/20", gateway=GW, dns_servers=DNS,
                 search_domains=SEARCH)
        n.compare(gateway=GW, dns=DNS, search=SEARCH)
        self.assertTrue(any("172.26.64.0/20" in p for p in n.problems),
                        n.problems)


if __name__ == "__main__":
    unittest.main()
