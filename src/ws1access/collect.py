"""State collection -- what is actually there, as opposed to what config.yml says.

This is the mechanism behind the tool's idempotency. Every phase's is_done()
question is a slice of what is gathered here, so the probes exist once rather
than nine times scattered across phase modules, where they would drift apart.

Everything is read-only. Two things are never touched:

  * /root/<cluster>/cp-cluster/secrets/cp-cluster/vault -- the Vault unseal keys
    and root key. Its existence is state worth reporting; its contents are the
    cluster's master key and are never read.
Not read at all, contrary to what this docstring claimed until 2026-07-30:
cp-cluster.env. The sentence described a redactor for its NOMAD_TOKEN /
CONSUL_TOKEN / VAULT_TOKEN lines, and neither the reader nor the redactor ever
existed on any path -- the claim was inherited forward and believed. If a future
change does read that file, `context.redact` is the redactor to use; it covers
`KEY=value` token lines, including `export`-prefixed and lower-case ones.

Each node is queried in a SINGLE ssh round trip. Six separate logins per node
would triple the runtime of a collection across seven nodes for no benefit.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime
from dataclasses import dataclass, field

from .ssh import SshResult, explain_failure, run_with_key, run_with_password

# Sections are delimited so one command can carry many answers back.
SEP = "@@WS1@@"

NODE_PROBE = f"""
echo '{SEP}hostname';   hostname -f 2>/dev/null
echo '{SEP}route';      ip route 2>/dev/null | grep '^default'
echo '{SEP}addrs';      ip -4 -br addr show 2>/dev/null
echo '{SEP}resolv';     (resolvectl status 2>/dev/null || cat /etc/resolv.conf) 2>/dev/null
echo '{SEP}pwage';      LC_ALL=C sudo -n chage -l configuser 2>/dev/null || LC_ALL=C chage -l configuser 2>/dev/null
echo '{SEP}os';         cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)='
echo '{SEP}disk';       df -h / 2>/dev/null | tail -1
echo '{SEP}end'
"""

# Internal ranges the cluster uses. Reported when a node address falls inside
# one -- see ova_profiles/26.07.yml for why this warns rather than blocks.
RESERVED = [
    ("172.17.0.0/16", "docker0"),
    ("172.26.64.0/20", "nomad"),
]


def _sections(output: str) -> dict[str, str]:
    """Split a probe response back into its labelled parts."""
    out: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in output.splitlines():
        if line.startswith(SEP):
            if current:
                out[current] = "\n".join(buf).strip()
            current, buf = line[len(SEP):].strip(), []
        elif current:
            buf.append(line)
    if current:
        out[current] = "\n".join(buf).strip()
    return out


# The configuser password EXPIRES 60 days after the OVA deploy, and when it does
# every SSH path breaks at once -- this tool's and wso's ansible alike (docs/03,
# docs/06, which even names the lab's date: 2026-09-20). The expiry date was
# already collected and displayed; nothing ever compared it to today, so a
# deploy could start with two days left and fail mid-run on an auth error that
# looks like something else entirely. That confusion cost hours on 2026-07-29.
#
# `chage -l` prints the date in the C locale as "Sep 20, 2026" -- NODE_PROBE
# forces LC_ALL=C so the format does not depend on the node's locale.
_CHAGE_DATE = "%b %d, %Y"

# Warn this far ahead. A deploy runs ~2 hours, but a resume can happen days
# later and phase 60/70 alone take over an hour, so a week is not enough margin
# to be worth staying quiet about.
EXPIRY_WARN_DAYS = 14


def password_expiry(value: str | None, today: "date | None" = None
                    ) -> tuple[str, int | None]:
    """Interpret `chage -l`'s "Password expires" value.

    Returns one of:
      ("never",   None)  -- no expiry set on this account
      ("days",    n)     -- expires in n days; n <= 0 means it already has
      ("unknown", None)  -- could not be determined

    The third state is the point. An unparsed date, a missing value or a locale
    that slipped past LC_ALL=C must not be reported as "fine" OR as "expired":
    "we could not tell" is its own answer (docs/08 A9, and the same rule the
    liveness and healthcheck probes follow).
    """
    if not value or not value.strip():
        return ("unknown", None)
    text = value.strip()
    if text.lower() in ("never", "n/a", "-"):
        return ("never", None)
    try:
        when = datetime.strptime(text, _CHAGE_DATE).date()
    except ValueError:
        return ("unknown", None)
    return ("days", (when - (today or date.today())).days)


@dataclass
class NodeState:
    ip: str
    expected_hostname: str | None = None
    reachable: bool = False
    error: str | None = None

    hostname: str | None = None
    interface: str | None = None
    address: str | None = None       # CIDR on the primary interface
    gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    extra_networks: dict[str, str] = field(default_factory=dict)  # docker0, nomad, ...
    os_name: str | None = None
    disk_free: str | None = None
    password_expires: str | None = None

    problems: list[str] = field(default_factory=list)

    def compare(self, *, gateway: str | None, dns: list[str] | None,
                search: list[str] | None) -> None:
        """Check what the node reports against what the config asked for.

        This is the step that makes phase 20 meaningful: ovftool exiting 0 says
        the OVF was accepted, not that its properties applied.
        """
        # A value the node does NOT report is a problem, not a pass. The old
        # code compared only when both sides had something, so a node with no
        # default route at all, or no DNS upstream at all, sailed through -- the
        # exact failure this phase exists to catch. SSH still works in those
        # states (the tool sits in the same subnet), so nothing else notices
        # until wso's ansible needs to leave the subnet an hour later.
        if self.expected_hostname:
            # Compare the LABEL, not a prefix: startswith() let 'access' match
            # 'access2', so two nodes with their IPs swapped in the config were
            # certified as correct and the roles landed on the wrong machines.
            short = (self.hostname or "").split(".")[0]
            if not self.hostname:
                self.problems.append("node reports no hostname")
            elif short != self.expected_hostname:
                self.problems.append(
                    f"hostname is {self.hostname}, expected {self.expected_hostname}"
                )
        if gateway:
            if not self.gateway:
                self.problems.append(
                    f"no default route on the node, expected gateway {gateway}")
            elif self.gateway != gateway:
                self.problems.append(f"gateway is {self.gateway}, expected {gateway}")
        if dns:
            # Cluster nodes answer with the systemd-resolved stub; the real
            # upstream is what matters -- and its absence means the node cannot
            # resolve anything, however healthy the stub looks.
            real = [s for s in (self.dns_servers or []) if not s.startswith("127.")]
            if not real:
                self.problems.append(
                    f"no DNS upstream on the node (only the local stub), "
                    f"expected {', '.join(dns)}")
            elif not set(dns) & set(real):
                self.problems.append(
                    f"DNS is {', '.join(real)}, expected {', '.join(dns)}"
                )
        if search:
            if not self.search_domains:
                self.problems.append(
                    f"no search domain on the node, expected {', '.join(search)}")
            elif not set(search) & set(self.search_domains):
                self.problems.append(
                    f"search domain is {', '.join(self.search_domains)}, "
                    f"expected {', '.join(search)}"
                )
        if self.address:
            try:
                addr = ipaddress.ip_interface(self.address).ip
                for cidr, owner in RESERVED:
                    if addr in ipaddress.ip_network(cidr):
                        self.problems.append(
                            f"address {addr} lies inside {cidr}, which the cluster "
                            f"uses for {owner} (consequence unverified)"
                        )
            except ValueError:
                pass


def parse_node(ip: str, output: str, expected_hostname: str | None = None) -> NodeState:
    s = _sections(output)
    node = NodeState(ip=ip, expected_hostname=expected_hostname, reachable=True)

    node.hostname = s.get("hostname") or None

    # The interface name is NOT eth0 despite the OVF property label -- it is
    # ens160 on this appliance. Resolve it from the default route instead of
    # assuming a name.
    if route := s.get("route"):
        if m := re.search(r"default via (\S+) dev (\S+)", route):
            node.gateway, node.interface = m.group(1), m.group(2)

    for line in (s.get("addrs") or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, addr = parts[0], parts[2]
        if name == node.interface:
            node.address = addr
        elif name not in ("lo",):
            node.extra_networks[name] = addr

    # resolvectl repeats each server per link, so de-duplicate while keeping
    # order. "~consul" is Consul's split-DNS routing domain, not a real search
    # domain, and would otherwise look like a misconfiguration.
    resolv = s.get("resolv") or ""

    def uniq(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    node.dns_servers = uniq(re.findall(r"(?:DNS Servers?:|nameserver)\s+(\S+)", resolv))
    domains: list[str] = []
    for m in re.findall(r"(?:DNS Domain:|search)\s+(.+)", resolv):
        domains += m.split()
    node.search_domains = uniq(d for d in domains if not d.startswith("~"))

    if os_txt := s.get("os"):
        if m := re.search(r'PRETTY_NAME="([^"]+)"', os_txt):
            node.os_name = m.group(1)

    if disk := s.get("disk"):
        parts = disk.split()
        if len(parts) >= 4:
            node.disk_free = f"{parts[3]} frei von {parts[1]}"

    if pw := s.get("pwage"):
        if m := re.search(r"Password expires\s*:\s*(.+)", pw):
            node.password_expires = m.group(1).strip()

    return node


def collect_node(
    ip: str,
    *,
    password: str | None = None,
    expected_hostname: str | None = None,
    user: str = "configuser",
    gateway: str | None = None,
    dns: list[str] | None = None,
    search: list[str] | None = None,
) -> NodeState:
    """Probe one node. Prefers key auth, falls back to the password.

    Both paths matter: before phase 50 only the password exists, afterwards only
    the key is needed.

    Pass gateway/dns/search to have the reported values CHECKED against them.
    Without them the node is only described, not verified -- which is what
    happened for a long time: NodeState.compare() existed in full and had no
    caller at all, so phase 20 promised to "verify network configuration" while
    actually testing nothing but SSH.
    """
    result: SshResult = run_with_key(ip, NODE_PROBE, user=user)
    if not result.ok and password:
        result = run_with_password(ip, NODE_PROBE, password, user=user)

    if not result.ok:
        return NodeState(
            ip=ip, expected_hostname=expected_hostname,
            reachable=False, error=explain_failure(ip, result, user),
        )
    state = parse_node(ip, result.output, expected_hostname)
    if gateway or dns or search:
        state.compare(gateway=gateway, dns=dns, search=search)
    return state


def render_nodes(nodes: list[NodeState]) -> str:
    lines = ["Nodes"]
    width = max((len(n.expected_hostname or n.ip) for n in nodes), default=10)
    for n in nodes:
        label = (n.expected_hostname or n.ip).ljust(width)
        if not n.reachable:
            lines.append(f"  {label}  {n.ip:<14} not reachable")
            for line in (n.error or "").splitlines():
                lines.append(f"      {line}")
            continue
        lines.append(
            f"  {label}  {n.ip:<14} {n.interface or '?':<8} "
            f"{n.address or '?':<18} gw {n.gateway or '?'}"
        )
        detail = []
        if n.dns_servers:
            detail.append("dns " + ",".join(n.dns_servers))
        if n.search_domains:
            detail.append("search " + ",".join(n.search_domains))
        if n.password_expires:
            detail.append(f"configuser expires: {n.password_expires}")
        if n.disk_free:
            detail.append(n.disk_free)
        if detail:
            lines.append("      " + " | ".join(detail))
        if n.extra_networks:
            lines.append("      internal: " + ", ".join(
                f"{k}={v}" for k, v in sorted(n.extra_networks.items())))
        for p in n.problems:
            lines.append(f"    ! {p}")
    return "\n".join(lines)
