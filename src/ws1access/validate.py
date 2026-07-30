"""Static config validation -- catch bad input in the dialog, not 40 min into a
deploy.

These are the deterministic, network-free checks that run against config.yml
alone: value formats, enums, IPs inside the subnet, node counts vs size,
mandatory fields, cert-topology consistency. Network- and cert-dependent checks
(DNS -> LB, the certificate cross-check) belong to preflight / the dialog, which
have the resolver and the PFX at hand.

`validate_config(cfg)` returns a list of human-readable error strings; an empty
list means the config is valid. The dialog calls the same functions per field so
a bad value is rejected while the user types.
"""

from __future__ import annotations

import ipaddress
import re

from . import access_profile, profile_yml

# DNS label: lowercase letters/digits/hyphen, not starting/ending with a hyphen.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_SIZES = {"small", "medium", "large"}
_ACCESS_COUNT = {"small": 2, "medium": 2, "large": 3}   # platform is always 3


def valid_label(s: str) -> bool:
    return bool(_LABEL.match(s or ""))


def valid_email(s: str) -> bool:
    return bool(_EMAIL.match(s or ""))


def valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def ip_in_subnet(ip: str, gateway: str, netmask: str) -> bool:
    try:
        net = ipaddress.ip_network(f"{gateway}/{netmask}", strict=False)
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def validate_config(cfg: dict) -> list[str]:
    # Robust against a file whose SHAPE is wrong, not only its values: a
    # top-level list, a section that is a string, deployment_settings that is not
    # a mapping. Each of those used to crash this function with an AttributeError
    # -- a traceback from the very code whose job is to name the mistake.
    # mapping() coerces a non-mapping to {} so the reads below cannot raise; a
    # wrong shape then yields the ordinary "missing" errors instead of a crash,
    # and the cases an operator actually hits (deployment_settings, the node
    # lists) are named outright.
    if not isinstance(cfg, dict):
        return [f"config.yml must be a mapping at the top level, not "
                f"{type(cfg).__name__} -- check the file's structure."]
    m = profile_yml.mapping
    errs: list[str] = []

    cluster = m(cfg.get("cluster"))
    size = cluster.get("size")
    if size not in _SIZES:
        errs.append(f"cluster.size must be small|medium|large (got {size!r}).")
    if cluster.get("auth", "key") not in ("key", "password"):
        errs.append("cluster.auth must be key|password.")
    if not cluster.get("name"):
        errs.append("cluster.name is missing.")

    net = m(cfg.get("network"))
    gw, nm = net.get("gateway"), net.get("netmask")
    nodes = m(cfg.get("nodes"))

    def _check_ips(group: str, entries: list) -> None:
        for n in entries:
            if not isinstance(n, dict):
                errs.append(f"{group}: an entry is not a mapping (got {n!r}).")
                continue
            ip = n.get("ip")
            if not valid_ip(ip):
                errs.append(f"{group}: invalid IP {ip!r} ({n.get('hostname')}).")
            elif gw and nm and not ip_in_subnet(ip, gw, nm):
                errs.append(f"{group}: {ip} is not in subnet {gw}/{nm}.")

    boot = m(nodes.get("bootstrap"))
    if boot:
        _check_ips("bootstrap", [boot])
    platform = nodes.get("platform") or []
    access_nodes = nodes.get("access") or []
    if not isinstance(platform, list):
        errs.append(f"nodes.platform must be a list of node entries, not "
                    f"{type(platform).__name__}.")
        platform = []
    if not isinstance(access_nodes, list):
        errs.append(f"nodes.access must be a list of node entries, not "
                    f"{type(access_nodes).__name__}.")
        access_nodes = []
    _check_ips("platform", platform)
    _check_ips("access", access_nodes)

    # Uniqueness and hostname format across ALL nodes. Both were claimed by the
    # dialog's validation line but never actually checked (Fable review H1): a
    # duplicated IP or an invalid hostname passed here and only surfaced in
    # phase 10/20, after the OVAs had been deployed. The bootstrap counts too --
    # it shares the subnet, and a collision with it is just as fatal.
    all_nodes = ([("bootstrap", boot)] if boot else []) \
        + [("platform", n) for n in platform] + [("access", n) for n in access_nodes]
    seen_ip: dict[str, str] = {}
    seen_host: dict[str, str] = {}
    for group, n in all_nodes:
        if not isinstance(n, dict):
            continue                      # already reported by _check_ips
        who = f"{group}/{n.get('hostname') or '?'}"
        ip = n.get("ip")
        if ip and ip in seen_ip:
            errs.append(f"duplicate IP {ip}: used by {seen_ip[ip]} and {who}.")
        elif ip:
            seen_ip[ip] = who
        host = (n.get("hostname") or "").strip()
        if not host:
            errs.append(f"{group}: a node has no hostname.")
            continue
        # Hostnames are used as VM names and as DNS labels -- same rule as the
        # tenant label (a-z, 0-9, '-'; no dots, no underscores, no uppercase).
        if not valid_label(host):
            errs.append(
                f"{group}: hostname {host!r} is not a valid DNS label "
                "(a-z, 0-9, '-', no dots/underscores/uppercase)."
            )
        if host in seen_host:
            errs.append(f"duplicate hostname {host!r}: used by {seen_host[host]} "
                        f"and {who}.")
        else:
            seen_host[host] = who

    if len(platform) != 3:
        errs.append(f"nodes.platform: exactly 3 expected (got {len(platform)}).")
    if size in _ACCESS_COUNT and len(access_nodes) != _ACCESS_COUNT[size]:
        errs.append(
            f"nodes.access: exactly {_ACCESS_COUNT[size]} expected for size={size} "
            f"(got {len(access_nodes)})."
        )

    acc = m(cfg.get("access"))
    if acc:
        if not acc.get("domain"):
            errs.append("access.domain is missing.")
        ft = m(acc.get("first_tenant"))
        if not valid_label(ft.get("tenant_name", "")):
            errs.append(
                f"access.first_tenant.tenant_name {ft.get('tenant_name')!r} is not a "
                "valid DNS label (a-z, 0-9, '-', no dots)."
            )
        for f in ("admin_user_name", "admin_first_name", "admin_last_name"):
            if not ft.get(f):
                errs.append(f"access.first_tenant.{f} is required.")
        if not valid_email(ft.get("admin_email", "")):
            errs.append(f"access.first_tenant.admin_email {ft.get('admin_email')!r} "
                        "is not a valid email.")
        try:
            access_profile.validate(acc)
        except ValueError as e:
            errs.append(str(e))

    lb = m(cfg.get("loadbalancer"))
    if lb.get("mode", "termination") not in ("termination", "passthrough"):
        errs.append("loadbalancer.mode must be termination|passthrough.")

    proxies = cfg.get("reverse_proxies") or []
    if not isinstance(proxies, list):
        errs.append(f"reverse_proxies must be a list of IPs, not "
                    f"{type(proxies).__name__}.")
        proxies = []
    for ip in proxies:
        if not valid_ip(ip):
            errs.append(f"reverse_proxies: invalid IP {ip!r}.")

    errs += _check_deployment_settings(cfg.get("deployment_settings") or {})
    return errs


def _check_deployment_settings(ops: dict) -> list[str]:
    """The optional profile.yml block. Absent is fine -- wrong is not.

    These land verbatim in a file wso parses on the bootstrap, so a bad value
    surfaces there, minutes into a deploy and far from its cause.
    """
    errs: list[str] = []
    if ops and not isinstance(ops, dict):
        return [f"deployment_settings must be a mapping, not "
                f"{type(ops).__name__} (e.g. a bare string is not valid)."]
    if not ops:
        return errs

    # NFS needs host AND path; one without the other configures nothing and
    # wso would still report "nfs backup server info is not set".
    host, path = ops.get("nfs_host"), ops.get("nfs_path")
    if bool(host) != bool(path):
        errs.append("deployment_settings: nfs_host and nfs_path must be set "
                    "together (one without the other configures no backup).")
    # The vendor's own example writes ":/controlplanenfs/us04pA". Copying that
    # colon costs an hour of silence: wso prepends one of its own, the mount
    # asks for an export that does not exist, and phase 70 dies on "permission
    # denied" (2026-07-28). A help text alone did not stop it -- this does.
    if path and str(path).startswith(":"):
        errs.append(
            f"deployment_settings.nfs_path must not start with a colon (got "
            f"{path!r}). wso adds its own, and the doubled '::' asks for an "
            f"export that does not exist. Write it plainly: "
            f"{str(path).lstrip(':')!r}. Omnissa's example file shows the "
            "colon; following it breaks the services deploy.")
    ver = ops.get("nfs_version")
    if ver and not (host and path):
        # A version with no target. Since the wizard field stopped defaulting to
        # "4", the only way to reach this is by typing a version into an
        # otherwise-empty NFS section -- an accidental entry that would still
        # make is_configured True and have phase 50 patch profile.yml for a
        # backup that does not exist. Caught here so `axs deploy` refuses it up
        # front instead of acting on it.
        errs.append("deployment_settings.nfs_version is set but there is no NFS "
                    "target -- add nfs_host and nfs_path, or clear the version.")
    elif ver and str(ver) not in ("3", "4"):
        errs.append(f"deployment_settings.nfs_version must be 3 or 4 (got {ver!r}).")

    if cidr := ops.get("bridge_network_subnet"):
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            errs.append(f"deployment_settings.bridge_network_subnet {cidr!r} is "
                        "not a CIDR (e.g. 10.90.0.0/24).")

    log = profile_yml.mapping(ops.get("logging"))
    for name in ("loki_server", "opensearch"):
        raw = log.get(name)
        if raw is not None and not isinstance(raw, dict):
            # `loki_server: http://loki:3100` instead of `loki_server:\n  url: ...`
            # -- the obvious shorthand to reach for, and `.get` on the string
            # took the validator down with it.
            errs.append(f"deployment_settings.logging.{name}: must be a mapping "
                        f"with a `url:` key, not {type(raw).__name__}.")
            continue
        b = raw or {}
        if b and not str(b.get("url") or "").strip():
            errs.append(f"deployment_settings.logging.{name}: url is required.")
    servers = log.get("syslog_servers")
    if servers is not None and not isinstance(servers, list):
        # `syslog_servers: {host: log1}` -- a forgotten `-`. Every access below
        # used to raise (`servers[:2]` on a dict gives
        # `KeyError: slice(None, 2, None)`), so the validator whose whole job is
        # naming this died on it, with a traceback that never mentions syslog.
        errs.append("deployment_settings.logging.syslog_servers: must be a LIST "
                    "of entries (`- host: ...`), not "
                    f"{type(servers).__name__}.")
        return errs
    servers = servers or []
    # The vendor template states "maximum two list entries" -- a third would be
    # dropped silently, so say so instead.
    if len(servers) > 2:
        errs.append(f"deployment_settings.logging.syslog_servers: at most 2 "
                    f"allowed (got {len(servers)}).")
    for i, s in enumerate(servers[:2], start=1):
        if not isinstance(s, dict):
            # `- log1.example.com` instead of `- host: log1.example.com` is an
            # entirely natural thing to write, and every `.get` below used to
            # raise AttributeError on it -- so the validator whose job is to
            # name the mistake died on it instead, with a traceback and no
            # mention of syslog. Same shape reached phase 50's done-probe
            # through profile_yml.is_configured, where the TUI reads any
            # exception as "not done" and runs the phase against a live cluster.
            errs.append(f"logging.syslog_servers[{i}]: must be a mapping with a "
                        f"`host:` key (got {s!r}).")
            continue
        if not str(s.get("host") or "").strip():
            # Stripped: a whitespace-only host passed here and was written out
            # to wso as a real entry, while both comparison sides skipped it --
            # so nothing ever reported the nonsense this tool had handed over.
            errs.append(f"logging.syslog_servers[{i}]: host is required.")
        if s.get("protocol") not in (None, "udp", "tcp", "tls"):
            errs.append(f"logging.syslog_servers[{i}]: protocol must be "
                        f"udp|tcp|tls (got {s['protocol']!r}).")
        port = s.get("port", 514)
        if not str(port).isdigit() or not 1 <= int(port) <= 65535:
            errs.append(f"logging.syslog_servers[{i}]: port {port!r} is not a "
                        "valid port number.")
    return errs
