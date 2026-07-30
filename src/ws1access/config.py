"""Load a cluster's config.yml and turn it into a Context.

Config lives at clusters/<cluster>/config.yml. It never contains secrets: the
vCenter and configuser passwords -- and the logging backend passwords, if any --
are supplied by the caller (the TUI hands them in directly) or, if not, prompted
at runtime with getpass. They are NEVER read from the environment and never
written to this machine's disk; they live only as in-process values and are
passed only to the processes that need them.

Where they DO leave the process, both unavoidable and both stated on the
credentials screen: ovftool takes the vCenter password (and the appliance
passwords, as OVF properties) on its local command line during phase 10, and
the vendor's own file formats want plain text ON THE BOOTSTRAP -- cp-cluster.ini
with cluster.auth 'password', profile.yml for a logging backend.
"""

from __future__ import annotations

import getpass
from pathlib import Path

import yaml

from .context import Context


def config_path(cluster: str) -> Path:
    return Path("clusters") / cluster / "config.yml"


def load(cluster: str) -> dict:
    path = config_path(cluster)
    if not path.exists():
        raise FileNotFoundError(
            f"No config for cluster {cluster!r} (looked in {path}).\n"
            f"Run 'axs configure -c {cluster}' or copy config.example.yml there."
        )
    return yaml.safe_load(path.read_text())


def configuser_password() -> str:
    return getpass.getpass("configuser password: ")


def context(cluster: str, *, password: str | None = None,
            vc_password: str | None = None,
            logging_passwords: dict | None = None) -> Context:
    cfg = load(cluster)
    nodes = cfg["nodes"]

    # Logging backend passwords are not in config.yml by design (see
    # configure._deployment_settings). Collect them here if the caller did not:
    # that covers the plain CLI path, where getpass is the right thing. The TUI
    # passes them in and never reaches this branch.
    ops = cfg.get("deployment_settings", {}) or {}
    logging_passwords = dict(logging_passwords or {})
    from . import profile_yml
    for name in profile_yml.needs_passwords(ops):
        if not logging_passwords.get(name):
            user = ((ops.get("logging") or {}).get(name) or {}).get("username", "?")
            logging_passwords[name] = getpass.getpass(
                f"{name} password for user {user}: ")

    vc = dict(cfg.get("vcenter", {}))
    if vc:
        # Supplied by the caller (TUI) or prompted at runtime; never stored,
        # never from the environment.
        vc["password"] = (vc_password if vc_password is not None
                          else getpass.getpass("vCenter password: "))

    all_nodes = [{**nodes["bootstrap"], "role": "bootstrap"}]
    all_nodes += [{**n, "role": "platform"} for n in nodes.get("platform", [])]
    all_nodes += [{**n, "role": "access"} for n in nodes.get("access", [])]

    return Context(
        bootstrap_ip=nodes["bootstrap"]["ip"],
        cluster_name=cfg["cluster"]["name"],
        local_name=cluster,
        deployment_settings=cfg.get("deployment_settings", {}) or {},
        logging_passwords=logging_passwords,
        configuser_password=password if password is not None else configuser_password(),
        bundle_path=cfg.get("assets", {}).get("bundle", ""),
        size=cfg["cluster"]["size"],
        auth=cfg["cluster"].get("auth", "key"),
        platform_ips=[n["ip"] for n in nodes.get("platform", [])],
        access_ips=[n["ip"] for n in nodes.get("access", [])],
        access=cfg.get("access", {}),
        vcenter=vc,
        ova_path=cfg.get("ova", {}).get("path", ""),
        nodes=all_nodes,
        network=cfg.get("network", {}),
        loadbalancer=cfg.get("loadbalancer", {}),
        reverse_proxies=cfg.get("reverse_proxies", []) or [],
    )
