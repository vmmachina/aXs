"""Generate cp-cluster.ini -- the Ansible inventory wso uses for the cluster.

This reproduces the output of Omnissa's own `update-cluster-ini.sh`, whose real
lab output is captured in reference/cp-cluster.ini.example and is the
authoritative template. The mapping is by ROLE, not by size, so it holds for
small/medium/large; only the node lists (from config) change.

Two orderings are deliberate and copied from the reference, not invented:

  * [linux:children] lists the groups in one order;
  * the group sections appear in a *different* order below it;
  * consul/vault/nomad list access nodes first, then platform.

The bootstrap node is never listed (validation rejects it if present).

Auth: the reference lab used ansible_password; by design (architecture note) the
tool uses the key path -- ansible_ssh_private_key_file, populated by the
ssh-copy-id step in phase 50.

VERIFIED: small (3 platform + 2 access) is byte-identical to the reference's
group sections. medium/large use the same role rules; asset_server ("one or two"
platform) should be checked once against update-cluster-ini.sh before a real
medium/large rollout -- see docs/06-pruefpunkte.md.
"""

from __future__ import annotations

# Order of the [linux:children] block (exactly as the reference lists it).
_CHILDREN = [
    "asset_server_linux",
    "consul_server_linux",
    "general_compute_linux",
    "kafka_server_linux",
    "nomad_server_linux",
    "opensearch_leader_linux",
    "opensearch_data_linux",
    "postgres_linux",
    "vault_server_linux",
    "general_compute_access_linux",
    "general_compute_nginx_http",
]

# Order in which the group sections are written (differs from _CHILDREN above).
_SECTION_ORDER = [
    "asset_server_linux",
    "consul_server_linux",
    "vault_server_linux",
    "nomad_server_linux",
    "kafka_server_linux",
    "postgres_linux",
    "opensearch_leader_linux",
    "opensearch_data_linux",
    "general_compute_linux",
    "general_compute_access_linux",
    "general_compute_nginx_http",
]


def _groups(platform: list[str], access: list[str]) -> dict[str, list[str]]:
    all_nodes = access + platform          # access first, then platform
    asset = platform[-2:]                  # "two of the platform nodes"
    infra = platform                       # kafka/postgres/opensearch/general_compute
    return {
        "asset_server_linux": asset,
        "consul_server_linux": all_nodes,
        "vault_server_linux": all_nodes,
        "nomad_server_linux": all_nodes,
        "kafka_server_linux": infra,
        "postgres_linux": infra,
        "opensearch_leader_linux": infra,
        "opensearch_data_linux": infra,
        "general_compute_linux": infra,
        "general_compute_access_linux": access,
        "general_compute_nginx_http": access,
    }


def render(
    platform: list[str],
    access: list[str],
    *,
    size: str,
    password: str | None = None,
    private_key_path: str | None = None,
) -> str:
    """Build the cp-cluster.ini text. Pure -- writes nothing.

    Auth: the lab / reference (and the user's real deployments) use
    ansible_password -- the key path breaks on the nodes' SSH login banner
    ("Authorized users only ..."), which wso's containerized ansible reads as a
    connection failure. Pass `password` for that (default, real-world) path;
    `private_key_path` remains available for banner-free environments.
    """
    groups = _groups(platform, access)

    lines = ["[linux:children]"]
    lines += _CHILDREN
    lines += ["", f"# Deployment size: {size}", ""]

    for name in _SECTION_ORDER:
        lines.append(f"[{name}]")
        lines += groups[name]
        lines.append("")

    lines.append("[linux:vars]")
    lines.append("ansible_user=configuser")
    if password is not None:
        lines.append(f"ansible_password={password}")
        lines.append("#ansible_ssh_private_key_file=")
    elif private_key_path:
        lines.append(f"ansible_ssh_private_key_file={private_key_path}")
    else:
        lines.append("#ansible_ssh_private_key_file=")
    return "\n".join(lines) + "\n"
