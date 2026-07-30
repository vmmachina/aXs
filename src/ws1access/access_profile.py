"""Generate access-profile.yml -- input to `wso access bootstrap` (phase 70).

Follows the field structure and the documented choices of the Omnissa install
guide's access-profile.yml section verbatim (fqdn / server_certificate /
first_tenant / cert_proxy / ip_ignore_list_for_xff_header / smtp). Every
customer-variable value comes from config -- nothing is assumed:

  * server_certificate.is_self_signed: false -> custom_cert_file/keyfile required
    (doc: place cert at /root/<cluster>/access/certs/). true -> LB terminates,
    no cert here (the lab's topology, one valid case among the documented ones).
  * cert_proxy.ssl_certificate_type: FQDN_CERT reuses the FQDN cert; CUSTOM_CERT
    needs its own path/key.
  * ip_ignore_list_for_xff_header: doc requires the LB plus every node between
    client and access (proxies + access nodes), minimum the LB.

The first_tenant.* fields are all mandatory per the doc.
"""

from __future__ import annotations

import yaml


def validate(access: dict) -> None:
    """Fail fast on cert-topology inconsistencies before phase 70.

    Caught here instead of 40 minutes into `wso services deploy`.
    """
    sc = access.get("server_certificate", {})
    # Default is self-signed (LB terminates) -- the safe default that needs no
    # cert here. Only a custom cert requires the file paths.
    if sc.get("is_self_signed", True) is False:
        if not sc.get("custom_cert_file") or not sc.get("custom_cert_keyfile"):
            raise ValueError(
                "server_certificate.is_self_signed=false requires custom_cert_file "
                "and custom_cert_keyfile (place them under access/certs/)."
            )
    cp = access.get("cert_proxy", {})
    if cp.get("enabled") and cp.get("ssl_certificate_type") == "CUSTOM_CERT":
        if not cp.get("ssl_certificate_path") or not cp.get("ssl_certificate_key"):
            raise ValueError(
                "cert_proxy CUSTOM_CERT requires ssl_certificate_path and "
                "ssl_certificate_key."
            )


def render(access: dict, *, ip_ignore: list[str]) -> str:
    """Build access-profile.yml from the config's `access` section.

    `access` mirrors the doc's fields; `ip_ignore` is the already-derived XFF
    ignore list (LB + non-bootstrap nodes + reverse proxies).
    """
    validate(access)
    sc = access.get("server_certificate", {})
    cp = access.get("cert_proxy", {})
    smtp = access.get("smtp", {})
    ft = access["first_tenant"]

    profile = {
        "fqdn": {
            "name": access["domain"],
            "port": access.get("port", 443),
            "ip": access["lb_ip"],
        },
        "server_certificate": {
            "is_self_signed": sc.get("is_self_signed", True),
            "custom_cert_file": sc.get("custom_cert_file"),
            "custom_cert_keyfile": sc.get("custom_cert_keyfile"),
        },
        "first_tenant": {
            "tenant_name": ft["tenant_name"],
            "admin_user_name": ft["admin_user_name"],
            "admin_email": ft["admin_email"],
            "admin_first_name": ft["admin_first_name"],
            "admin_last_name": ft["admin_last_name"],
        },
        "cert_proxy": {
            "enabled": cp.get("enabled", False),
            "ssl_certificate_type": cp.get("ssl_certificate_type", "FQDN_CERT"),
            "ssl_certificate_path": cp.get("ssl_certificate_path"),
            "ssl_certificate_key": cp.get("ssl_certificate_key"),
        },
        "ip_ignore_list_for_xff_header": ip_ignore,
        "smtp": {
            "enabled": smtp.get("enabled", False),
            "host": smtp.get("host"),
            "port": smtp.get("port", 587),
            "user": smtp.get("user"),
            "security_type": smtp.get("security_type"),
        },
    }
    return yaml.safe_dump(profile, sort_keys=False, default_flow_style=False)
