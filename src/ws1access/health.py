"""Doc-anchored health/readiness gates for aXs (phases 60/70).

Two wso commands are the authoritative acceptance gates. Their behaviour was
verified at the lab (2026-07-23) on a healthy cluster:

  * `wso access check-service-readiness` -- prints JSON `{service: "READY"|...}`
    directly (there is NO `-f json` flag; the plain output is already JSON),
    rc=0 when healthy. We PARSE the JSON rather than trust the exit code
    (rc semantics on NOT_READY are unverified).
  * `wso healthcheck -f json` -- a "Checking ... done" text prefix followed by a
    JSON object {vault, consul, nomad, services}; each member carries `healthy`
    and vault additionally `sealed`. rc=0 when healthy.

Why BOTH: check-service-readiness lists only the ~20 Access services, NOT the
~30 infrastructure services (postgres, kafka, redis, opensearch, ingress,
backups, logging, ...). healthcheck covers the platform tier. The docs pair the
two commands consistently, so phase-70 acceptance requires both green.
"""

from __future__ import annotations

import json

# The Access core services (Omnissa doc p.24 + the lab readiness output). Every
# one must be present in the output AND "READY". A MISSING key means the service
# was never deployed (e.g. wso aborted early) -> critical, not a pass.
ACCESS_CORE = frozenset({
    "cds", "acs", "saas", "crypto", "token", "ws1notifications", "ws1ntfmanager",
    "federation", "analytics", "authcontrol", "skycap", "greenbox", "cas",
    "certproxy", "commchannel", "ws1admin", "mpsso", "hubconsole", "usergroup",
    "launcher",
})

# Services allowed to fail WITHOUT blocking a functional Access deploy -- an
# EXPLICIT allowlist, never the complement (Fable review: backup/ingress/db are
# data-path/-safety and must stay critical). Doc: logging/NTP/NFS "not mandatory".
# Substring match so `control-plane-logging`, `telegraf-statsd`, ... are covered.
ADVISORY_SUBSTR = ("logging", "telegraf", "monitoring")


def is_advisory(service_name: str) -> bool:
    n = service_name.lower()
    return any(s in n for s in ADVISORY_SUBSTR)


def _load_json(text: str) -> dict | None:
    """The first complete JSON object in `text`, or None.

    wso's answer is never alone on the wire, and MEASURED on the lab cluster
    2026-07-29 the noise is not where it looks:

        stdout:  {"vault":{"reachable":true, ...     the answer
        stderr:  Checking Vault ......done ...       wso's own progress

    `run_with_key` returns stdout + stderr CONCATENATED, so on the key path the
    JSON comes first and the progress lines land AFTER it. `json.loads` on
    everything-from-the-first-brace then fails with "Extra data: line 2
    column 1", every single time -- a healthy cluster reported as unreadable,
    permanently, for anyone who has a key to the bootstrap.

    The pty path escapes it because ssh writes both channels to the one
    terminal as they arrive, so the progress lines -- printed while the work
    happens -- come first and the JSON last. That also makes the intermittent
    failure that started this hunt plausible for the first time: two channels,
    usually in order, occasionally not. Plausible, still not proven.

    So: decode ONE object and ignore whatever follows. Candidate braces are
    tried in order, because a stray '{' in a banner would otherwise poison the
    only attempt.

    Known limit, stated because it is a real trade: if wso ever printed a
    COMPLETE JSON object before its answer, that decoy would win. The old code
    called such output unreadable, which is less useful but not wrong. No such
    output has been seen; a test records the behaviour either way.
    """
    decoder = json.JSONDecoder()
    limit = len(text.rstrip())
    start = text.find("{")
    while start >= 0:
        try:
            value, _end = decoder.raw_decode(text, start)
        except RecursionError:
            # Deeply nested input. The old code caught this with a bare
            # `except Exception`; narrowing to ValueError let it escape a
            # done-probe, and an exception there is read as "not done".
            return None
        except ValueError as exc:
            # A parse that runs out of input at the very END means the answer
            # was CUT OFF, not that this brace was noise. Moving on to the
            # next candidate would then decode the first inner object -- and a
            # connection dropped mid-answer would be reported as
            # "vault: unreachable" about a reachable Vault, instead of as the
            # transport failure it is. Measured, Fable review.
            if getattr(exc, "pos", -1) >= limit:
                return None
        else:
            if isinstance(value, dict):
                return value
        start = text.find("{", start + 1)
    return None


# Carried in the problem list when the answer could not be read at all. The
# CALLER turns it into something diagnosable -- see unreadable_message. Keeping
# it a marker rather than a sentence is what lets p60 and p70 recognise it.
UNREADABLE_HEALTHCHECK = "<unparseable healthcheck output>"


def unreadable_message(rc: int, redacted: str) -> str:
    """What to show instead of the bare marker.

    "I could not read it" was all the operator got -- for four different
    causes. The ssh exit code alone separates them: 255 with a connection
    message is transport, non-zero with wso's own words is wso, and 0 with
    something unexpected is the answer having changed shape. docs/08 A9 made
    exactly this fix for check-service-readiness and it was never carried
    here, in either phase that asks.
    """
    tail = (redacted or "").strip()
    if not tail:
        return (f"could not read `wso healthcheck -f json` (ssh rc {rc}); "
                "it answered nothing at all")
    return (f"could not read `wso healthcheck -f json` (ssh rc {rc}); "
            f"it answered: {tail[-200:]}")


# Returned in `missing` when the output could not be read at all. Callers MUST
# distinguish it from real service names: "I could not read the answer" and
# "these services do not exist" are different diagnoses, and reporting the first
# as the second sends the operator hunting for services that may be fine.
UNREADABLE = "<unparseable check-service-readiness output>"


def parse_readiness(text: str) -> tuple[bool, list[str], list[str]]:
    """Returns (ok, not_ready, missing).

    ok = every ACCESS_CORE key is present and READY, and every other listed key
    is READY too (an unknown listed service that is NOT_READY is still critical
    -- the doc says 'each service' must be READY).

    On unreadable output, `missing` is exactly [UNREADABLE] -- see the note there.
    """
    data = _load_json(text)
    if data is None:
        return (False, [], [UNREADABLE])
    not_ready = sorted(k for k, v in data.items() if str(v).upper() != "READY")
    missing = sorted(k for k in ACCESS_CORE if k not in data)
    return (not not_ready and not missing, not_ready, missing)


def parse_healthcheck(text: str, *, include_services: bool = True
                      ) -> tuple[bool, list[str]]:
    """Returns (ok, problems). Checks vault/consul/nomad reachable, every member
    healthy, vault not sealed, and -- unless include_services is False --
    services.Result empty.

    Phase 60 owns the PLATFORM (Vault/Consul/Nomad); the services belong to
    phase 70. Folding both into one verdict made phase 60's done-probe flip
    back to "todo" whenever a service was mid-deploy, and a restart then
    launched `wso cp deploy` alongside a running `wso services deploy`.
    Observed live 2026-07-28 13:18. So phase 60 asks with include_services
    False, and answers a question it can actually answer.
    """
    d = _load_json(text)
    if d is None:
        return (False, [UNREADABLE_HEALTHCHECK])
    problems: list[str] = []
    for comp in ("vault", "consul", "nomad"):
        c = d.get(comp) or {}
        if not c.get("reachable", False):
            problems.append(f"{comp}: unreachable ({c.get('error') or 'no detail'})")
            continue
        for group in ("servers", "clients"):
            for m in (c.get(group) or []):
                name = m.get("name", "?")
                if not m.get("healthy", False):
                    problems.append(f"{comp}/{name}: unhealthy")
                if (m.get("additional") or {}).get("sealed"):
                    problems.append(f"{comp}/{name}: SEALED (needs `wso cp unseal`)")
    if include_services:
        for s in ((d.get("services") or {}).get("Result") or []):
            problems.append(f"service issue: {s}")
    return (not problems, problems)


def sealed_detected(healthcheck_text: str) -> bool:
    """True if any Vault member reports sealed -- triggers the unseal repair."""
    _, problems = parse_healthcheck(healthcheck_text)
    return any("SEALED" in p for p in problems)
