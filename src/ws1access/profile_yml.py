"""Patch `profile.yml` -- the cluster's operational settings (phase 50).

`wso access init` creates this file itself, fully commented out, with the four
keys it filled in (cluster_name, datacenter_name, deployment_size, product) and
a long block of documentation for everything else. See
reference/profile.yml.example for the verbatim template.

So this module does NOT render the file the way cluster_ini.py and
access_profile.py render theirs. It PATCHES: read what wso wrote, change only
the keys the operator actually set, leave the rest -- comments, unknown keys, a
future release's new entries -- exactly as found. Two reasons:

  * the four keys wso fills in are not ours to touch, and
  * the comments in that file are the operator's own reference; regenerating
    the file would silently delete them.

Everything here is optional. A cluster deployed with none of it is regular --
the lab ran green that way (docs/07). But `wso cp deploy` prints two warnings
about it, and they are not equal in weight (verbatim, cp-deploy.log):

    NTP server is not set ... For production deployments, NTP server is highly
    recommended to prevent time drift.
    NFS configuration is not present ... For production deployments, NFS is
    required for disaster recovery.

NTP is *recommended*; NFS is *required for disaster recovery*. And logging has
a deadline rather than a recommendation: per the template's own comment,
changing it after the first deployment "would require a full
redeployment/upgrade of the cluster to take effect".
"""

from __future__ import annotations

import re

import yaml

# The scalar keys, in the order the template lists them. Each appears in the
# file as a commented sample line ("#ntp_server: us.pool.ntp.org"), which is
# what gets replaced when a value is configured.
SCALARS = ("ntp_server", "nfs_host", "nfs_path", "nfs_version",
           "bridge_network_subnet")

_MARK = "# ---- set by aXs ----"


# nfs_version is a number in the vendor's own example ("nfs_version: 4"), so it
# is emitted as one -- quoting it would hand wso a string where it wrote an int.
_NUMERIC = ("nfs_version",)


def _scalar_line(key: str, value: object) -> str:
    """One `key: value` line, quoted the way YAML needs it.

    nfs_path is the reason this is not just an f-string: the vendor's own
    example is ":/controlplanenfs/us04pA" -- a leading colon, which bare YAML
    would read as a mapping. Anything that could be mistaken for YAML syntax
    gets quoted; a hostname or CIDR does not need it and reads better without.
    """
    s = str(value).strip()
    if key in _NUMERIC and s.isdigit():
        return f"{key}: {int(s)}"
    # Let PyYAML decide on quoting and escaping. Hand-rolled quotes broke on a
    # value that contained a double quote of its own -- it produced
    # `nfs_path: ":/exp/"quoted""`, which is not YAML at all, and the damage
    # only surfaced when wso read the file.
    return yaml.safe_dump({key: s}, default_flow_style=False,
                          width=10 ** 6, allow_unicode=True).strip()


def _set_scalar(lines: list[str], key: str, value: object) -> list[str]:
    """Replace the template's commented sample line for `key`, or append.

    In-place is preferred: the result reads like a file a person edited, and
    the key keeps its documented position. If the template ever stops shipping
    that line, the value is appended instead so nothing is silently dropped.

    A LATER uncommented duplicate of the same key is dropped, and that is not
    tidiness. YAML resolves a duplicate key to the LAST occurrence, so writing
    only the first one left the file parsing to the operator's old value: the
    comparison kept reporting drift, phase 50 kept patching, and -- since the
    phase now verifies its own write -- it would fail on every single run with
    the change apparently applied. Commented duplicates are kept; they are the
    template's documentation and YAML never reads them.

    TOP-LEVEL lines only -- no leading whitespace. These keys all live at the
    root of profile.yml, and matching indented lines meant an unrelated nested
    key of the same name was in scope: `custom_block:\\n  ntp_server: 1.2.3.4`
    had its inner line silently DELETED by the duplicate rule above (a
    regression the duplicate fix introduced), and replacing an indented line
    instead produced a file that no longer parses at all. Neither is a
    duplicate of anything -- a different path is a different key.
    """
    # The optional spaces belong INSIDE the comment group, not in front of the
    # key: `^#?[ \t]*` still matched `  ntp_server:` whenever the `#` was absent,
    # so the first attempt at this fix changed nothing at all. Either the key
    # starts at column 0, or a `#` does and the key follows it.
    pat = re.compile(rf"^(?:#[ \t]*)?{re.escape(key)}[ \t]*:.*$")
    live = re.compile(rf"^{re.escape(key)}[ \t]*:.*$")
    out, replaced = [], False
    for ln in lines:
        if pat.match(ln):
            if not replaced:
                out.append(_scalar_line(key, value))
                replaced = True
                continue
            if live.match(ln):
                continue        # a duplicate that YAML would prefer over ours
        out.append(ln)
    if not replaced:
        out.append(_scalar_line(key, value))
    return out


def mapping(value: object) -> dict:
    """`value` if it is a mapping, an empty one otherwise.

    `logging: enabled` in config.yml is a plausible hand-edit, and the usual
    `... or {}` does NOT catch it: a non-empty string is truthy, so it sailed
    through and the next `.get` raised AttributeError. That reached
    `needs_passwords`, which runs at every deploy start, and phase 50's
    done-probe -- where the TUI reads any exception as "not done" and runs the
    phase against a healthy cluster.
    """
    return value if isinstance(value, dict) else {}


def syslog_entries(logging: object) -> list[dict]:
    """The syslog entries to act on, out of whatever the operator wrote.

    One helper for every caller -- writer, comparison, summary, validator,
    configure wizard -- because the alternative is five near-copies of the same
    defensive code, and this project's signature defect is the one that gets
    fixed in four of them. The first attempt at exactly this guarded the
    individual ENTRY in three places and left the CONTAINER unguarded in all
    five.

    Two one-character mistakes have to survive here:
      * `syslog_servers: {host: log1}` -- a forgotten `-`. That is a dict, not a
        list, and `servers[:2]` on a dict raises `KeyError: slice(None, 2, None)`.
      * `- log1.example.com` instead of `- host: log1.example.com`. A string,
        and `.get` on it raises AttributeError.

    Sliced to two BEFORE the invalid entries are dropped, which is what
    `validate_config` reports on -- so the writer and the comparison agree about
    which entries exist even when one of them is junk.
    """
    servers = mapping(logging).get("syslog_servers")
    if not isinstance(servers, list):
        return []
    return [s for s in servers[:2] if isinstance(s, dict)]


def _port(value: object) -> int | None:
    """A port as an int, or None when the value is not one.

    Shared by the writer and the comparison so the two cannot disagree about
    what a given entry means -- a difference there would show up as drift
    against aXs's own output.
    """
    s = str(value).strip()
    return int(s) if s.isdigit() else None


def _logging_block(logging: dict) -> str:
    """The `logging:` mapping, rendered by PyYAML rather than by hand.

    Only the backends that carry values are emitted -- an empty `loki_server:`
    would look configured to wso while carrying nothing. Syslog is capped at
    two entries because the template says "maximum two list entries".
    """
    out: dict = {}
    logging = mapping(logging)
    for name in ("loki_server", "opensearch"):
        # password_prompt is aXs bookkeeping ("ask at deploy time"), not a wso
        # field -- it must never reach the file.
        block = {k: v for k, v in mapping(logging.get(name)).items()
                 if v not in (None, "") and k != "password_prompt"}
        # A backend without a url is not a backend. A hand-edited config.yml
        # carrying only a password used to produce `loki_server: {password: ...}`,
        # which looks configured to wso and points nowhere.
        if block.get("url"):
            out[name] = block
    servers = []
    for s in syslog_entries(logging):
        # Stripped before the truthiness test, and the same on both comparison
        # sides: `host: " "` used to be written out to wso as a real entry while
        # both flatten sides skipped it, so nothing ever reported the nonsense
        # this tool had handed over.
        if str(s.get("host") or "").strip():
            entry = {"host": str(s["host"]).strip(),
                     "protocol": s.get("protocol", "udp")}
            # A port that is not a number used to raise a bare ValueError out
            # of here -- and `is_configured` calls this, so the crash reached
            # phase 50's done-probe, where the TUI reads any exception as "not
            # done" and runs the phase against a healthy cluster. Omitted
            # rather than replaced with 514: inventing a value the operator did
            # not write is how a config becomes untraceable, and
            # validate_config already rejects the bad one by name.
            if (port := _port(s.get("port", 514))) is not None:
                entry["port"] = port
            servers.append(entry)
    if servers:
        out["syslog_servers"] = servers
    if logging.get("syslog_cert_passphrase"):
        out["syslog_cert_passphrase"] = logging["syslog_cert_passphrase"]
    if not out:
        return ""
    body = yaml.safe_dump({"logging": out}, sort_keys=False, default_flow_style=False)
    return body.rstrip("\n")


def needs_passwords(settings: dict | None) -> list[str]:
    """Which logging backends were configured with a user but no password.

    The password is deliberately not in config.yml (see configure.py). The
    deploy asks for it and hands it back through `with_passwords`.
    """
    log = mapping(mapping(settings).get("logging"))
    return [name for name in ("loki_server", "opensearch")
            if mapping(log.get(name)).get("password_prompt")]


def with_passwords(settings: dict, passwords: dict[str, str]) -> dict:
    """A copy of `settings` with the prompted passwords filled in.

    Returns a copy on purpose: the originals stay in the Context free of
    secrets, so anything that logs or reports them cannot leak one.
    """
    import copy
    out = copy.deepcopy(settings or {})
    log = mapping(out.get("logging"))
    for name, pw in (passwords or {}).items():
        block = log.get(name)
        if isinstance(block, dict) and pw:
            block.pop("password_prompt", None)
            block["password"] = pw
    return out


def is_configured(settings: dict | None) -> bool:
    """Did the operator set anything at all? If not, the file is left alone."""
    if not settings:
        return False
    if any(str(settings.get(k) or "").strip() for k in SCALARS):
        return True
    return bool(_logging_block(settings.get("logging")))


def patch(text: str, settings: dict) -> str:
    """Return `text` with the configured settings applied. Pure -- no I/O.

    Unset keys are not touched, so they stay commented out and wso keeps its
    defaults, which is exactly the behaviour of a deployment that never used
    this feature.
    """
    lines = text.splitlines()

    # ORDER MATTERS. Cut the previous aXs block FIRST, then patch the scalars.
    # The other way round, a scalar appended at the end (the fallback path when
    # the template has no sample line for it) landed BEHIND the old block and
    # was removed again by the cut -- the value vanished without a word.
    lines = _drop_block(lines)

    for key in SCALARS:
        value = str(settings.get(key) or "").strip()
        if value:
            lines = _set_scalar(lines, key, value)

    block = _logging_block(settings.get("logging") or {})
    if block:
        lines += ["", _MARK, block]
    return "\n".join(lines) + "\n"


def _drop_block(lines: list[str]) -> list[str]:
    """Remove a previously written aXs block, and nothing else.

    Two ways this used to go wrong, both destructive:

      * the presence test was a substring match while the cut needed an exact
        line, so editing the marker at all ("... (do not remove)") raised
        ValueError and phase 50 died on a bare traceback;
      * the cut removed everything from the marker to the end of the file. With
        the marker moved up -- by a person tidying the file -- that deleted
        wso's own keys, the very ones this module promises not to touch.

    So: match the marker exactly, and refuse to cut if the remainder still
    contains a top-level key. Better to leave a stale block (wso reads the last
    duplicate) than to shred the file.
    """
    idx = next((i for i, ln in enumerate(lines) if ln.strip() == _MARK), None)
    if idx is None:
        return lines
    tail = lines[idx + 1:]
    # Our block is a single `logging:` mapping. Anything else below the marker
    # is not ours, so the marker is not where we put it -- leave it all alone.
    keys = [ln for ln in tail
            if ln[:1] not in ("", "#", " ", "\t") and ":" in ln]
    if any(not ln.startswith("logging:") for ln in keys):
        return lines
    out = lines[:idx]
    while out and not out[-1].strip():
        out.pop()
    return out


# Returned by `drift` when the remote file could not be parsed. Callers MUST
# keep it apart from a real difference: "I could not read the file" and "the
# file disagrees" are different diagnoses, and phase 70 already paid for
# reporting the first as the second (docs/08 A9).
UNREADABLE = "<could not parse profile.yml on the bootstrap>"

# Never compared, never printed. Dropping them costs one thing, knowingly: a
# change that is ONLY a password is invisible to this check (docs/09 §5.2).
# The alternative is a comparison that handles secrets, and therefore one that
# can print them.
# Matched as SUBSTRINGS of the key name, lowercased -- `admin_password`,
# `syslog_cert_passphrase` and a future `api_secret` all have to be caught, and
# an exact list would have printed the first two.
_SECRET_KEYS = ("password", "passphrase", "secret", "token", "api_key")


def _scalar(value: object) -> str:
    """One value, normalised so both sides can be compared as text.

    Numbers go through int() when they look like one, because wso writes
    `nfs_version: 4` while config.yml may carry "4" -- and, less obviously,
    "04": _scalar_line emits that as `4`, so comparing the raw strings reported
    drift against aXs's OWN output on every run.
    """
    s = str(value).strip()
    if s.lstrip("+-").isdigit():
        return str(int(s))
    return s


def _flatten_logging(logging: object) -> dict[str, str]:
    """The logging block as dotted key -> value, secrets removed.

    Defensive about shape throughout: this reads a file a person can edit on
    the bootstrap. `logging: enabled` or `port: default` used to raise out of
    here, and an exception from a done-probe is not a warning -- the TUI reads
    it as "phase not done" and RUNS phase 50 against a healthy cluster, while
    the plain path dies on a traceback. Anything unshaped is skipped, and the
    key simply does not take part in the comparison.
    """
    out: dict[str, str] = {}
    logging = mapping(logging)
    for name in ("loki_server", "opensearch"):
        block = mapping(logging.get(name))
        if not block:
            continue
        # Same rule as _logging_block: no url, no backend. Otherwise a stray
        # `user:` on one side would read as a configured backend on the other.
        if not str(block.get("url") or "").strip():
            continue
        for key, value in block.items():
            # Secrets are matched by SUBSTRING, not equality. `admin_password`
            # and a nested `auth: {password: ...}` both carry one, and a
            # comparison that prints them is exactly what this rule exists to
            # prevent. A dict or list value is dropped for the same reason: it
            # could carry a secret under any key name at all.
            if _is_secret(key) or isinstance(value, (dict, list)):
                continue
            if value in (None, ""):
                continue
            out[f"logging.{name}.{key}"] = _scalar(value)
    # Numbered by the position in the WRITTEN list, not in the configured one.
    # `_logging_block` skips entries without a host and writes the next one at
    # index 0; counting the original position here made a config whose first
    # entry lacks a host compare `syslog_servers[1].*` against a file that has
    # `syslog_servers[0].*` -- three differences on both sides of aXs's own
    # output, so `drift` reported them on every single run and no amount of
    # patching could clear them. The two sides have to enumerate the same way.
    written = 0
    for server in syslog_entries(logging):
        host = str(server.get("host") or "").strip()
        if not host:
            continue
        out[f"logging.syslog_servers[{written}].host"] = host
        out[f"logging.syslog_servers[{written}].protocol"] = str(
            server.get("protocol", "udp")).strip()
        # Omitted when it is not a number -- exactly what _logging_block
        # writes, so an unparseable port is not reported as a difference
        # between the two sides that both dropped it.
        if (port := _port(server.get("port", 514))) is not None:
            out[f"logging.syslog_servers[{written}].port"] = str(port)
        written += 1
    return out


def _is_secret(key: str) -> bool:
    k = str(key).lower()
    return any(s in k for s in _SECRET_KEYS)


def _flatten(settings: dict) -> dict[str, str]:
    """The keys aXs owns, as dotted key -> normalised string."""
    out = {key: _scalar(settings.get(key))
           for key in SCALARS
           if str(settings.get(key) or "").strip()}
    out.update(_flatten_logging(settings.get("logging")))
    return out


def drift(remote_text: str, settings: dict) -> list[str]:
    """What the bootstrap's profile.yml says versus what config.yml asks for.

    Semantic, per key, over ONLY the keys aXs owns -- not a byte diff. Comments,
    wso's own four keys, formatting and any key a future release adds are
    invisible here, which is what makes the answer usable rather than always
    positive.

    Why this exists: phase 50's done-probe asks `wso access validate`, which
    validates the files from the LAST run. An operator who adds an NFS target
    after a successful deploy -- exactly what wso's own warning asks for -- gets
    "already done", profile.yml is never patched, phase 60 is green off the
    historical folder hash, and the run ends green with no backup at all. It
    would surface at the first restore (docs/08 B1, docs/09 §3).

    Returns one human-readable line per differing key, [] when they agree, and
    exactly [UNREADABLE] when the remote file could not be parsed.
    """
    diff = _compare(remote_text, settings)
    if diff is None:
        return [UNREADABLE]
    out = []
    for key in sorted(diff):
        want_v, have_v = diff[key]
        if have_v is None:
            out.append(f"{key}: config.yml asks for {want_v!r}, "
                       "the bootstrap has nothing")
        elif want_v is None:
            out.append(f"{key}: not set in config.yml, "
                       f"the bootstrap has {have_v!r}")
        else:
            out.append(f"{key}: config.yml asks for {want_v!r}, "
                       f"the bootstrap has {have_v!r}")
    return out


def _compare(remote_text: str,
             settings: dict) -> dict[str, tuple[str | None, str | None]] | None:
    """key -> (wanted, actual) for every key that differs.

    {} when the two sides agree (or aXs owns nothing here), None when the remote
    file could not be read at all. Shared by `drift` (which formats it for a
    human) and `drift_keys` (which classifies it), so the message an operator
    reads and the decision to roll out can never be derived from two different
    comparisons.
    """
    # Nothing configured means aXs owns nothing here, so there is nothing to
    # compare against -- wso's own values and a hand-edited file are not drift
    # from a config.yml that makes no claim.
    if not is_configured(settings):
        return {}
    try:
        data = yaml.safe_load(remote_text)
    except yaml.YAMLError:
        return None
    if data is None:
        # An empty or fully commented-out file: wso wrote it, aXs never
        # patched it. Every configured key is missing, which the comparison
        # below states key by key.
        data = {}
    if not isinstance(data, dict):
        return None

    want = _flatten(settings)
    have = _flatten(data)
    return {key: (want.get(key), have.get(key))
            for key in set(want) | set(have)
            if want.get(key) != have.get(key)}


def drift_keys(remote_text: str, settings: dict) -> list[str] | None:
    """The dotted keys that differ, or None when the remote file is unreadable.

    The machine-readable half of `drift`. Kept separate because the decision
    "does this need rolling out?" must not be made by matching on the English
    sentences `drift` produces.
    """
    diff = _compare(remote_text, settings)
    return None if diff is None else sorted(diff)


def actionable_keys(remote_text: str, settings: dict) -> list[str] | None:
    """The drifting keys aXs could actually WRITE. None when unreadable.

    Narrower than `drift_keys` by exactly one case, and the difference is what
    keeps phase 50 from being red forever: a key that config.yml no longer sets
    but the bootstrap still carries. `drift_keys` reports it -- correctly, the
    two sides do differ -- but `patch` writes values, it does not remove keys,
    so nothing this phase can do would make that difference go away.

    Driving the red verdict off `drift_keys` therefore produced: probe red ->
    run -> patch cannot touch it -> the phase's own verification fails -> red
    again, identically, on every future run, with no way out but hand-editing
    the file on the bootstrap. Found by review, not by the round-trip property
    test, whose fixture set every key and so could not contain this case.

    aXs deliberately does not delete the leftover value: it may be wso's own, or
    an operator's, and removing settings nobody asked to remove is not this
    tool's business. It is reported instead.
    """
    diff = _compare(remote_text, settings)
    if diff is None:
        return None
    return sorted(key for key, (want, _have) in diff.items() if want is not None)


def orphan_keys(remote_text: str, settings: dict) -> list[str]:
    """Keys the bootstrap has and config.yml no longer sets.

    The complement of `actionable_keys` within the drift: worth saying out loud,
    since the operator may believe removing the line removed the setting -- but
    not something this phase can act on.
    """
    diff = _compare(remote_text, settings) or {}
    return sorted(key for key, (want, _have) in diff.items() if want is None)


def classify(keys: list[str]) -> tuple[list[str], list[str]]:
    """Split drifting keys into (retrofittable, needs_rebuild) -- docs/09 §4.

    What is MEASURED and what is not, because the difference matters here:

      * NTP: measured. A retrofitted `ntp_server` was applied by re-running the
        platform on the live cluster (commit bad8894). Containers share the
        host kernel clock, so it is right in every container at the same moment.
      * NFS, bridge subnet: **NOT measured.** The reasoning is that the NFS
        volume lives in the Nomad job definition and the bridge subnet is
        node-level configuration, so `wso cp deploy` should re-render both --
        but whether `wso services deploy` is additionally required for NFS is
        explicitly open (docs/09 §4). Treated as retrofittable on that
        reasoning, and phase 60 says so when it rolls one out rather than
        letting a green run imply a proof that does not exist.

    Central logging is not like that, on Omnissa's own statement: "Updating the
    logging configuration after first deployment would require a full
    redeployment/upgrade of the cluster to take effect." Rolling out the
    platform would NOT apply it. So it must never set the pending marker --
    a phase that went red over a logging change could never go green again,
    which docs/09 §4 names as worse than the drift it reports. It is said out
    loud as a warning instead.

    Unknown future keys count as retrofittable: `_flatten` only ever produces
    keys this module itself writes, so an unrecognised prefix means a key was
    added here without extending this function. Erring towards "we will try to
    apply it" fails visibly (the rollout runs and the drift persists, which
    phase 50 verifies and reports) instead of invisibly.
    """
    retrofittable, needs_rebuild = [], []
    for key in keys:
        target = needs_rebuild if str(key).startswith("logging.") else retrofittable
        target.append(key)
    return retrofittable, needs_rebuild


def summary(settings: dict) -> list[str]:
    """Short, human-readable lines about what will be written -- for the deploy
    log, so the record shows which operational settings this cluster got."""
    out = []
    for key in SCALARS:
        if v := str(settings.get(key) or "").strip():
            out.append(f"{key} = {v}")
    logging = mapping(settings.get("logging"))
    for name in ("loki_server", "opensearch"):
        if mapping(logging.get(name)).get("url"):
            out.append(f"logging.{name} = {logging[name]['url']}")
    for s in syslog_entries(logging):
        if s.get("host"):
            out.append(f"logging.syslog = {s['host']}:{s.get('port', 514)}"
                       f"/{s.get('protocol', 'udp')}")
    return out
