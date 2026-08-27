"""
ssh plugin: full-inventory diff of the SSH daemon's effective
configuration, resolved via `sshd -G` rather than parsing
sshd_config text directly.

Why `sshd -G` instead of reading /etc/ssh/sshd_config: sshd_config
supports Match blocks (conditional overrides scoped to a user, group,
or address), Include directives that pull in other files, and
compiled-in defaults for anything the file doesn't mention at all.
Parsing the text file yourself means re-implementing all of that
resolution logic and getting it subtly wrong. `sshd -G` shells out to
the daemon's own config resolver and prints the FINAL, fully resolved
directive set, the same source of truth sshd itself uses at
connection time. Same subprocess-seam pattern as services.py/timers.py.

Why `-G` and not `-T`: per sshd(8), `-T` is "similar to the -G flag,
but it includes the additional testing performed by the -t flag,"
and `-t` additionally checks "sanity of the keys", reading the host
key files, which are root-only on virtually every distro. `-G` skips
that check and resolves the exact same directive set without ever
touching the key files, verified empirically: `sshd -G` as an
unprivileged user produces byte-identical output to `sshd -T` as
root. No other plugin in this project requires root, and config
drift detection doesn't need sshd's key-sanity check anyway, we're
reading resolved config, not validating whether sshd could actually
start.
"""

from __future__ import annotations

import subprocess

from configsentry.config import SSHConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState
from configsentry.plugins.base import PluginError

PLUGIN_NAME = "ssh"


class SSHQueryError(PluginError):
    """
    Raised when sshd itself can't be queried, binary missing, or
    `sshd -G` exits non-zero (e.g. a genuinely malformed
    sshd_config). One subprocess call covers every directive, so
    (like packages.py/ports.py) a failure here is whole-plugin, not
    attributable to any single directive.
    """


def _query_sshd_config() -> dict[str, list[str]]:
    """
    Return {directive: [value, ...]} for every directive `sshd -G`
    reports.

    Values are collected into a list, not a single string, because a
    handful of directives are legitimately repeated across multiple
    lines, `listenaddress` (one line per bind address) and
    `hostkey` (one line per host key file) both do this on a stock
    config. Collapsing to a plain dict via something like
    `dict(line.partition(" ") for line in output)` would silently
    keep only the LAST occurrence of each directive, the same class
    of bug ports.py avoids by using rpartition() for IPv6 addresses.

    Splitting on the FIRST space (partition, not split) matters too:
    a directive's value can itself contain spaces, e.g.
    `authorizedkeysfile` is `.ssh/authorized_keys .ssh/authorized_keys2`,
    one value with an embedded space, not two directives.
    """
    try:
        result = subprocess.run(
            ["sshd", "-G"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise SSHQueryError(
            "sshd not found, is OpenSSH server installed on this host?"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise SSHQueryError(f"sshd -G failed: {exc.stderr.strip()}") from exc

    directives: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        name, _, value = line.partition(" ")
        directives.setdefault(name, []).append(value)
    return directives


def capture_baseline(config: SSHConfig) -> PluginSnapshot:
    """
    Snapshot every directive `sshd -G` reports.

    `config` is unused for the capture itself, flag_insecure only
    affects check(), not what gets captured (see SSHConfig's
    docstring). Still required as a parameter so this satisfies
    plugins.base.PluginModule's uniform capture_baseline(config)
    shape, the same reasoning packages.py's docstring gives.

    A query failure is caught HERE, not raised, same as
    packages.py/ports.py, it lands in PluginSnapshot.error instead of
    propagating.
    """
    try:
        directives = _query_sshd_config()
    except SSHQueryError as exc:
        return PluginSnapshot(plugin=PLUGIN_NAME, error=str(exc))

    resources = [
        ResourceState(resource=name, value={"values": values})
        for name, values in sorted(directives.items())
    ]
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: SSHConfig, baseline: PluginSnapshot) -> list[Finding]:
    """
    Diff current `sshd -G` output against the baseline snapshot,
    full-inventory style, same all_names union pattern as
    packages.check().

    A query failure here is RAISED, not caught, check() runs inside
    cli.py's report-building flow, which already catches PluginError
    and turns it into PluginResult.error (see packages.check()'s
    docstring for the same reasoning).

    After the normal added/removed/modified/unchanged comparison,
    config.flag_insecure (if set) can force a directive's status to
    "modified" even when it's unchanged from baseline, same
    override precedent as services.py's ActiveState == "failed"
    check. This is deliberately independent of drift: a directive can
    be insecure whether or not it changed since baseline, and a pure
    equality check would stay silent on "insecure since before you
    ever ran baseline," which is exactly the case worth flagging.
    """
    current = _query_sshd_config()
    baseline_by_name = {r.resource: r.value.get("values") for r in baseline.resources}
    flag_insecure = config.flag_insecure or {}

    all_names = set(baseline_by_name) | set(current)
    findings: list[Finding] = []

    for name in sorted(all_names):
        was_present = name in baseline_by_name
        is_present = name in current

        baseline_values = baseline_by_name.get(name)
        current_values = current.get(name)

        baseline_value = {"values": baseline_values} if was_present else None
        current_value = {"values": current_values} if is_present else None

        detail = None
        if not was_present and is_present:
            status = "added"
        elif was_present and not is_present:
            status = "removed"
        elif baseline_values != current_values:
            status = "modified"
        else:
            status = "unchanged"

        # Insecure-value override: independent of the drift verdict
        # just computed above. Fires whenever the CURRENT value
        # contains the configured insecure value, regardless of
        # status, an insecure directive that hasn't drifted from
        # baseline is still insecure. Forced status reuses "modified"
        # rather than adding a new DriftStatus, per SSHConfig's
        # docstring; this is the one place this plugin treats
        # "matches baseline" and "no finding worth surfacing" as
        # different questions, mirroring services.py's failed-state
        # override.
        insecure_value = flag_insecure.get(name)
        if (
            insecure_value is not None
            and current_values is not None
            and insecure_value in current_values
        ):
            status = "modified"
            detail = f"{name} is set to {insecure_value!r}, which is flagged as insecure"

        findings.append(
            Finding(
                resource=name,
                status=status,
                baseline_value=baseline_value,
                current_value=current_value,
                detail=detail,
            )
        )

    return findings
