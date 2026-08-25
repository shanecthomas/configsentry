"""
services plugin: tracks the enablement and runtime state of a
configured list of systemd units.
"""

from __future__ import annotations

import subprocess

from configsentry.config import ServicesConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState
from configsentry.plugins.base import PluginError

PLUGIN_NAME = "services"

# Requested in this order; `systemctl show ... --value` with multiple
# --property flags prints one value per line in the same order
# requested, so parsing is a straight zip rather than needing to parse
# `Key=Value` pairs and build a dict ourselves.
#
# LoadState tells us whether the unit exists at all 
# UnitFileState is the boot-time config: enabled/disabled/static/masked.
# ActiveState is the runtime state: active/inactive/failed/activating/...
_PROPERTIES = ["LoadState", "UnitFileState", "ActiveState"]


class ServiceQueryError(PluginError):
    """
    Raised only when systemctl itself is unusable i.e. binary missing,
    or (on a non-systemd host) unable to reach the service manager at
    all. NOT raised for an individual unit that doesn't exist or is
    misconfigured; that's captured as data (LoadState="not-found"),
    the same way file_integrity captures a missing path as
    {"exists": False} rather than treating it as an error.
    """


def _query_unit_state(name: str) -> dict[str, str]:
    """
    Query one systemd unit's load/enablement/activity state.

    Uses `systemctl show --value`, not `systemctl is-enabled` /
    `is-active`. Those two subcommands communicate state through exit
    code, and the exit code's meaning depends on which state it is,
    e.g. `is-active` exits 3 for "inactive", which is a normal,
    expected state, not a failure. That makes "did the command fail"
    and "what's the process's exit status" the same signal for the
    wrong reasons, and error-handling code has to special-case exit
    codes to tell them apart. `show` always exits 0 for a real
    subprocess-invocation success and puts the actual state in
    stdout, even for a nonexistent unit (LoadState comes back
    "not-found" rather than the command failing). A non-zero
    exit / exception here means something is wrong with systemctl
    itself, not with the unit being queried.
    """
    try:
        result = subprocess.run(
            ["systemctl", "show", name, f"--property={','.join(_PROPERTIES)}", "--value"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise ServiceQueryError(
            "systemctl not found -- is this a systemd host?"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise ServiceQueryError(
            f"systemctl show failed for {name!r}: {exc.stderr.strip()}"
        ) from exc

    values = result.stdout.splitlines()
    # Defensive padding: if systemctl ever returns fewer lines than
    # properties requested (e.g. a trailing blank value got swallowed),
    # zip() would silently drop the last property instead of raising.
    # Padding to the expected length turns that into an empty string
    # for the missing field rather than a misaligned mapping.
    values += [""] * (len(_PROPERTIES) - len(values))
    return dict(zip(_PROPERTIES, values, strict=True))


def _capture_one(name: str) -> ResourceState:
    """
    Capture current state for a single unit name.
    """
    return ResourceState(resource=name, value=_query_unit_state(name))


def capture_baseline(config: ServicesConfig) -> PluginSnapshot:
    """
    Capture current state for every configured unit name.

    A ServiceQueryError here means systemctl itself is broken. Every
    remaining name would fail identically, so this stops at the first
    failure and reports it at the snapshot level (PluginSnapshot.error),
    the same way packages.capture_baseline reports a missing dpkg-query.
    This is the one place services diverges from file_integrity's
    per-resource try/except loop: file_integrity's per-path failures
    (permission denied) are independent across paths, but a systemctl
    failure here is not independent -- it's a whole-plugin condition
    surfacing through a per-unit call.
    """
    resources: list[ResourceState] = []
    for name in config.names:
        try:
            resources.append(_capture_one(name))
        except ServiceQueryError as exc:
            return PluginSnapshot(plugin=PLUGIN_NAME, error=str(exc))
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: ServicesConfig, baseline: PluginSnapshot) -> list[Finding]:
    """
    Compare current state of each configured unit against its baseline
    record.

    Deliberate deviation from file_integrity/packages here: a unit
    whose current ActiveState is "failed" is ALWAYS reported as
    drift, even if the baseline was also "failed". A pure
    baseline-vs-current equality check (the pattern every other
    plugin uses) would report "unchanged" if you happened to capture
    the baseline while the service was already down, which is
    exactly the case where staying silent is most misleading. This is
    the one place this plugin intentionally treats "state contents
    equal" and "no drift" as different questions.
    """
    baseline_by_name = {r.resource: r.value for r in baseline.resources}
    findings: list[Finding] = []

    for name in config.names:
        baseline_value = baseline_by_name.get(name)
        if baseline_value is None:
            findings.append(
                Finding(
                    resource=name,
                    status="added",
                    detail="No baseline record for this unit -- run `baseline` again.",
                )
            )
            continue

        current_value = _query_unit_state(name)

        # LoadState="not-found" means the unit itself doesn't exist
        # (uninstalled, or the unit file was removed), which is distinct from
        # any particular enablement/activity state. Branching on this
        # first, like file_integrity branches on `exists` first,
        # means a unit disappearing entirely is reported as "removed"
        # rather than as a same-status dict of different values.
        was_present = baseline_value.get("LoadState") != "not-found"
        is_present = current_value.get("LoadState") != "not-found"

        detail = None
        if not was_present and not is_present:
            status = "unchanged"
        elif not was_present and is_present:
            status = "added"
        elif was_present and not is_present:
            status = "removed"
        elif current_value.get("ActiveState") == "failed":
            # Forced regardless of equality with baseline. See this
            # function's docstring.
            status = "modified"
            detail = "unit is in a failed state"
        elif current_value != baseline_value:
            status = "modified"
        else:
            status = "unchanged"

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
