"""
sysctl plugin: tracks the value of a configured list of kernel
tunables (net.ipv4.ip_forward, kernel.randomize_va_space, ...).

1. Read /proc/sys directly instead of shelling out to `sysctl -n`.

   Known limitation, not handled: a handful of interface-scoped keys
   (VLAN-style names containing a literal dot, e.g. "eth0.100") use a
   "/" in the dotted name to disambiguate that dot from the hierarchy
   separator. This plugin's naive dot-to-slash translation doesn't
   round-trip those. 

2. A missing key is captured as a state (present: False), not an error

3. No plugin-specific *Error/PluginError subclass. 
   Reading /proc/sys has no equivalent failure mode: there's no
   external binary that can be "missing", and a real read failure
   (permission denied) is inherently per-key, not whole-plugin.

_SYSCTL_ROOT is a module-level constant (default /proc/sys) rather
than hardcoding the path inline, specifically so tests can monkeypatch
it to a tmp_path and build a fake /proc/sys layout underneath,
the same "seam for testing" role subprocess.run plays in
services.py/timers.py, just for a filesystem root instead of a
subprocess call.
"""

from __future__ import annotations

from pathlib import Path

from configsentry.config import SysctlConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState

PLUGIN_NAME = "sysctl"

_SYSCTL_ROOT = Path("/proc/sys")


def _sysctl_path(name: str) -> Path:
    return _SYSCTL_ROOT / name.replace(".", "/")


def _capture_one(name: str) -> ResourceState:
    """
    Capture the current value of a single sysctl key. Deliberately
    never raises for a missing key, same reasoning as
    file_integrity._capture_one(): "this key doesn't exist on this
    host" is a valid, capturable state, not an error. It only raises
    for things that really are exceptional (e.g. permission denied
    reading the file), and even that gets caught one level up.
    """
    path = _sysctl_path(name)

    if not path.exists():
        return ResourceState(resource=name, value={"present": False})

    # Kernel files under /proc/sys report a single value per line
    # (multi-value keys like net.ipv4.ip_local_port_range exist, but
    # are still one line of whitespace-separated text), .strip()
    # drops the trailing newline the kernel always writes.
    return ResourceState(
        resource=name,
        value={"present": True, "value": path.read_text().strip()},
    )


def capture_baseline(config: SysctlConfig) -> PluginSnapshot:
    """
    Capture current state for every configured key.

    Same per-resource resilience as file_integrity.capture_baseline():
    one key raising OSError (e.g. permission denied, unlikely for
    /proc/sys but not impossible under restrictive LSM policies)
    shouldn't kill the whole plugin run.
    """
    resources: list[ResourceState] = []
    for name in config.names:
        try:
            resources.append(_capture_one(name))
        except OSError as exc:
            resources.append(ResourceState(resource=name, value={"error": str(exc)}))
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: SysctlConfig, baseline: PluginSnapshot) -> list[Finding]:
    """Compare current state of each configured key against its baseline record."""
    baseline_by_name = {r.resource: r.value for r in baseline.resources}
    findings: list[Finding] = []

    for name in config.names:
        baseline_val = baseline_by_name.get(name)
        if baseline_val is None:
            findings.append(
                Finding(
                    resource=name,
                    status="added",
                    detail="No baseline record for this key, run `baseline` again.",
                )
            )
            continue

        # Mirror capture_baseline's per-key resilience: one unreadable
        # key at check-time shouldn't crash the whole run.
        try:
            current_val = _capture_one(name).value
        except OSError as exc:
            current_val = {"error": str(exc)}

        # A key that couldn't be read on EITHER side, now or at
        # baseline time, isn't safe to run through the normal
        # present/value comparison below, for the same reason as
        # file_integrity.check(): an {"error": ...} payload has no
        # "present" key, which would silently evaluate as "not
        # present" and produce a wrong added/removed/unchanged verdict
        # instead of reporting what's actually true, we don't know.
        if "error" in baseline_val or "error" in current_val:
            findings.append(
                Finding(
                    resource=name,
                    status="error",
                    baseline_value=baseline_val,
                    current_value=current_val,
                    detail=current_val.get("error") or baseline_val.get("error"),
                )
            )
            continue

        was_present = baseline_val.get("present", False)
        is_present = current_val.get("present", False)

        if not was_present and not is_present:
            status = "unchanged"
        elif not was_present and is_present:
            status = "added"
        elif was_present and not is_present:
            status = "removed"
        elif baseline_val.get("value") != current_val.get("value"):
            status = "modified"
        else:
            status = "unchanged"

        findings.append(
            Finding(
                resource=name,
                status=status,
                baseline_value=baseline_val,
                current_value=current_val,
            )
        )

    return findings
