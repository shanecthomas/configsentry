"""
packages plugin: full-inventory diff against dpkg.

Only Debian/Ubuntu (dpkg) is supported for now.
"""

from __future__ import annotations

import subprocess

from configsentry.config import PackagesConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState
from configsentry.plugins.base import PluginError

PLUGIN_NAME = "packages"

# dpkg-query's own -f format string. Tab-separated so parsing back out
# is a single str.partition("\t") -- no ambiguity the way a comma- or
# space-separated format could have if a field ever contained one.
_DPKG_QUERY_FORMAT = "${Package}\t${Version}\n"


class PackageQueryError(PluginError):
    """
    Raised when the package manager itself can't be queried -- binary
    missing (wrong distro), or dpkg-query exits non-zero. Unlike
    file_integrity's per-file errors, there's no per-resource
    granularity here: one subprocess call covers every package, so a
    failure is a whole-plugin failure, not something you can attribute
    to one resource. Subclasses PluginError so cli.py's generic
    exception handling catches this without needing to import
    `packages` specifically.
    """


def _query_installed_dpkg() -> dict[str, str]:
    """Return {package_name: version} for every package dpkg reports installed."""
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", f"-f={_DPKG_QUERY_FORMAT}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise PackageQueryError(
            "dpkg-query not found -- is this a Debian/Ubuntu host?"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise PackageQueryError(f"dpkg-query failed: {exc.stderr.strip()}") from exc

    installed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line:
            continue
        name, _, version = line.partition("\t")
        installed[name] = version
    return installed


def capture_baseline(config: PackagesConfig) -> PluginSnapshot:
    """
    Snapshot every currently-installed package.

    `config` is currently unused -- PackagesConfig has no fields yet,
    since full-inventory mode means there's nothing to configure
    beyond "this plugin is on." It's still a required parameter so
    this module satisfies plugins.base.PluginModule's uniform
    capture_baseline(config) shape; cli.py's plugin loop calls every
    plugin the same way regardless of whether that plugin happens to
    need the argument.

    A query failure is caught HERE, not raised -- it lands in
    PluginSnapshot.error, a field the schema already has (models.py).
    """
    try:
        installed = _query_installed_dpkg()
    except PackageQueryError as exc:
        return PluginSnapshot(plugin=PLUGIN_NAME, error=str(exc))

    resources = [
        ResourceState(resource=name, value={"version": version})
        for name, version in sorted(installed.items())
    ]
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: PackagesConfig, baseline: PluginSnapshot) -> list[Finding]:
    """
    Diff current installed state against the baseline snapshot.

    `config` is unused here too, for the same reason as in
    capture_baseline() -- see that docstring.

    Unlike capture_baseline(), a query failure here is RAISED, not
    caught. check() runs inside cli.py's report-building flow, which
    already has a home for "the plugin blew up" at the PluginResult
    level (see its docstring: "set if the plugin blew up; run
    continues"). cli.py is the right place to catch this and turn it
    into that field -- the same centralization pattern it already uses
    for config-loading errors in _load_config_or_exit().
    """
    current = _query_installed_dpkg()
    baseline_by_name = {r.resource: r.value for r in baseline.resources}

    all_names = set(baseline_by_name) | set(current)
    findings: list[Finding] = []

    for name in sorted(all_names):
        was_installed = name in baseline_by_name
        is_installed = name in current

        baseline_value = baseline_by_name.get(name)
        current_value = {"version": current[name]} if is_installed else None

        if not was_installed and is_installed:
            status = "added"
        elif was_installed and not is_installed:
            status = "removed"
        elif baseline_value.get("version") != current_value.get("version"):
            # Reached only when both sides are installed (the only way
            # `name` lands in all_names without tripping the two
            # branches above), so both dicts are guaranteed non-None
            # here -- no defensive None-check needed.
            status = "modified"
        else:
            status = "unchanged"

        findings.append(
            Finding(
                resource=name,
                status=status,
                baseline_value=baseline_value,
                current_value=current_value,
            )
        )

    return findings
