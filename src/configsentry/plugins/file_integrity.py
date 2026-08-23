"""
file_integrity plugin: hashes a configured list of files and reports
when their contents or permissions change.

Written as plain functions, not a class implementing some
`BasePlugin` interface. That's intentional -- once this works end to
end, and plugin #2 exists to compare it against, THEN the common
shape between them gets extracted into an interface. Designing the
interface before you have two real examples means guessing at what
the abstraction needs, which is how you end up with a base class that
doesn't actually fit anything.
"""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from configsentry.models import Finding, PluginSnapshot, ResourceState

PLUGIN_NAME = "file_integrity"


def _hash_file(path: Path) -> str:
    """
    SHA-256 the file contents, reading in chunks rather than
    path.read_bytes(). For config files this barely matters (they're
    small), but it's the correct habit: read_bytes() loads the whole
    file into memory at once, which would be a real problem if this
    plugin is ever pointed at something large. Chunked reading keeps
    memory use constant regardless of file size.
    """
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _capture_one(path_str: str) -> ResourceState:
    """
    Capture the current state of a single path. Deliberately never
    raises for a missing file -- "this file doesn't exist" is a valid,
    capturable state, not an error. It only raises for things that
    really are exceptional (e.g. permission denied reading the file),
    and even that gets caught one level up in capture_baseline().
    """
    path = Path(path_str)

    if not path.exists():
        return ResourceState(resource=path_str, value={"exists": False})

    file_stat = path.stat()
    return ResourceState(
        resource=path_str,
        value={
            "exists": True,
            "sha256": _hash_file(path),
            # stat.S_IMODE strips the file-type bits, leaving just the
            # permission bits (e.g. 0644), formatted as the octal
            # string you'd recognize from `chmod`/`ls -l`.
            "mode": oct(stat.S_IMODE(file_stat.st_mode)),
        },
    )


def capture_baseline(paths: list[str]) -> PluginSnapshot:
    """Capture current state for every configured path."""
    resources: list[ResourceState] = []
    for path_str in paths:
        try:
            resources.append(_capture_one(path_str))
        except OSError as exc:
            # A single unreadable file (e.g. permissions) shouldn't
            # kill the whole plugin run. Record it as a resource with
            # an error value and keep going.
            resources.append(
                ResourceState(resource=path_str, value={"error": str(exc)})
            )
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(paths: list[str], baseline: PluginSnapshot) -> list[Finding]:
    """Compare current state of each path against its baseline record."""
    baseline_by_path = {r.resource: r for r in baseline.resources}
    findings: list[Finding] = []

    for path_str in paths:
        baseline_state = baseline_by_path.get(path_str)
        if baseline_state is None:
            findings.append(
                Finding(
                    resource=path_str,
                    status="added",
                    detail="No baseline record for this path -- run `baseline` again.",
                )
            )
            continue

        baseline_val = baseline_state.value

        # Mirror capture_baseline's per-path resilience: one unreadable
        # file (e.g. permission denied) shouldn't crash the whole check
        # run. Caught here as data, same as it already is in capture_baseline.
        try:
            current_val = _capture_one(path_str).value
        except OSError as exc:
            current_val = {"error": str(exc)}

        # A resource that couldn't be read on EITHER side -- now or at
        # baseline time -- is not safe to run through the normal
        # exists/hash comparison below. baseline_val or current_val
        # missing "exists" entirely (because it's an {"error": ...}
        # payload instead) would silently evaluate as "not present" on
        # that side, which can produce a false "unchanged" or a wrong
        # "added"/"removed" -- reporting a status we don't actually know
        # to be true. Report it as its own explicit status instead.
        if "error" in baseline_val or "error" in current_val:
            findings.append(
                Finding(
                    resource=path_str,
                    status="error",
                    baseline_value=baseline_val,
                    current_value=current_val,
                    detail=current_val.get("error") or baseline_val.get("error"),
                )
            )
            continue

        was_present = baseline_val.get("exists", False)
        is_present = current_val.get("exists", False)

        if not was_present and not is_present:
            status = "unchanged"
        elif not was_present and is_present:
            status = "added"
        elif was_present and not is_present:
            status = "removed"
        elif baseline_val.get("sha256") != current_val.get("sha256") or baseline_val.get("mode") != current_val.get("mode"):
            status = "modified"
        else:
            status = "unchanged"

        findings.append(
            Finding(
                resource=path_str,
                status=status,
                baseline_value=baseline_val,
                current_value=current_val,
            )
        )

    return findings
