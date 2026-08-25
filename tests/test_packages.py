"""
Unlike test_file_integrity.py, these mock subprocess.run rather than
using tmp_path -- there's no real filesystem state to set up, and we
don't want tests that actually depend on the host's real dpkg
database (non-deterministic, and won't run in CI containers without
dpkg at all).
"""

from configsentry.config import PackagesConfig
from configsentry.models import PluginSnapshot
from configsentry.plugins import packages


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _mock_dpkg_output(monkeypatch, package_versions: dict[str, str]) -> None:
    """Patch subprocess.run to return dpkg-query-shaped output."""
    stdout = "".join(f"{name}\t{version}\n" for name, version in package_versions.items())

    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess(stdout)

    monkeypatch.setattr(packages.subprocess, "run", fake_run)


def test_capture_baseline_snapshots_all_installed(monkeypatch):
    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2", "curl": "8.5.0-2"})

    snapshot = packages.capture_baseline(PackagesConfig())

    assert snapshot.error is None
    assert len(snapshot.resources) == 2
    by_name = {r.resource: r.value for r in snapshot.resources}
    assert by_name["bash"] == {"version": "5.2.21-2"}
    assert by_name["curl"] == {"version": "8.5.0-2"}


def test_capture_baseline_records_error_when_dpkg_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(packages.subprocess, "run", fake_run)

    snapshot = packages.capture_baseline(PackagesConfig())

    assert snapshot.resources == []
    assert "dpkg-query not found" in snapshot.error


def test_check_unchanged(monkeypatch):
    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2"})
    baseline = packages.capture_baseline(PackagesConfig())

    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2"})  # nothing changed
    findings = packages.check(PackagesConfig(), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified(monkeypatch):
    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2"})
    baseline = packages.capture_baseline(PackagesConfig())

    _mock_dpkg_output(monkeypatch, {"bash": "5.2.24-1"})  # upgraded since baseline
    findings = packages.check(PackagesConfig(), baseline)

    assert findings[0].status == "modified"
    assert findings[0].baseline_value == {"version": "5.2.21-2"}
    assert findings[0].current_value == {"version": "5.2.24-1"}


def test_check_added(monkeypatch):
    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2"})
    baseline = packages.capture_baseline(PackagesConfig())

    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2", "htop": "3.3.0-1"})  # newly installed
    findings = packages.check(PackagesConfig(), baseline)

    added = next(f for f in findings if f.resource == "htop")
    assert added.status == "added"
    assert added.baseline_value is None
    assert added.current_value == {"version": "3.3.0-1"}


def test_check_removed(monkeypatch):
    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2", "htop": "3.3.0-1"})
    baseline = packages.capture_baseline(PackagesConfig())

    _mock_dpkg_output(monkeypatch, {"bash": "5.2.21-2"})  # htop uninstalled
    findings = packages.check(PackagesConfig(), baseline)

    removed = next(f for f in findings if f.resource == "htop")
    assert removed.status == "removed"
    assert removed.baseline_value == {"version": "3.3.0-1"}
    assert removed.current_value is None


def test_check_raises_when_dpkg_missing(monkeypatch):
    empty_baseline = PluginSnapshot(plugin=packages.PLUGIN_NAME, resources=[])

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(packages.subprocess, "run", fake_run)

    try:
        packages.check(PackagesConfig(), empty_baseline)
        assert False, "expected PackageQueryError"
    except packages.PackageQueryError as exc:
        assert "dpkg-query not found" in str(exc)
