"""
Tests use pytest's built-in `tmp_path` fixture rather than mocking the
filesystem. Since file_integrity does real, simple file I/O (no
subprocess calls, no network), a real temp directory that pytest wipes
after each test is both simpler AND more honest than mocking `open()`
and `Path.stat()` would be. Mocking is the right call for plugins that
shell out to subprocess (later plugins will use it) -- it's overkill
here.
"""

from configsentry.config import FileIntegrityConfig
from configsentry.models import PluginSnapshot, ResourceState
from configsentry.plugins import file_integrity


def test_capture_existing_file(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")

    snapshot = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))

    assert len(snapshot.resources) == 1
    resource = snapshot.resources[0]
    assert resource.value["exists"] is True
    assert "sha256" in resource.value
    assert "mode" in resource.value


def test_capture_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist"

    snapshot = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(missing)]))

    assert snapshot.resources[0].value == {"exists": False}


def test_check_unchanged(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")

    baseline = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))
    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    baseline = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))

    target.write_text("PermitRootLogin yes\n")  # someone changed it
    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), baseline)

    assert findings[0].status == "modified"


def test_check_removed(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    baseline = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))

    target.unlink()  # file deleted since baseline
    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), baseline)

    assert findings[0].status == "removed"


def test_check_added(tmp_path):
    target = tmp_path / "new_file"
    baseline = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))  # didn't exist yet

    target.write_text("surprise\n")  # appeared since baseline
    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), baseline)

    assert findings[0].status == "added"


def test_check_reports_error_on_unreadable_file(tmp_path, monkeypatch):
    target = tmp_path / "sudoers"
    target.write_text("root ALL=(ALL) ALL\n")
    baseline = file_integrity.capture_baseline(FileIntegrityConfig(paths=[str(target)]))  # readable at baseline time

    # Simulate the file becoming unreadable by the time `check` runs
    # (e.g. permission-restricted) without needing a real root-owned
    # file in the test environment.
    def raise_permission_error(path_str):
        raise PermissionError(f"[Errno 13] Permission denied: '{path_str}'")

    monkeypatch.setattr(file_integrity, "_capture_one", raise_permission_error)

    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), baseline)

    assert findings[0].status == "error"
    assert "Permission denied" in findings[0].detail


def test_check_reports_error_when_baseline_itself_has_error(tmp_path):
    target = tmp_path / "sudoers"
    target.write_text("root ALL=(ALL) ALL\n")

    # Simulate capture_baseline having already failed on this path --
    # the stored baseline value has an "error" key, not "exists".
    error_baseline = PluginSnapshot(
        plugin="file_integrity",
        resources=[ResourceState(resource=str(target), value={"error": "Permission denied"})],
    )

    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), error_baseline)

    # Must NOT be "unchanged" just because neither side has an "exists" key.
    assert findings[0].status == "error"


def test_check_no_baseline_record(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    empty_baseline = PluginSnapshot(plugin="file_integrity", resources=[])

    findings = file_integrity.check(FileIntegrityConfig(paths=[str(target)]), empty_baseline)

    assert findings[0].status == "added"
    assert "run `baseline` again" in findings[0].detail
