"""
Tests monkeypatch sysctl._SYSCTL_ROOT to a tmp_path and build a fake
/proc/sys layout underneath it, rather than mocking subprocess.run
(there isn't one to mock) or touching the real /proc/sys (whose
contents aren't test-controlled and, on some hosts, aren't even
writable to set up interesting cases). Same "real filesystem, no
mocking" approach as test_file_integrity.py, just rooted somewhere
other than the path under test.
"""

from configsentry.config import SysctlConfig
from configsentry.models import PluginSnapshot, ResourceState
from configsentry.plugins import sysctl


def _write_key(root, dotted_name: str, value: str) -> None:
    path = root / dotted_name.replace(".", "/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def test_sysctl_path_maps_dots_to_slashes():
    assert sysctl._sysctl_path("net.ipv4.ip_forward") == sysctl._SYSCTL_ROOT / "net/ipv4/ip_forward"


def test_capture_existing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")

    snapshot = sysctl.capture_baseline(SysctlConfig(names=["net.ipv4.ip_forward"]))

    assert snapshot.error is None
    assert snapshot.resources[0].value == {"present": True, "value": "0"}


def test_capture_missing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)

    snapshot = sysctl.capture_baseline(SysctlConfig(names=["kernel.made_up_knob"]))

    assert snapshot.resources[0].value == {"present": False}


def test_check_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "kernel.randomize_va_space", "2\n")
    baseline = sysctl.capture_baseline(SysctlConfig(names=["kernel.randomize_va_space"]))

    findings = sysctl.check(SysctlConfig(names=["kernel.randomize_va_space"]), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")
    baseline = sysctl.capture_baseline(SysctlConfig(names=["net.ipv4.ip_forward"]))

    _write_key(tmp_path, "net.ipv4.ip_forward", "1\n")  # someone flipped it
    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), baseline)

    assert findings[0].status == "modified"
    assert findings[0].baseline_value["value"] == "0"
    assert findings[0].current_value["value"] == "1"


def test_check_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")
    baseline = sysctl.capture_baseline(SysctlConfig(names=["net.ipv4.ip_forward"]))

    (tmp_path / "net/ipv4/ip_forward").unlink()  # module/knob gone since baseline
    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), baseline)

    assert findings[0].status == "removed"


def test_check_added(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    baseline = sysctl.capture_baseline(SysctlConfig(names=["net.ipv4.ip_forward"]))  # didn't exist yet

    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")  # module loaded since baseline
    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), baseline)

    assert findings[0].status == "added"


def test_check_reports_error_on_unreadable_key(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")
    baseline = sysctl.capture_baseline(SysctlConfig(names=["net.ipv4.ip_forward"]))  # readable at baseline time

    # Simulate the key becoming unreadable by the time `check` runs,
    # without needing a real permission-restricted /proc/sys entry in
    # the test environment.
    def raise_permission_error(name):
        raise PermissionError(f"[Errno 13] Permission denied: '{name}'")

    monkeypatch.setattr(sysctl, "_capture_one", raise_permission_error)

    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), baseline)

    assert findings[0].status == "error"
    assert "Permission denied" in findings[0].detail


def test_check_reports_error_when_baseline_itself_has_error(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")

    # Simulate capture_baseline having already failed on this key --
    # the stored baseline value has an "error" key, not "present".
    error_baseline = PluginSnapshot(
        plugin="sysctl",
        resources=[ResourceState(resource="net.ipv4.ip_forward", value={"error": "Permission denied"})],
    )

    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), error_baseline)

    # Must NOT be "unchanged" just because neither side has a "present" key.
    assert findings[0].status == "error"


def test_check_no_baseline_record(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "_SYSCTL_ROOT", tmp_path)
    _write_key(tmp_path, "net.ipv4.ip_forward", "0\n")
    empty_baseline = PluginSnapshot(plugin="sysctl", resources=[])

    findings = sysctl.check(SysctlConfig(names=["net.ipv4.ip_forward"]), empty_baseline)

    assert findings[0].status == "added"
    assert "run `baseline` again" in findings[0].detail
