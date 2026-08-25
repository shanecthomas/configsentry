"""
Mocks subprocess.run rather than depending on a real systemd host.
Same rationale as test_packages.py: no systemd in CI containers, and
we don't want tests whose outcome depends on which units happen to be
installed on whatever machine runs pytest.
"""

from configsentry.config import ServicesConfig
from configsentry.models import PluginSnapshot
from configsentry.plugins import services


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _mock_unit_state(monkeypatch, states: dict[str, dict[str, str]]) -> None:
    """
    states: {unit_name: {"LoadState": ..., "UnitFileState": ..., "ActiveState": ...}}
    Missing properties for a unit default to "". Same as a real
    systemctl invocation returning a blank line for that property.
    """

    def fake_run(args, **kwargs):
        # args[2] is the unit name in the systemctl show <name> ... invocation
        name = args[2]
        unit_state = states[name]
        stdout = "\n".join(unit_state.get(prop, "") for prop in services._PROPERTIES) + "\n"
        return _FakeCompletedProcess(stdout)

    monkeypatch.setattr(services.subprocess, "run", fake_run)


def _state(load="loaded", unit_file="enabled", active="active") -> dict[str, str]:
    return {"LoadState": load, "UnitFileState": unit_file, "ActiveState": active}


def test_capture_baseline_snapshots_configured_units(monkeypatch):
    _mock_unit_state(monkeypatch, {"sshd": _state(), "docker": _state(active="inactive")})

    snapshot = services.capture_baseline(ServicesConfig(names=["sshd", "docker"]))

    assert snapshot.error is None
    by_name = {r.resource: r.value for r in snapshot.resources}
    assert by_name["sshd"] == _state()
    assert by_name["docker"]["ActiveState"] == "inactive"


def test_capture_baseline_records_error_when_systemctl_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    snapshot = services.capture_baseline(ServicesConfig(names=["sshd"]))

    assert snapshot.resources == []
    assert "systemctl not found" in snapshot.error


def test_check_unchanged(monkeypatch):
    _mock_unit_state(monkeypatch, {"sshd": _state()})
    baseline = services.capture_baseline(ServicesConfig(names=["sshd"]))

    _mock_unit_state(monkeypatch, {"sshd": _state()})  # nothing changed
    findings = services.check(ServicesConfig(names=["sshd"]), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified_on_disabled(monkeypatch):
    _mock_unit_state(monkeypatch, {"sshd": _state(unit_file="enabled")})
    baseline = services.capture_baseline(ServicesConfig(names=["sshd"]))

    _mock_unit_state(monkeypatch, {"sshd": _state(unit_file="disabled")})
    findings = services.check(ServicesConfig(names=["sshd"]), baseline)

    assert findings[0].status == "modified"
    assert findings[0].baseline_value["UnitFileState"] == "enabled"
    assert findings[0].current_value["UnitFileState"] == "disabled"


def test_check_failed_always_reported_even_if_baseline_was_also_failed(monkeypatch):
    """
    The one deliberate deviation from equality-based status: a
    currently-failed unit is never "unchanged", even if the baseline
    snapshot was captured while it was already failed.
    """
    _mock_unit_state(monkeypatch, {"sshd": _state(active="failed")})
    baseline = services.capture_baseline(ServicesConfig(names=["sshd"]))

    _mock_unit_state(monkeypatch, {"sshd": _state(active="failed")})  # identical to baseline
    findings = services.check(ServicesConfig(names=["sshd"]), baseline)

    assert findings[0].status == "modified"
    assert findings[0].detail == "unit is in a failed state"


def test_check_removed_when_unit_uninstalled(monkeypatch):
    _mock_unit_state(monkeypatch, {"docker": _state()})
    baseline = services.capture_baseline(ServicesConfig(names=["docker"]))

    _mock_unit_state(
        monkeypatch, {"docker": _state(load="not-found", unit_file="", active="inactive")}
    )
    findings = services.check(ServicesConfig(names=["docker"]), baseline)

    assert findings[0].status == "removed"


def test_check_added_when_unit_now_exists(monkeypatch):
    _mock_unit_state(
        monkeypatch, {"docker": _state(load="not-found", unit_file="", active="inactive")}
    )
    baseline = services.capture_baseline(ServicesConfig(names=["docker"]))

    _mock_unit_state(monkeypatch, {"docker": _state()})  # now installed
    findings = services.check(ServicesConfig(names=["docker"]), baseline)

    assert findings[0].status == "added"


def test_check_no_baseline_record_reports_added(monkeypatch):
    empty_baseline = PluginSnapshot(plugin=services.PLUGIN_NAME, resources=[])
    _mock_unit_state(monkeypatch, {"sshd": _state()})

    findings = services.check(ServicesConfig(names=["sshd"]), empty_baseline)

    assert findings[0].status == "added"
    assert "No baseline record" in findings[0].detail


def test_check_raises_when_systemctl_missing(monkeypatch):
    baseline = PluginSnapshot(
        plugin=services.PLUGIN_NAME,
        resources=[{"resource": "sshd", "value": _state()}],
    )

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    try:
        services.check(ServicesConfig(names=["sshd"]), baseline)
        assert False, "expected ServiceQueryError"
    except services.ServiceQueryError as exc:
        assert "systemctl not found" in str(exc)
