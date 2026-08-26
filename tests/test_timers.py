"""
Mocks subprocess.run rather than depending on a real systemd host.
Same rationale as test_services.py.
"""

from configsentry.config import TimersConfig
from configsentry.models import PluginSnapshot
from configsentry.plugins import timers


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _mock_timer_state(monkeypatch, states: dict[str, dict[str, str]]) -> None:
    """
    states: {unit_name: {property: value}}, keyed by the FULL unit
    name (e.g. "logrotate.timer") since that's what's actually passed
    to systemctl. Missing properties default to "".
    """

    def fake_run(args, **kwargs):
        # args[2] is the full unit name in the systemctl show <name> ... invocation
        full_name = args[2]
        unit_state = states[full_name]
        stdout = "\n".join(unit_state.get(prop, "") for prop in timers._PROPERTIES) + "\n"
        return _FakeCompletedProcess(stdout)

    monkeypatch.setattr(timers.subprocess, "run", fake_run)


def _state(
    load="loaded",
    unit_file="enabled",
    active="active",
    unit="logrotate.service",
    calendar="{ OnCalendar=*-*-* 03:00:00 ; next_elapse=Wed 2026-08-26 03:00:00 UTC }",
    monotonic="",
    persistent="yes",
) -> dict[str, str]:
    return {
        "LoadState": load,
        "UnitFileState": unit_file,
        "ActiveState": active,
        "Unit": unit,
        "TimersCalendar": calendar,
        "TimersMonotonic": monotonic,
        "Persistent": persistent,
    }


def test_full_unit_name_appends_suffix_once():
    assert timers._full_unit_name("logrotate") == "logrotate.timer"
    assert timers._full_unit_name("logrotate.timer") == "logrotate.timer"


def test_strip_next_elapse_removes_only_volatile_half():
    raw = "{ OnCalendar=*-*-* 03:00:00 ; next_elapse=Wed 2026-08-26 03:00:00 UTC }"
    assert timers._strip_next_elapse(raw) == "{ OnCalendar=*-*-* 03:00:00 }"


def test_capture_baseline_snapshots_configured_timers(monkeypatch):
    _mock_timer_state(
        monkeypatch,
        {"logrotate.timer": _state(), "fstrim.timer": _state(active="inactive")},
    )

    snapshot = timers.capture_baseline(TimersConfig(names=["logrotate", "fstrim"]))

    assert snapshot.error is None
    by_name = {r.resource: r.value for r in snapshot.resources}
    # stored under the bare config name, not the full ".timer" name
    assert by_name["logrotate"]["ActiveState"] == "active"
    assert by_name["fstrim"]["ActiveState"] == "inactive"


def test_capture_baseline_strips_next_elapse_from_calendar_field(monkeypatch):
    _mock_timer_state(monkeypatch, {"logrotate.timer": _state()})

    snapshot = timers.capture_baseline(TimersConfig(names=["logrotate"]))

    stored = snapshot.resources[0].value["TimersCalendar"]
    assert "next_elapse" not in stored
    assert stored == "{ OnCalendar=*-*-* 03:00:00 }"


def test_capture_baseline_records_error_when_systemctl_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(timers.subprocess, "run", fake_run)

    snapshot = timers.capture_baseline(TimersConfig(names=["logrotate"]))

    assert snapshot.resources == []
    assert "systemctl not found" in snapshot.error


def test_check_unchanged_despite_next_elapse_moving_forward(monkeypatch):
    """
    The whole point of stripping next_elapse: two queries of an
    untouched timer, taken at different moments, must NOT report
    drift just because systemd's predicted next-firing time advanced.
    """
    _mock_timer_state(monkeypatch, {"logrotate.timer": _state()})
    baseline = timers.capture_baseline(TimersConfig(names=["logrotate"]))

    later_state = _state(
        calendar="{ OnCalendar=*-*-* 03:00:00 ; next_elapse=Thu 2026-08-27 03:00:00 UTC }"
    )
    _mock_timer_state(monkeypatch, {"logrotate.timer": later_state})
    findings = timers.check(TimersConfig(names=["logrotate"]), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified_on_schedule_change(monkeypatch):
    _mock_timer_state(monkeypatch, {"logrotate.timer": _state()})
    baseline = timers.capture_baseline(TimersConfig(names=["logrotate"]))

    changed_state = _state(
        calendar="{ OnCalendar=*-*-* 00:00:00 ; next_elapse=Wed 2026-08-26 00:00:00 UTC }"
    )
    _mock_timer_state(monkeypatch, {"logrotate.timer": changed_state})
    findings = timers.check(TimersConfig(names=["logrotate"]), baseline)

    assert findings[0].status == "modified"
    assert findings[0].baseline_value["TimersCalendar"] == "{ OnCalendar=*-*-* 03:00:00 }"
    assert findings[0].current_value["TimersCalendar"] == "{ OnCalendar=*-*-* 00:00:00 }"


def test_check_modified_on_retargeted_unit(monkeypatch):
    """A timer firing a different unit than baseline is real drift."""
    _mock_timer_state(monkeypatch, {"logrotate.timer": _state(unit="logrotate.service")})
    baseline = timers.capture_baseline(TimersConfig(names=["logrotate"]))

    _mock_timer_state(monkeypatch, {"logrotate.timer": _state(unit="backdoor.service")})
    findings = timers.check(TimersConfig(names=["logrotate"]), baseline)

    assert findings[0].status == "modified"


def test_check_removed_when_timer_uninstalled(monkeypatch):
    _mock_timer_state(monkeypatch, {"fstrim.timer": _state()})
    baseline = timers.capture_baseline(TimersConfig(names=["fstrim"]))

    _mock_timer_state(
        monkeypatch,
        {"fstrim.timer": _state(load="not-found", unit_file="", active="inactive", unit="")},
    )
    findings = timers.check(TimersConfig(names=["fstrim"]), baseline)

    assert findings[0].status == "removed"


def test_check_added_when_timer_now_exists(monkeypatch):
    _mock_timer_state(
        monkeypatch,
        {"fstrim.timer": _state(load="not-found", unit_file="", active="inactive", unit="")},
    )
    baseline = timers.capture_baseline(TimersConfig(names=["fstrim"]))

    _mock_timer_state(monkeypatch, {"fstrim.timer": _state()})
    findings = timers.check(TimersConfig(names=["fstrim"]), baseline)

    assert findings[0].status == "added"


def test_check_no_baseline_record_reports_added(monkeypatch):
    empty_baseline = PluginSnapshot(plugin=timers.PLUGIN_NAME, resources=[])
    _mock_timer_state(monkeypatch, {"logrotate.timer": _state()})

    findings = timers.check(TimersConfig(names=["logrotate"]), empty_baseline)

    assert findings[0].status == "added"
    assert "No baseline record" in findings[0].detail


def test_check_raises_when_systemctl_missing(monkeypatch):
    baseline = PluginSnapshot(
        plugin=timers.PLUGIN_NAME,
        resources=[{"resource": "logrotate", "value": _state()}],
    )

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(timers.subprocess, "run", fake_run)

    try:
        timers.check(TimersConfig(names=["logrotate"]), baseline)
        assert False, "expected TimerQueryError"
    except timers.TimerQueryError as exc:
        assert "systemctl not found" in str(exc)
