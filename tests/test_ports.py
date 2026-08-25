"""
Mirrors test_packages.py: mock subprocess.run to return `ss`-shaped
output rather than depending on the real host's actual listening
sockets, which is both non-deterministic and won't be consistent
across CI containers.
"""

from configsentry.config import PortsConfig
from configsentry.models import PluginSnapshot
from configsentry.plugins import ports


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _mock_ss_output(monkeypatch, lines: list[str]) -> None:
    """
    Patch subprocess.run to return `ss -tulnH`-shaped output.

    Each line should already be in ss's space-separated column shape,
    e.g. "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*". Callers build
    these directly rather than through a helper, since the column
    layout itself (and specifically column index 4 being the local
    address:port) is exactly what ports._query_listening_sockets()
    is responsible for parsing correctly.
    """
    stdout = "\n".join(lines) + "\n" if lines else ""

    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess(stdout)

    monkeypatch.setattr(ports.subprocess, "run", fake_run)


def test_capture_baseline_snapshots_listening_sockets(monkeypatch):
    _mock_ss_output(
        monkeypatch,
        [
            "tcp   LISTEN 0 128 0.0.0.0:22        0.0.0.0:*",
            "udp   UNCONN 0 0   0.0.0.0:68         0.0.0.0:*",
        ],
    )

    snapshot = ports.capture_baseline(PortsConfig())

    assert snapshot.error is None
    assert len(snapshot.resources) == 2
    by_key = {r.resource: r.value for r in snapshot.resources}
    assert by_key["tcp:0.0.0.0:22"] == {
        "protocol": "tcp",
        "address": "0.0.0.0",
        "port": "22",
    }
    assert by_key["udp:0.0.0.0:68"] == {
        "protocol": "udp",
        "address": "0.0.0.0",
        "port": "68",
    }


def test_capture_baseline_parses_bracketed_ipv6_address(monkeypatch):
    _mock_ss_output(
        monkeypatch,
        ["tcp   LISTEN 0 128 [::]:22           [::]:*"],
    )

    snapshot = ports.capture_baseline(PortsConfig())

    by_key = {r.resource: r.value for r in snapshot.resources}
    assert by_key["tcp:[::]:22"] == {
        "protocol": "tcp",
        "address": "[::]",
        "port": "22",
    }


def test_capture_baseline_records_error_when_ss_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(ports.subprocess, "run", fake_run)

    snapshot = ports.capture_baseline(PortsConfig())

    assert snapshot.resources == []
    assert "ss not found" in snapshot.error


def test_check_unchanged(monkeypatch):
    _mock_ss_output(monkeypatch, ["tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"])
    baseline = ports.capture_baseline(PortsConfig())

    _mock_ss_output(monkeypatch, ["tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"])  # unchanged
    findings = ports.check(PortsConfig(), baseline)

    assert findings[0].status == "unchanged"


def test_check_added(monkeypatch):
    _mock_ss_output(monkeypatch, ["tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"])
    baseline = ports.capture_baseline(PortsConfig())

    _mock_ss_output(
        monkeypatch,
        [
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*",  # new listener since baseline
        ],
    )
    findings = ports.check(PortsConfig(), baseline)

    added = next(f for f in findings if f.resource == "tcp:0.0.0.0:4444")
    assert added.status == "added"
    assert added.baseline_value is None
    assert added.current_value == {"protocol": "tcp", "address": "0.0.0.0", "port": "4444"}


def test_check_removed(monkeypatch):
    _mock_ss_output(
        monkeypatch,
        [
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*",
        ],
    )
    baseline = ports.capture_baseline(PortsConfig())

    _mock_ss_output(monkeypatch, ["tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"])  # 4444 closed
    findings = ports.check(PortsConfig(), baseline)

    removed = next(f for f in findings if f.resource == "tcp:0.0.0.0:4444")
    assert removed.status == "removed"
    assert removed.baseline_value == {"protocol": "tcp", "address": "0.0.0.0", "port": "4444"}
    assert removed.current_value is None


def test_check_raises_when_ss_missing(monkeypatch):
    empty_baseline = PluginSnapshot(plugin=ports.PLUGIN_NAME, resources=[])

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(ports.subprocess, "run", fake_run)

    try:
        ports.check(PortsConfig(), empty_baseline)
        assert False, "expected PortQueryError"
    except ports.PortQueryError as exc:
        assert "ss not found" in str(exc)
