"""
Mirrors test_packages.py/test_ports.py: mock subprocess.run to return
`sshd -G`-shaped output rather than depending on a real sshd binary
and config file being present on the CI container.
"""

from configsentry.config import SSHConfig
from configsentry.models import PluginSnapshot
from configsentry.plugins import ssh


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _mock_sshd_output(monkeypatch, lines: list[str]) -> None:
    """
    Patch subprocess.run to return `sshd -G`-shaped output: one
    "directive value" line per entry. Callers pass full lines
    (not a dict) specifically so a test can include the same
    directive name twice, exercising the repeated-directive case
    (listenaddress, hostkey) that a dict-keyed helper couldn't
    represent at all.
    """
    stdout = "\n".join(lines) + "\n" if lines else ""

    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess(stdout)

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)


def test_capture_baseline_snapshots_directives(monkeypatch):
    _mock_sshd_output(
        monkeypatch,
        ["permitrootlogin without-password", "passwordauthentication yes"],
    )

    snapshot = ssh.capture_baseline(SSHConfig())

    assert snapshot.error is None
    by_name = {r.resource: r.value for r in snapshot.resources}
    assert by_name["permitrootlogin"] == {"values": ["without-password"]}
    assert by_name["passwordauthentication"] == {"values": ["yes"]}


def test_capture_baseline_collects_repeated_directive_into_list(monkeypatch):
    # listenaddress and hostkey legitimately appear on multiple lines
    # in real sshd -T output, one per bind address / host key file.
    _mock_sshd_output(
        monkeypatch,
        [
            "listenaddress [::]:22",
            "listenaddress 0.0.0.0:22",
            "hostkey /etc/ssh/ssh_host_rsa_key",
            "hostkey /etc/ssh/ssh_host_ed25519_key",
        ],
    )

    snapshot = ssh.capture_baseline(SSHConfig())

    by_name = {r.resource: r.value for r in snapshot.resources}
    assert by_name["listenaddress"] == {"values": ["[::]:22", "0.0.0.0:22"]}
    assert by_name["hostkey"] == {
        "values": ["/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key"]
    }


def test_capture_baseline_preserves_embedded_space_in_value(monkeypatch):
    # authorizedkeysfile's value is itself two space-separated paths,
    # one directive, one value, not two directives.
    _mock_sshd_output(
        monkeypatch,
        ["authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"],
    )

    snapshot = ssh.capture_baseline(SSHConfig())

    by_name = {r.resource: r.value for r in snapshot.resources}
    assert by_name["authorizedkeysfile"] == {
        "values": [".ssh/authorized_keys .ssh/authorized_keys2"]
    }


def test_capture_baseline_records_error_when_sshd_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)

    snapshot = ssh.capture_baseline(SSHConfig())

    assert snapshot.resources == []
    assert "sshd not found" in snapshot.error


def test_capture_baseline_records_error_when_config_invalid(monkeypatch):
    # sshd -G still fails loudly on a genuinely broken sshd_config,
    # confirmed against a real invalid config: exit 255, stderr names
    # the bad directive. This plugin's whole-plugin error path (see
    # SSHQueryError) covers that failure, not just "binary missing."
    import subprocess as _subprocess

    def fake_run(*args, **kwargs):
        raise _subprocess.CalledProcessError(
            255,
            ["sshd", "-G"],
            stderr="/etc/ssh/sshd_config: line 1: Bad configuration option: BogusDirective\n",
        )

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)

    snapshot = ssh.capture_baseline(SSHConfig())

    assert "Bad configuration option" in snapshot.error


def test_check_unchanged(monkeypatch):
    _mock_sshd_output(monkeypatch, ["passwordauthentication no"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["passwordauthentication no"])  # unchanged
    findings = ssh.check(SSHConfig(), baseline)

    assert findings[0].status == "unchanged"


def test_check_modified(monkeypatch):
    _mock_sshd_output(monkeypatch, ["passwordauthentication no"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["passwordauthentication yes"])  # flipped since baseline
    findings = ssh.check(SSHConfig(), baseline)

    assert findings[0].status == "modified"
    assert findings[0].baseline_value == {"values": ["no"]}
    assert findings[0].current_value == {"values": ["yes"]}


def test_check_added(monkeypatch):
    _mock_sshd_output(monkeypatch, ["passwordauthentication no"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(
        monkeypatch,
        ["passwordauthentication no", "banner /etc/issue.net"],  # newly present
    )
    findings = ssh.check(SSHConfig(), baseline)

    added = next(f for f in findings if f.resource == "banner")
    assert added.status == "added"
    assert added.baseline_value is None
    assert added.current_value == {"values": ["/etc/issue.net"]}


def test_check_removed(monkeypatch):
    _mock_sshd_output(
        monkeypatch, ["passwordauthentication no", "banner /etc/issue.net"]
    )
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["passwordauthentication no"])  # banner directive gone
    findings = ssh.check(SSHConfig(), baseline)

    removed = next(f for f in findings if f.resource == "banner")
    assert removed.status == "removed"
    assert removed.baseline_value == {"values": ["/etc/issue.net"]}
    assert removed.current_value is None


def test_check_raises_when_sshd_missing(monkeypatch):
    empty_baseline = PluginSnapshot(plugin=ssh.PLUGIN_NAME, resources=[])

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)

    try:
        ssh.check(SSHConfig(), empty_baseline)
        assert False, "expected SSHQueryError"
    except ssh.SSHQueryError as exc:
        assert "sshd not found" in str(exc)


def test_check_flag_insecure_forces_modified_even_when_unchanged(monkeypatch):
    # permitrootlogin was ALREADY "yes" at baseline time, a pure
    # equality check would report "unchanged" and stay silent on a
    # directive that was insecure from before baseline was ever
    # captured. flag_insecure exists specifically to catch this.
    _mock_sshd_output(monkeypatch, ["permitrootlogin yes"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["permitrootlogin yes"])  # still unchanged
    config = SSHConfig(flag_insecure={"permitrootlogin": "yes"})
    findings = ssh.check(config, baseline)

    finding = next(f for f in findings if f.resource == "permitrootlogin")
    assert finding.status == "modified"
    assert "flagged as insecure" in finding.detail


def test_check_flag_insecure_does_not_fire_on_safe_value(monkeypatch):
    _mock_sshd_output(monkeypatch, ["permitrootlogin no"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["permitrootlogin no"])
    config = SSHConfig(flag_insecure={"permitrootlogin": "yes"})
    findings = ssh.check(config, baseline)

    finding = next(f for f in findings if f.resource == "permitrootlogin")
    assert finding.status == "unchanged"
    assert finding.detail is None


def test_check_flag_insecure_is_opt_in_by_default(monkeypatch):
    # No flag_insecure configured at all, an insecure value must
    # NOT be flagged. This is the "empty or doesn't exist -> no
    # error raised" requirement.
    _mock_sshd_output(monkeypatch, ["permitrootlogin yes"])
    baseline = ssh.capture_baseline(SSHConfig())

    _mock_sshd_output(monkeypatch, ["permitrootlogin yes"])
    findings = ssh.check(SSHConfig(), baseline)  # flag_insecure defaults to None

    finding = next(f for f in findings if f.resource == "permitrootlogin")
    assert finding.status == "unchanged"
    assert finding.detail is None
