"""
CLI-level tests using typer's CliRunner.

Plugin logic itself is already covered directly in
test_file_integrity.py / test_packages.py -- calling capture_baseline()
and check() as plain functions is simpler and more precise than
routing everything through a subprocess-like CliRunner invocation.

These tests exist for a different reason: to catch orchestration bugs
that only live in cli.py -- exit codes, the missing-config /
missing-baseline error paths, and the --json / --all flags -- which is
exactly the code that just got rewritten around the _PLUGINS registry
during the interface extraction. Every test passes explicit --config /
--baseline-file paths rather than relying on the cwd-relative defaults,
so these don't depend on where pytest happens to be invoked from.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from configsentry.cli import app
from configsentry.plugins import packages

runner = CliRunner()


def _write_config(tmp_path, *, file_integrity_paths=None, packages_enabled=False):
    lines = ["plugins:"]
    if file_integrity_paths is not None:
        lines.append("  file_integrity:")
        lines.append("    paths:")
        for p in file_integrity_paths:
            lines.append(f"      - {p}")
    if packages_enabled:
        lines.append("  packages: {}")
    if file_integrity_paths is None and not packages_enabled:
        lines.append("  {}")

    config_path = tmp_path / "configsentry.yaml"
    config_path.write_text("\n".join(lines) + "\n")
    return config_path


def _mock_dpkg(monkeypatch, package_versions: dict[str, str]) -> None:
    """Same mocking approach as test_packages.py, applied at the module
    the CLI actually calls through -- packages.subprocess.run."""
    stdout = "".join(f"{name}\t{version}\n" for name, version in package_versions.items())

    class _FakeCompletedProcess:
        def __init__(self) -> None:
            self.stdout = stdout

    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess()

    monkeypatch.setattr(packages.subprocess, "run", fake_run)


def test_baseline_missing_config_file(tmp_path):
    result = runner.invoke(
        app,
        [
            "baseline",
            "--config", str(tmp_path / "nope.yaml"),
            "--baseline-file", str(tmp_path / "baseline.json"),
        ],
    )
    assert result.exit_code == 2
    assert "Config file not found" in result.output


def test_baseline_invalid_config(tmp_path):
    bad = tmp_path / "configsentry.yaml"
    bad.write_text("plugins:\n  file_integrity:\n    paths: not_a_list\n")

    result = runner.invoke(
        app,
        [
            "baseline",
            "--config", str(bad),
            "--baseline-file", str(tmp_path / "baseline.json"),
        ],
    )
    assert result.exit_code == 2
    assert "Invalid config file" in result.output


def test_check_missing_baseline_file(tmp_path):
    cfg = _write_config(tmp_path, file_integrity_paths=[str(tmp_path / "target")])

    result = runner.invoke(
        app,
        [
            "check",
            "--config", str(cfg),
            "--baseline-file", str(tmp_path / "does_not_exist.json"),
        ],
    )
    assert result.exit_code == 2
    assert "No baseline found" in result.output


def test_baseline_then_check_clean_run(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    cfg = _write_config(tmp_path, file_integrity_paths=[str(target)])
    baseline_file = tmp_path / "baseline.json"

    baseline_result = runner.invoke(
        app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert baseline_result.exit_code == 0
    assert baseline_file.exists()

    check_result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert check_result.exit_code == 0
    assert "No drift detected" in check_result.output


def test_check_exit_code_1_on_drift(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    cfg = _write_config(tmp_path, file_integrity_paths=[str(target)])
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])

    target.write_text("PermitRootLogin yes\n")  # drift since baseline

    result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert result.exit_code == 1
    assert "Drift detected" in result.output
    assert "modified" in result.output


def test_check_json_output_is_valid_and_reflects_drift(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("v1\n")
    cfg = _write_config(tmp_path, file_integrity_paths=[str(target)])
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])
    target.write_text("v2\n")

    result = runner.invoke(
        app,
        ["check", "--config", str(cfg), "--baseline-file", str(baseline_file), "--json"],
    )

    payload = json.loads(result.output)
    assert payload["plugin_results"][0]["plugin"] == "file_integrity"
    assert payload["plugin_results"][0]["findings"][0]["status"] == "modified"


def test_check_all_flag_reveals_unchanged_rows_hidden_by_default(tmp_path, monkeypatch):
    _mock_dpkg(monkeypatch, {"bash": "1.0", "curl": "2.0"})
    cfg = _write_config(tmp_path, packages_enabled=True)
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])
    # dpkg state unchanged between baseline and check -- both packages
    # are "unchanged" drift-wise.

    default_result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert "No drift detected" in default_result.output
    assert "unchanged" not in default_result.output  # hidden by the drift-only default

    all_result = runner.invoke(
        app,
        ["check", "--config", str(cfg), "--baseline-file", str(baseline_file), "--all"],
    )
    assert "unchanged" in all_result.output
    assert "bash" in all_result.output
    assert "curl" in all_result.output


def test_packages_whole_plugin_failure_surfaces_as_error(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(packages.subprocess, "run", fake_run)
    cfg = _write_config(tmp_path, packages_enabled=True)
    baseline_file = tmp_path / "baseline.json"

    baseline_result = runner.invoke(
        app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert baseline_result.exit_code == 0  # capture_baseline() caught it internally

    check_result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert check_result.exit_code == 2
    assert "dpkg-query not found" in check_result.output


def test_packages_check_time_failure_uses_generic_plugin_error_handler(tmp_path, monkeypatch):
    """
    Distinct from test_packages_whole_plugin_failure_surfaces_as_error:
    that test fails at BASELINE time (caught inside capture_baseline(),
    surfaced via plugin_baseline.error). This one fails at CHECK time --
    dpkg-query works when the baseline was captured, but is gone by the
    time `check` runs (e.g. host got downgraded off Debian somehow).
    That exercises the try/except PluginError branch in check() itself,
    not the plugin_baseline.error branch -- a real, distinct code path
    that the other test doesn't touch.
    """
    _mock_dpkg(monkeypatch, {"bash": "1.0"})
    cfg = _write_config(tmp_path, packages_enabled=True)
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])

    def fake_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(packages.subprocess, "run", fake_run)

    result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert result.exit_code == 2
    assert "dpkg-query not found" in result.output


def test_check_plugin_added_to_config_after_baseline_was_captured(tmp_path):
    """
    Real scenario: baseline captured with only file_integrity enabled,
    then packages gets added to configsentry.yaml before the next
    `check` -- without an intervening `baseline` run. There's no
    baseline data for packages yet, which should surface as a clean
    per-plugin error, not a crash.
    """
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n")
    cfg = _write_config(tmp_path, file_integrity_paths=[str(target)])
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])

    # Now enable packages too, without rebaselining.
    cfg = _write_config(tmp_path, file_integrity_paths=[str(target)], packages_enabled=True)

    result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert result.exit_code == 2
    assert "No baseline data for this plugin" in result.output
    cfg = _write_config(tmp_path)
    baseline_file = tmp_path / "baseline.json"
    runner.invoke(app, ["baseline", "--config", str(cfg), "--baseline-file", str(baseline_file)])

    result = runner.invoke(
        app, ["check", "--config", str(cfg), "--baseline-file", str(baseline_file)]
    )
    assert "No plugins configured" in result.output
