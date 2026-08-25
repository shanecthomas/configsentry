"""
CLI entry point. This file's only job is orchestration: load config,
call the plugin, read/write the baseline file, render output, set the
exit code. It should never contain plugin logic itself -- if you find
yourself writing a hash function in here, that code belongs in a
plugins/ file instead.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from configsentry.config import AppConfig, load_config
from configsentry.models import Baseline, PluginResult, ScanReport
from configsentry.plugins import file_integrity, packages, services
from configsentry.plugins.base import PluginError, PluginModule

app = typer.Typer(
    help="configsentry: capture a config baseline, then detect drift against it."
)
console = Console()

# Registers every plugin once, in one place. Each entry pairs a plugin
# module with a getter that pulls THAT plugin's own config object off
# AppConfig.plugins -- that one-line-per-plugin getter is the only spot
# left that needs to know PluginsConfig's individual field names.
# Everything downstream (baseline(), check()) calls plugins uniformly
# through the PluginModule contract and never branches per plugin name.
_PLUGINS: dict[str, tuple[PluginModule, Callable[[AppConfig], Any]]] = {
    file_integrity.PLUGIN_NAME: (file_integrity, lambda cfg: cfg.plugins.file_integrity),
    packages.PLUGIN_NAME: (packages, lambda cfg: cfg.plugins.packages),
    services.PLUGIN_NAME: (services, lambda cfg: cfg.plugins.services),
}

# Fail fast at import time, not at first use, if a plugin module drifts
# out of shape with the contract (e.g. someone renames PLUGIN_NAME or
# changes check()'s signature). isinstance() works here because
# PluginModule is @runtime_checkable -- see plugins/base.py.
for _plugin_module, _ in _PLUGINS.values():
    assert isinstance(_plugin_module, PluginModule), (
        f"{_plugin_module.__name__!r} does not satisfy PluginModule -- "
        f"check its capture_baseline()/check() signatures against plugins/base.py"
    )

# Typer reads these type hints to build the actual CLI: `Path` becomes
# a path argument, `bool` becomes a --flag/--no-flag pair, and the
# typer.Option(...) call supplies the default value plus the flag
# names and help text shown in `--help`. You're not writing argparse
# boilerplate -- the function signature IS the CLI definition.
ConfigOption = typer.Option(
    Path("configsentry.yaml"), "--config", "-c", help="Path to configsentry.yaml"
)
BaselineFileOption = typer.Option(
    Path(".configsentry/baseline.json"),
    "--baseline-file",
    "-b",
    help="Where the baseline is read from / written to",
)


def _load_config_or_exit(config: Path) -> AppConfig:
    """
    Shared error-handling wrapper around load_config().

    config.py's job is to raise loudly on bad input (that's its
    contract, per its own docstring); this is the one place that
    contract actually gets honored -- turning FileNotFoundError and
    ValidationError into a clean message + exit code 2, instead of
    letting either fall through to a raw traceback. Both commands call
    this instead of load_config() directly so that contract only has
    to be implemented once.
    """
    try:
        return load_config(config)
    except FileNotFoundError:
        console.print(f"[red]Config file not found: {config}[/red]")
        raise typer.Exit(code=2) from None
    except ValidationError as exc:
        console.print(f"[red]Invalid config file {config}:[/red]\n{exc}")
        raise typer.Exit(code=2) from None


@app.command()
def baseline(
    config: Path = ConfigOption,
    baseline_file: Path = BaselineFileOption,
) -> None:
    """Capture the current state of everything in the config as the new baseline."""
    app_config = _load_config_or_exit(config)

    result = Baseline()

    for plugin_module, get_config in _PLUGINS.values():
        plugin_config = get_config(app_config)
        if plugin_config is None:
            continue
        result.plugin_snapshots.append(plugin_module.capture_baseline(plugin_config))

    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text(result.model_dump_json(indent=2))

    total_resources = sum(len(s.resources) for s in result.plugin_snapshots)
    console.print(
        f"[green]Baseline captured:[/green] {total_resources} resource(s) "
        f"across {len(result.plugin_snapshots)} plugin(s) -> {baseline_file}"
    )


@app.command()
def check(
    config: Path = ConfigOption,
    baseline_file: Path = BaselineFileOption,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    show_all: bool = typer.Option(
        False, "--all", "-a", help="Include unchanged resources in table output (default: drift only)"
    ),
) -> None:
    """Compare current state against the stored baseline and report drift."""
    app_config = _load_config_or_exit(config)

    if not baseline_file.exists():
        console.print(f"[red]No baseline found at {baseline_file}. Run `baseline` first.[/red]")
        raise typer.Exit(code=2)

    stored_baseline = Baseline.model_validate_json(baseline_file.read_text())
    snapshots_by_plugin = {s.plugin: s for s in stored_baseline.plugin_snapshots}

    report = ScanReport(mode="check")

    for plugin_name, (plugin_module, get_config) in _PLUGINS.items():
        plugin_config = get_config(app_config)
        if plugin_config is None:
            continue

        plugin_baseline = snapshots_by_plugin.get(plugin_name)
        if plugin_baseline is None:
            report.plugin_results.append(
                PluginResult(
                    plugin=plugin_name,
                    error="No baseline data for this plugin -- run `baseline` again.",
                )
            )
            continue

        if plugin_baseline.error:
            # nothing to diff against, so surface the same message rather
            # than attempting a check() that has no baseline to compare to
            report.plugin_results.append(
                PluginResult(plugin=plugin_name, error=plugin_baseline.error)
            )
            continue

        try:
            findings = plugin_module.check(plugin_config, plugin_baseline)
            report.plugin_results.append(PluginResult(plugin=plugin_name, findings=findings))
        except PluginError as exc:
            # Catches any future plugin's own error type without cli.py needing to import
            # or name it specifically -- see plugins/base.py.
            report.plugin_results.append(PluginResult(plugin=plugin_name, error=str(exc)))

    if json_output:
        print(report.model_dump_json(indent=2))
    else:
        _render_table(report, show_all=show_all)

    if report.has_errors:
        raise typer.Exit(code=2)
    if report.has_drift:
        raise typer.Exit(code=1)
    # implicit exit code 0: clean


def _render_table(report: ScanReport, show_all: bool = False) -> None:
    if not report.plugin_results:
        console.print("[dim]No plugins configured -- nothing to check.[/dim]")
        return

    table = Table(title="configsentry check")
    table.add_column("Plugin")
    table.add_column("Resource")
    table.add_column("Status")
    table.add_column("Detail")

    status_colors = {
        "unchanged": "dim",
        "modified": "yellow",
        "added": "cyan",
        "removed": "red",
        "error": "bold red",
    }

    for plugin_result in report.plugin_results:
        if plugin_result.error:
            table.add_row(plugin_result.plugin, "-", "[red]ERROR[/red]", plugin_result.error)
            continue
        # Default view is drift-only. A full-inventory plugin like
        # `packages` can produce thousands of "unchanged" rows, which
        # would bury the handful that actually matter.
        findings = plugin_result.findings if show_all else plugin_result.drifted_findings
        for finding in findings:
            color = status_colors.get(finding.status, "white")
            table.add_row(
                plugin_result.plugin,
                finding.resource,
                f"[{color}]{finding.status}[/{color}]",
                finding.detail or "",
            )

    if table.row_count:
        console.print(table)

    # Same priority as the exit-code logic below: errors outrank drift,
    # which outranks clean. Checking has_drift first here would let a run
    # with a real error still print "No drift detected." in green --
    # technically true, but a misleading thing to tell someone next to an
    # exit code of 2.
    if report.has_errors:
        console.print("[bold red]Errors occurred -- results may be incomplete.[/bold red]")
    elif report.has_drift:
        console.print("[yellow]Drift detected.[/yellow]")
    else:
        console.print("[green]No drift detected.[/green]")


if __name__ == "__main__":
    app()
