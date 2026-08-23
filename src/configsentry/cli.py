"""
CLI entry point. This file's only job is orchestration: load config,
call the plugin, read/write the baseline file, render output, set the
exit code. It should never contain plugin logic itself -- if you find
yourself writing a hash function in here, that code belongs in a
plugins/ file instead.
"""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from configsentry.config import AppConfig, load_config
from configsentry.models import Baseline, PluginResult, ScanReport
from configsentry.plugins import file_integrity

app = typer.Typer(
    help="configsentry: capture a config baseline, then detect drift against it."
)
console = Console()

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

    if app_config.plugins.file_integrity is not None:
        snapshot = file_integrity.capture_baseline(app_config.plugins.file_integrity.paths)
        result.plugin_snapshots.append(snapshot)

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
) -> None:
    """Compare current state against the stored baseline and report drift."""
    app_config = _load_config_or_exit(config)

    if not baseline_file.exists():
        console.print(f"[red]No baseline found at {baseline_file}. Run `baseline` first.[/red]")
        raise typer.Exit(code=2)

    stored_baseline = Baseline.model_validate_json(baseline_file.read_text())
    snapshots_by_plugin = {s.plugin: s for s in stored_baseline.plugin_snapshots}

    report = ScanReport(mode="check")

    if app_config.plugins.file_integrity is not None:
        fi_config = app_config.plugins.file_integrity
        fi_baseline = snapshots_by_plugin.get(file_integrity.PLUGIN_NAME)
        if fi_baseline is None:
            report.plugin_results.append(
                PluginResult(
                    plugin=file_integrity.PLUGIN_NAME,
                    error="No baseline data for this plugin -- run `baseline` again.",
                )
            )
        else:
            findings = file_integrity.check(fi_config.paths, fi_baseline)
            report.plugin_results.append(
                PluginResult(plugin=file_integrity.PLUGIN_NAME, findings=findings)
            )

    if json_output:
        print(report.model_dump_json(indent=2))
    else:
        _render_table(report)

    if report.has_errors:
        raise typer.Exit(code=2)
    if report.has_drift:
        raise typer.Exit(code=1)
    # implicit exit code 0: clean


def _render_table(report: ScanReport) -> None:
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

    any_findings = False
    for plugin_result in report.plugin_results:
        if plugin_result.error:
            table.add_row(plugin_result.plugin, "-", "[red]ERROR[/red]", plugin_result.error)
            any_findings = True
            continue
        for finding in plugin_result.findings:
            any_findings = True
            color = status_colors.get(finding.status, "white")
            table.add_row(
                plugin_result.plugin,
                finding.resource,
                f"[{color}]{finding.status}[/{color}]",
                finding.detail or "",
            )

    if not any_findings:
        console.print("[dim]No plugins configured -- nothing to check.[/dim]")
        return

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
