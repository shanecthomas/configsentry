"""
Shared data contract for configsentry.

Every plugin produces a PluginResult made of Findings. The CLI never
looks at plugin-specific details -- it only ever consumes these shapes.
That's the whole point of defining them centrally: plugin #5 can't
accidentally return something plugin #1 didn't, because Pydantic will
refuse to construct the object if the data doesn't fit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

# Literal here is doing the job an Enum would do in a lot of other
# languages: it constrains a string field to a fixed, known set of
# values. Unlike a plain `str`, Pydantic will reject "modifed" (typo)
# or "Modified" (wrong case) at construction time instead of letting
# a bad value silently flow through to your JSON output.
DriftStatus = Literal["added", "removed", "modified", "unchanged", "error"]
# Only one mode exists today. Kept as a Literal (not a bare "check" string)
# so a future mode like "watch" is a one-line addition here, and every
# place that pattern-matches on `mode` gets a type-checker nudge to
# handle it -- instead of a silent string typo somewhere downstream.
ScanMode = Literal["check"]


class ResourceState(BaseModel):
    """
    Raw, un-judged captured state of one resource -- e.g. one file's
    hash and permissions at the moment `baseline` was run. No concept
    of "drift" belongs here; that only exists once you have two of
    these to compare.
    """

    resource: str  # e.g. "/etc/ssh/sshd_config"
    value: dict  # plugin-specific payload, e.g. {"sha256": "...", "mode": "0644"}


class PluginSnapshot(BaseModel):
    """Everything one plugin captured during a baseline run."""

    plugin: str
    resources: list[ResourceState] = Field(default_factory=list)
    error: str | None = None


class Baseline(BaseModel):
    """
    Top-level object written to the baseline file (e.g. .configsentry/baseline.json).
    This is the ONLY thing `check` reads back in -- it never re-reads config.
    """

    schema_version: str = "1.0"
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    plugin_snapshots: list[PluginSnapshot] = Field(default_factory=list)


class Finding(BaseModel):
    """A single per-resource comparison result (e.g. one file)."""

    resource: str  # e.g. "/etc/ssh/sshd_config"
    status: DriftStatus
    baseline_value: dict | None = None
    current_value: dict | None = None
    detail: str | None = None


class PluginResult(BaseModel):
    """Everything one plugin produced during a run."""

    plugin: str
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None  # set if the plugin blew up; run continues

    @property
    def drifted_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status not in ("unchanged", "error")]

    @property
    def error_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "error"]


class ScanReport(BaseModel):
    """
    Output object produced by `check` -- a diff between a Baseline and
    live current state.

    schema_version exists from day one, even though there's only one
    version right now. The moment you need to change this shape later,
    you check this field before parsing instead of guessing based on
    which fields happen to be present.
    """

    schema_version: str = "1.0"
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    mode: ScanMode
    plugin_results: list[PluginResult] = Field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return any(pr.drifted_findings for pr in self.plugin_results)

    @property
    def has_errors(self) -> bool:
        return any(pr.error or pr.error_findings for pr in self.plugin_results)
