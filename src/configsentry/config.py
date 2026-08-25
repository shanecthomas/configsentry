"""
Loads and validates configsentry.yaml.

Note this is its OWN small set of Pydantic models, separate from
models.py. models.py describes plugin *output* (snapshots, findings).
This file describes plugin *input* (what the user told us to check).
Different concerns, different models -- resist the urge to merge them
just because they're both "Pydantic stuff."
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class FileIntegrityConfig(BaseModel):
    paths: list[str] = Field(default_factory=list)


class PackagesConfig(BaseModel):
    """
    No fields yet. This plugin runs in full-inventory mode.
    """


class ServicesConfig(BaseModel):
    """
    Named-list, not full-inventory -- unlike PackagesConfig. A typical
    host's systemd unit list runs into the hundreds, many of them
    transient or templated (getty@tty1.service, oneshot units that are
    supposed to flip active/inactive as part of normal operation). A
    full diff would bury real drift in expected noise. `names` mirrors
    FileIntegrityConfig.paths: you tell it exactly which units you
    care about (sshd, docker, cron, ...), and only those get tracked.
    """

    names: list[str] = Field(default_factory=list)


class PortsConfig(BaseModel):
    """
    This plugin runs in full-inventory mode over every LISTEN-state socket.
    """


class PluginsConfig(BaseModel):
    # Every future plugin gets one more optional field here, e.g.:
    #   sysctl: SysctlConfig | None = None
    # `None` means "not configured, so this plugin doesn't run."
    file_integrity: FileIntegrityConfig | None = None
    packages: PackagesConfig | None = None
    services: ServicesConfig | None = None
    ports: PortsConfig | None = None


class AppConfig(BaseModel):
    plugins: PluginsConfig


def load_config(path: Path) -> AppConfig:
    """
    Read and validate configsentry.yaml.

    Raises FileNotFoundError if the path doesn't exist, and
    pydantic.ValidationError if the YAML doesn't match the expected
    shape (e.g. `paths` isn't a list). We deliberately let both of
    those exceptions propagate up to the CLI layer rather than
    swallowing them here -- the CLI is responsible for turning
    exceptions into user-facing error messages, config.py's job is
    just to load correctly or fail loudly.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    return AppConfig.model_validate(raw)
