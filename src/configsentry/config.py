"""
Loads and validates configsentry.yaml.

Note this is its OWN small set of Pydantic models, separate from
models.py. models.py describes plugin *output* (snapshots, findings).
This file describes plugin *input* (what the user told us to check).
Different concerns, different models, resist the urge to merge them
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
    Named-list, not full-inventory. Unlike PackagesConfig. A typical
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


class TimersConfig(BaseModel):
    """
    Named-list, not full-inventory. Same rationale as ServicesConfig:
    a host can carry many transient/templated timer units, and only a
    handful are usually security- or ops-relevant enough to track.
    `names` takes bare unit names without the `.timer` suffix (mirrors
    ServicesConfig.names, which also omits `.service`); the plugin
    appends the suffix itself. See plugins/timers.py for why.
    """

    names: list[str] = Field(default_factory=list)


class SysctlConfig(BaseModel):
    """
    Named-list, not full-inventory. A stock kernel exposes hundreds of
    tunables under /proc/sys, most of which are irrelevant to a given
    host's threat model. `names` mirrors ServicesConfig.names /
    TimersConfig.names: track only the handful (net.ipv4.ip_forward,
    kernel.randomize_va_space, ...) that actually matter for this
    host, using the dotted names sysctl(8)/sysctl.conf(5) use, e.g.
    "net.ipv4.ip_forward". See plugins/sysctl.py for how that maps
    to a /proc/sys path.
    """

    names: list[str] = Field(default_factory=list)


class SSHConfig(BaseModel):
    """
    Full-inventory mode over every directive `sshd -G` report.

    flag_insecure is a SEPARATE, opt-in concern from the full-inventory
    capture above, it doesn't change what gets captured, only whether
    check() forces a directive to report as drift regardless of
    baseline equality. It's a small named mapping of
    {directive: insecure_value}, e.g. {"permitrootlogin": "yes"}.
    A directive listed here whose CURRENT value matches the mapped
    value is always flagged, the same override precedent services.py
    uses for ActiveState == "failed" (see plugins/ssh.py check()).
    None or {} means no directives get this treatment, nothing is
    flagged by default, matching every other plugin's "absent config
    field = plugin/feature doesn't run" convention.

    YAML gotcha worth knowing before editing configsentry.yaml:
    sshd -G prints "yes"/"no" as literal strings, but PyYAML's
    safe_load treats *unquoted* yes/no as YAML 1.1 booleans, not
    strings, `permitrootlogin: yes` in YAML becomes Python `True`,
    which will never equal sshd -G's string "yes" and would silently
    never fire. Pydantic catches this loudly (ValidationError: "Input
    should be a valid string") rather than corrupting the value
    silently, but avoid tripping it in the first place by always
    quoting the value: `permitrootlogin: "yes"`.
    """

    flag_insecure: dict[str, str] | None = None


class PluginsConfig(BaseModel):
    # Every future plugin gets one more optional field here.
    # `None` means "not configured, so this plugin doesn't run."
    file_integrity: FileIntegrityConfig | None = None
    packages: PackagesConfig | None = None
    services: ServicesConfig | None = None
    ports: PortsConfig | None = None
    timers: TimersConfig | None = None
    sysctl: SysctlConfig | None = None
    ssh: SSHConfig | None = None


class AppConfig(BaseModel):
    plugins: PluginsConfig


def load_config(path: Path) -> AppConfig:
    """
    Read and validate configsentry.yaml.

    Raises FileNotFoundError if the path doesn't exist, and
    pydantic.ValidationError if the YAML doesn't match the expected
    shape (e.g. `paths` isn't a list). We deliberately let both of
    those exceptions propagate up to the CLI layer rather than
    swallowing them here, the CLI is responsible for turning
    exceptions into user-facing error messages, config.py's job is
    just to load correctly or fail loudly.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    return AppConfig.model_validate(raw)
