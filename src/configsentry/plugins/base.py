"""
Structural contract every plugin module satisfies.

This is a typing.Protocol, not an ABC. The plugins are plain modules
with module-level functions, not classes -- Protocol checks
structurally (does this module happen to expose the right names with
the right shapes?) instead of requiring inheritance from a shared
base. That fits code you're not restructuring into classes just to
satisfy an interface.

@runtime_checkable makes isinstance() actually work against this at
runtime, not just under a type checker. cli.py uses that to fail fast
-- at import time -- if a plugin module doesn't conform, without
needing mypy/pyright wired into the project.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from configsentry.models import Finding, PluginSnapshot


class PluginError(RuntimeError):
    """
    Base class for "the whole plugin blew up" errors -- as opposed to
    a single resource being unreadable, which plugins report as DATA
    (a Finding/ResourceState with status="error"), never an exception.

    Plugin-specific errors (e.g. packages.PackageQueryError) should
    subclass this, so cli.py can catch whole-plugin failures generically
    in one place without importing or naming every plugin's specific
    exception type.
    """


@runtime_checkable
class PluginModule(Protocol):
    PLUGIN_NAME: str

    def capture_baseline(self, config: Any) -> PluginSnapshot: ...
    def check(self, config: Any, baseline: PluginSnapshot) -> list[Finding]: ...
