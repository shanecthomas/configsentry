"""
timers plugin: tracks the schedule and enablement/state of a
configured list of systemd timer units.

Deliberately NOT folded into services.py, even though timer units are
systemd units too. services.py's whole shape (three properties:
LoadState/UnitFileState/ActiveState) answers "is it enabled, is it
currently running/failed", a *state* question. The interesting
question for a timer is different: "when does it fire, and did that
change": a *schedule* question. A timer can sit "active" (systemd's
sense: loaded and waiting) every single day while its OnCalendar=
expression is quietly retargeted from daily to hourly, and
services.py's three properties would show zero drift throughout.
Rather than branch services.py's property list on unit suffix (two
resource shapes hiding behind one plugin name), this stays a separate
plugin with its own property set and its own definition of drift.
"""

from __future__ import annotations

import re
import subprocess

from configsentry.config import TimersConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState
from configsentry.plugins.base import PluginError

PLUGIN_NAME = "timers"

# LoadState/UnitFileState/ActiveState: same three properties as
# services.py, same reason, LoadState="not-found" is how a
# nonexistent unit is distinguished from a real state, and
# UnitFileState/ActiveState cover enablement and current run state.
#
# Unit: the service this timer actually triggers (e.g.
# "logrotate.service"). Stable, not volatile, retargeting a timer at
# a different unit is real drift, not something that changes on its
# own between two queries.
#
# TimersCalendar / TimersMonotonic: the actual schedule config
# (OnCalendar=, OnBootSec=, OnUnitActiveSec=, ...). This is the field
# that matters most and that services.py has no equivalent of. See
# _strip_next_elapse() for why these can't be compared as raw strings.
#
# Persistent: whether a missed run fires on next boot. Stable,
# genuinely part of the configured behavior.
_PROPERTIES = [
    "LoadState",
    "UnitFileState",
    "ActiveState",
    "Unit",
    "TimersCalendar",
    "TimersMonotonic",
    "Persistent",
]

# TimersCalendar/TimersMonotonic values look like:
#   { OnCalendar=*-*-* 03:00:00 ; next_elapse=Wed 2026-08-26 03:00:00 UTC }
# next_elapse is systemd's *computed prediction* of the next firing
# time, not configuration, it moves forward every time you query it,
# even with the schedule itself untouched. Comparing these strings
# raw would report "modified" on every single check() run regardless
# of real drift, which would make the plugin useless. This strips the
# volatile half, keeping only the configured expression:
#   { OnCalendar=*-*-* 03:00:00 }
_NEXT_ELAPSE_RE = re.compile(r"\s*;\s*next_elapse=[^}]*(?=\})")


def _strip_next_elapse(raw: str) -> str:
    # Lookahead (?=\}) matches up to but not consuming the closing
    # brace, and the replacement puts back a single space, so this
    # normalizes to "{ OnCalendar=... }" regardless of how much
    # trailing whitespace systemd printed before "}".
    return _NEXT_ELAPSE_RE.sub(" ", raw)


class TimerQueryError(PluginError):
    """
    Raised only when systemctl itself is unusable, binary missing,
    or unable to reach the service manager at all. Same split as
    services.ServiceQueryError: an individual timer that doesn't exist
    is captured as data (LoadState="not-found"), never an exception.
    """


def _full_unit_name(name: str) -> str:
    """
    Config takes bare names ("logrotate"), mirroring
    ServicesConfig.names which also omits ".service". Unlike
    ".service" though, systemctl does NOT default to ".timer" when you
    pass a bare name, it defaults to ".service" for every unit type
    unless you're explicit. So this plugin has to append the suffix
    itself rather than relying on systemctl's own default the way
    services.py implicitly does.
    """
    return name if name.endswith(".timer") else f"{name}.timer"


def _query_timer_state(name: str) -> dict[str, str]:
    full_name = _full_unit_name(name)
    try:
        result = subprocess.run(
            ["systemctl", "show", full_name, f"--property={','.join(_PROPERTIES)}", "--value"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise TimerQueryError(
            "systemctl not found, is this a systemd host?"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise TimerQueryError(
            f"systemctl show failed for {full_name!r}: {exc.stderr.strip()}"
        ) from exc

    values = result.stdout.splitlines()
    values += [""] * (len(_PROPERTIES) - len(values))
    state = dict(zip(_PROPERTIES, values, strict=True))

    state["TimersCalendar"] = _strip_next_elapse(state["TimersCalendar"])
    state["TimersMonotonic"] = _strip_next_elapse(state["TimersMonotonic"])
    return state


def _capture_one(name: str) -> ResourceState:
    return ResourceState(resource=name, value=_query_timer_state(name))


def capture_baseline(config: TimersConfig) -> PluginSnapshot:
    """
    Same whole-plugin-error handling as services.capture_baseline: a
    TimerQueryError means systemctl itself is broken, every remaining
    name would fail identically, so this stops at the first failure
    and reports it at the snapshot level.
    """
    resources: list[ResourceState] = []
    for name in config.names:
        try:
            resources.append(_capture_one(name))
        except TimerQueryError as exc:
            return PluginSnapshot(plugin=PLUGIN_NAME, error=str(exc))
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: TimersConfig, baseline: PluginSnapshot) -> list[Finding]:
    """
    Compare current state of each configured timer against its
    baseline record.

    Unlike services.check(), there's no forced-drift override here.
    services.py forces "failed" ActiveState to always report as drift
    because a service silently dying is the exact case where staying
    quiet is misleading. A timer unit's ActiveState doesn't carry that
    same signal, "active" for a timer just means "loaded and
    waiting to fire next", and a timer's own ActiveState essentially
    never goes to "failed" in normal operation the way a service's
    does (a failure in the thing it *triggers* shows up on that
    service's own ActiveState, tracked separately if it's also
    configured under `services`). 
    """
    baseline_by_name = {r.resource: r.value for r in baseline.resources}
    findings: list[Finding] = []

    for name in config.names:
        baseline_value = baseline_by_name.get(name)
        if baseline_value is None:
            findings.append(
                Finding(
                    resource=name,
                    status="added",
                    detail="No baseline record for this timer, run `baseline` again.",
                )
            )
            continue

        current_value = _query_timer_state(name)

        was_present = baseline_value.get("LoadState") != "not-found"
        is_present = current_value.get("LoadState") != "not-found"

        if not was_present and not is_present:
            status = "unchanged"
        elif not was_present and is_present:
            status = "added"
        elif was_present and not is_present:
            status = "removed"
        elif current_value != baseline_value:
            status = "modified"
        else:
            status = "unchanged"

        findings.append(
            Finding(
                resource=name,
                status=status,
                baseline_value=baseline_value,
                current_value=current_value,
            )
        )

    return findings
