"""
ports plugin: full-inventory diff of every LISTEN-state TCP and
UNCONN-state (i.e. bound-and-listening) UDP socket.
"""

from __future__ import annotations

import subprocess

from configsentry.config import PortsConfig
from configsentry.models import Finding, PluginSnapshot, ResourceState
from configsentry.plugins.base import PluginError

PLUGIN_NAME = "ports"


class PortQueryError(PluginError):
    """
    Raised when `ss` itself can't be queried i.e. binary missing, or a
    non-zero exit. Like packages.PackageQueryError, there's no
    per-resource granularity: one subprocess call covers every socket,
    so a failure here is whole-plugin, not attributable to one port.
    """


def _query_listening_sockets() -> dict[str, dict[str, str]]:
    """
    Return {resource_key: {"protocol", "address", "port"}} for every
    currently listening socket.

    `ss -tulnH`:
      -t / -u   TCP and UDP sockets (see ports.py module docstring
                and the config.py PortsConfig class for why both are
                in scope from the start -- unlike packages.py's
                dpkg/dnf split, TCP vs UDP is a flag, not a separate
                query path).
      -l        listening only. This is doing double duty: for TCP it
                filters to State=LISTEN, and for UDP (a connectionless
                protocol with no real "listening" state) it filters to
                sockets that are bound and receiving, which `ss` reports
                as State=UNCONN. Because `-l` already applies that
                filter for both protocols, the parsing below trusts
                ss's own selection rather than re-filtering on the
                State column itself, which would require treating TCP
                and UDP's "is this listening" test as two different
                string comparisons for no extra safety.
      -n        numeric ports/addresses (no DNS/service-name lookups,
                which would be slow and make output host-resolver-
                dependent instead of a stable fact about the socket).
      -H        suppress the header row, so there's no first-line
                special case to skip.

    No -p (process attribution): resolving the owning process for
    sockets you don't own requires elevated privileges, and running
    unprivileged would make baseline quality silently depend on
    which UID happened to run the command. 
    """
    try:
        result = subprocess.run(
            ["ss", "-tulnH"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise PortQueryError(
            "ss not found -- is iproute2 installed on this host?"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise PortQueryError(f"ss failed: {exc.stderr.strip()}") from exc

    sockets: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        # Columns (with -H, no header row to skip): Netid State
        # Recv-Q Send-Q LocalAddress:Port PeerAddress:Port [Process].
        # split() on whitespace is safe here -- none of the fields
        # ss emits in this mode contain embedded spaces.
        fields = line.split()
        if len(fields) < 5:
            # Defensive: skip a line ss's own format doesn't match
            # instead of crashing the whole plugin over one
            # unparseable row.
            continue

        protocol = fields[0]
        local_address_port = fields[4]

        # rpartition, not split(":"), because IPv6 addresses are
        # bracketed and contain their own colons, e.g. "[::]:22" or
        # "[fe80::1]:53". The port is always everything after the
        # LAST colon, so rpartition's right-anchored split handles
        # both "0.0.0.0:22" and "[::]:22" with the same logic,
        # no separate IPv4/IPv6 branch needed.
        address, _, port = local_address_port.rpartition(":")

        # protocol:address:port as the resource key: address alone
        # isn't unique (a service can bind the same port on both
        # 0.0.0.0 and [::]), and port alone obviously isn't either.
        resource_key = f"{protocol}:{address}:{port}"
        sockets[resource_key] = {
            "protocol": protocol,
            "address": address,
            "port": port,
        }

    return sockets


def capture_baseline(config: PortsConfig) -> PluginSnapshot:
    """
    Snapshot every currently listening socket.

    `config` is unused, see PortsConfig's docstring: same reasoning
    as packages.capture_baseline(). Still a required parameter to
    satisfy plugins.base.PluginModule's uniform capture_baseline(config)
    shape.
    """
    try:
        sockets = _query_listening_sockets()
    except PortQueryError as exc:
        return PluginSnapshot(plugin=PLUGIN_NAME, error=str(exc))

    resources = [
        ResourceState(resource=key, value=value)
        for key, value in sorted(sockets.items())
    ]
    return PluginSnapshot(plugin=PLUGIN_NAME, resources=resources)


def check(config: PortsConfig, baseline: PluginSnapshot) -> list[Finding]:
    """
    Diff current listening sockets against the baseline snapshot.

    `config` unused, same reasoning as capture_baseline() above.

    A query failure here is RAISED, not caught: see
    packages.check()'s docstring for why that split exists: cli.py
    already has a home for "the plugin blew up mid-check" at the
    PluginResult level.
    """
    current = _query_listening_sockets()
    baseline_by_key = {r.resource: r.value for r in baseline.resources}

    all_keys = set(baseline_by_key) | set(current)
    findings: list[Finding] = []

    for key in sorted(all_keys):
        was_listening = key in baseline_by_key
        is_listening = key in current

        baseline_value = baseline_by_key.get(key)
        current_value = current.get(key)

        if not was_listening and is_listening:
            status = "added"
        elif was_listening and not is_listening:
            status = "removed"
        elif baseline_value != current_value:
            # Reached only when both sides are listening (the only
            # way `key` lands in all_keys without tripping the two
            # branches above), so both dicts are guaranteed non-None
            # here. In practice this rarely fires since the key
            # already encodes protocol/address/port - it would only
            # trip if a future version of this plugin adds a field
            # to the captured value (e.g. process attribution) that
            # can change without the key changing.
            status = "modified"
        else:
            status = "unchanged"

        findings.append(
            Finding(
                resource=key,
                status=status,
                baseline_value=baseline_value,
                current_value=current_value,
            )
        )

    return findings
