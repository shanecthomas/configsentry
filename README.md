[![CI](https://github.com/shanecthomas/configsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/shanecthomas/configsentry/actions/workflows/ci.yml)
# configsentry

Config drift auditor for Linux hosts. Capture a baseline of the
configuration surfaces that matter (files, systemd services and
timers, listening ports, installed packages, kernel tunables, SSH
daemon hardening), then check live state against it and get an exit
code and a report a script or CI job can act on.

Environment-agnostic, detect-and-report only - no auto-remediation.

## Why

Most drift-detection tooling either wants a full agent + control
plane (Chef InSpec, Ansible + AWX) or only covers one narrow surface
(AIDE for files, `auditd` for syscalls). configsentry is a single
static binary's worth of scope: one YAML file, one baseline command,
one check command, plugin-based so each configuration surface is
independently testable and the diff logic per surface is explicit,
not hidden behind a generic rules DSL.

## Demo

<img src="assets/demo.svg" alt="configsentry running as an unprivileged user: whoami confirms testuser, baseline then check, showing a modified app.conf entry and an SSH daemon flagged for permitrootlogin/passwordauthentication" width="900">

Real terminal session, recorded end to end as an unprivileged user:
`baseline` captures current state, a user-owned config file gets an
unexpected line appended, `check` reports it as `modified` alongside
two SSH directives flagged as insecure by policy (see the `ssh`
plugin's `flag_insecure` option below) — and exits 1. No plugin in
this project requires root.

## Status

v1 complete - all seven planned plugins implemented:
- `file_integrity`
- `packages` (apt/dpkg only)
- `services` (systemd only)
- `timers` (systemd only)
- `ports` (requires `ss`/iproute2, no process attribution)
- `sysctl`
- `ssh` (requires `sshd`, resolved via `sshd -G`)

## How it works

Every plugin answers two questions independently: what does
"baseline" mean for this surface, and what counts as drift once you
have a fresh capture to compare against it. `cli.py` doesn't know or
care how any individual plugin answers either question - it only
requires each one satisfy a small structural contract
(`plugins/base.py`'s `PluginModule` Protocol), so adding surface #8
never means touching the orchestration, baseline storage, or report
rendering code. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
design rationale and how to add a new plugin.

## Usage

```bash
cp configsentry.example.yaml configsentry.yaml   # edit paths for your host
configsentry baseline
configsentry check
configsentry check --json
```

`check` exits 0 (clean), 1 (drift detected), or 2 (error)

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new plugin.
