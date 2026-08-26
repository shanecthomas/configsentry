[![CI](https://github.com/shanecthomas/configsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/shanecthomas/configsentry/actions/workflows/ci.yml)
# configsentry

Config drift auditor for Linux hosts. Capture a baseline of the
configuration surfaces (files, services, ports, packages,
cron, sysctl, SSH hardening), then check live state against it.

Environment-agnostic, detect-and-report only - no auto-remediation.

## Status

Early development. Currently implemented plugins: 
- `file_integrity`
- `packages` (apt/dpkg only)
- `services` (systemd only)
- `timers` (systemd only)
- `ports` (requires `ss`/iproute2, no process attribution)
- `sysctl`

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
