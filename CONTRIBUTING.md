# Contributing to configsentry

This is mainly a guide to adding a new plugin, since that's the shape
almost all contribution work here takes. If you're fixing a bug or
touching `cli.py`/`models.py` directly, the same testing/lint bar
applies, but the plugin-specific sections below won't be relevant.

## The mental model

Every plugin answers two questions, independently:

1. **What does "baseline" mean for this surface?** — captured once,
   stored as a `PluginSnapshot`.
2. **What does "drift" mean for this surface?** — computed by
   comparing a fresh capture against that stored snapshot, producing a
   list of `Finding`s.

`cli.py` never knows or cares how a plugin answers either question. It
only knows the shape every plugin promises to expose (see
`plugins/base.py`'s `PluginModule` Protocol): a `PLUGIN_NAME`, a
`capture_baseline(config)`, and a `check(config, baseline)`. That
contract is the entire integration surface. As long as your plugin
satisfies it, `cli.py` orchestrates it identically to every other
plugin — baseline capture, drift comparison, JSON/table rendering,
exit codes, all shared code you don't touch.

Why plain functions and a `Protocol` instead of a `BasePlugin` class
with subclassing: the interface was extracted *after* two plugins
(`file_integrity`, then `packages`) existed to compare against, not
designed upfront. Guessing at a shared shape before you have two real
examples tends to produce a base class that fits neither. If you're
ever tempted to add a third pattern (e.g. an `async` variant, or a
plugin that needs setup/teardown), the same rule applies: build it
concretely first, generalize once you have two.

## Files you'll touch, in order

Adding a plugin means touching four files. Do them in this order —
each one depends on the last existing:

1. **`src/configsentry/config.py`** — add a `<Name>Config` Pydantic
   model describing what a user can configure for this plugin (a list
   of names/paths, or nothing at all — see "Design decisions" below),
   and add it as an optional field on `PluginsConfig`. `None` means
   "not configured, plugin doesn't run" — that's handled generically
   by `cli.py`, you don't add branching logic for it.

2. **`src/configsentry/plugins/<name>.py`** — the plugin itself. At
   minimum: a `PLUGIN_NAME` string constant, `capture_baseline(config)
   -> PluginSnapshot`, and `check(config, baseline) -> list[Finding]`.
   If your plugin has a failure mode where the underlying tool itself
   is unusable (binary missing, command fails outright), define a
   `<Name>QueryError(PluginError)` subclass for it — subclassing
   `PluginError` is what lets `cli.py` catch it generically without
   importing your plugin by name (see `plugins/base.py`'s docstring).

3. **`src/configsentry/cli.py`** — import your plugin module and add
   one line to the `_PLUGINS` dict: `<name>.PLUGIN_NAME: (<name>,
   lambda cfg: cfg.plugins.<name>)`. That's the only place that needs
   to know your config field's name. Everything else in `cli.py` loops
   over `_PLUGINS` uniformly.

4. **`tests/test_<name>.py`** — see the testing section below.

Then update `configsentry.example.yaml` and the plugin list in
`README.md`. Easy to forget since nothing breaks if you skip them, but
they're the only docs a new user actually reads first.

## Design decisions to make before writing code

These aren't implementation details — they change what your plugin
*means*, and they're worth deciding deliberately rather than
defaulting into. Look at how the existing plugins answered them
differently:

**Named list vs. full inventory.** `file_integrity`, `services`,
`timers`, and `sysctl` take a user-specified list (paths, unit names,
tunable names) — appropriate when the full universe of possible
resources is either huge or noisy with expected churn (a host exposes
hundreds of systemd units and hundreds of sysctl keys, most either
transient/templated or irrelevant to any given threat model).
`packages` and `ports` run in full-inventory mode with no config
fields at all — appropriate when there's no sensible curated subset,
and an unexpected new entry *is* the signal you're looking for. Ask:
would a user ever want to say "watch only these five," or is "watch
everything and tell me what's new" the only sane mode?

**Per-resource errors vs. whole-plugin errors.** `file_integrity` and
`sysctl` catch failures per-resource (one unreadable file or key
becomes a `Finding` with `status="error"`, the rest of the run
continues) because each resource is read independently — a file read
or a `/proc/sys` read doesn't depend on any other file or key
succeeding. `packages`, `services`, `timers`, and `ports` treat a
query failure as whole-plugin (one subprocess call covers every
resource, so if it fails, nothing about any individual resource is
knowable) and report it via `PluginSnapshot.error` / `PluginResult.error`
instead — this is also the only case where you need a `PluginError`
subclass at all (see the pitfall below); `file_integrity` and `sysctl`
have none, because there's no whole-plugin failure mode to catch. Ask:
does querying one resource succeeding or failing depend on any other
resource? If every resource comes from one command, it's
whole-plugin. If each is fetched independently, it's per-resource —
and if it's per-resource, you probably don't need a custom exception
type either.

**Whether "equal to baseline" is the whole drift test.** Every plugin
except `services` treats "current state != baseline state" as the
complete definition of drift. `services` deliberately overrides that:
a unit whose current `ActiveState` is `failed` is *always* reported as
drift, even if the baseline was captured while it was already failed
— because a pure equality check would silently treat "captured a
broken baseline" as "no news." Ask: is there a state your plugin
should always flag regardless of what the baseline says?

## Common pitfalls

- **Forgetting the `cli.py` registration.** A plugin can have a
  correct `config.py` field and a fully working module, and still
  silently never run if it's missing from `_PLUGINS`. Nothing errors
  — the config option just does nothing. If your new plugin "isn't
  detecting anything," check this first.

- **Mocking the wrong `subprocess.run`.** Tests patch the plugin
  module's *local* binding — `monkeypatch.setattr(ports.subprocess,
  "run", fake_run)`, not `subprocess.run` directly — because `import
  subprocess` binds the module name into your plugin's namespace at
  import time. Patching the global doesn't reach it.

- **Picking a resource key that isn't stable and unique.** `ports`
  uses `protocol:address:port` instead of just `port`, because port
  alone collides across TCP/UDP and across bind addresses. If two
  distinct resources can share a key, you'll get false "unchanged"
  results — a genuinely different resource getting silently absorbed
  into another's baseline record. Whatever you pick, write a test
  that would fail if resources collided.

- **Forgetting `PluginError` as the base for your exception.** If
  your query-failure exception doesn't subclass `PluginError`, it
  propagates as a raw, uncaught exception during `check()` instead of
  landing in `PluginResult.error` the way it's supposed to — `cli.py`
  only catches `PluginError` generically, on purpose, so it doesn't
  need to import every plugin's specific exception type. This only
  applies if your plugin *has* a whole-plugin failure mode in the
  first place (see "per-resource vs. whole-plugin errors" above) —
  `file_integrity` and `sysctl` define no exception type at all,
  because a per-resource `OSError` is caught and turned into
  `Finding(status="error")` data before it ever needs to propagate.

- **Treating "config unused" as "make the parameter optional."**
  Full-inventory plugins (`packages`, `ports`) still take `config` as
  a required parameter in both functions even though they ignore it —
  because `cli.py` calls every plugin identically through the
  `PluginModule` shape. Dropping the parameter breaks the contract
  even though nothing in your plugin needs it.

- **Trusting a text format's structure more than the tool that
  produces it.** `ports` originally would have broken on IPv6
  addresses (`[::]:22`) if it split on the first `:` instead of the
  last — bracketed IPv6 addresses contain their own colons. If you're
  parsing command output, write a test with the least-common, most
  awkward real-world case you can think of, not just the happy path.

## Testing conventions

Look at `tests/test_packages.py` or `tests/test_ports.py` as the
template for anything that shells out to a system command — they
mock `subprocess.run` to return canned, tool-shaped output rather than
depending on the sandbox/CI container's real state (non-deterministic,
and CI containers won't have `dpkg`, `systemctl`, or `ss` consistently
available). `tests/test_file_integrity.py` is the template for
anything working with the real filesystem where the path under test is
itself user-supplied config — it uses `tmp_path` directly, since
filesystem operations are fast, deterministic, and sandboxed cheaply
without a fake. `tests/test_sysctl.py` is the template for the
filesystem case one level removed from that: the plugin doesn't take
a path from config, it takes a *name* and computes a path underneath
a fixed root it doesn't control directly (`/proc/sys` in production).
There, `tmp_path` alone isn't enough — the test monkeypatches the
plugin's root constant (`sysctl._SYSCTL_ROOT`) to `tmp_path` and
builds a fake layout underneath it, the same "seam for testing" role
`subprocess.run` plays in the mocking-based tests above, just for a
filesystem root instead of a subprocess call.

Every plugin's test file covers the same core cases regardless of
which pattern it follows: baseline capture succeeds, baseline capture
records an error when the underlying tool is missing, and `check()`
correctly reports `added`/`removed`/`modified`/`unchanged` (plus
`check()` raising when the tool goes missing mid-check, for
whole-plugin-error plugins). Match that coverage for a new plugin
before adding plugin-specific cases on top.

## Before opening a PR

```bash
pytest
ruff check .
```

Both need to be clean — CI runs the same two commands and will block
on either.
