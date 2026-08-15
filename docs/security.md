# Security

Sindri follows these rules:

- Machine mode accepts only registered actions.
- JSON decoder accepts exactly one request and rejects unknown request and
  scenario-input fields.
- User input is validated by scenario input definitions.
- System commands are executed through argument arrays, not through shell string composition.
- Dangerous actions require a persisted, short-lived, one-time approval bound
  to the action and canonical plan outside `--test` mode.
- Run logs are size- and age-bounded and pass through secret redaction.
- Change operations use a kernel-owned advisory lock. The kernel releases it
  after normal exit, crashes and `SIGKILL`; PID, boot ID and process start time
  are retained for diagnostics and compatibility with older lock files.
- History updates are serialized and atomically replaced.
- Destructive filesystem operations are limited to recorded managed resources
  and reject protected roots and symlinks.

Future hardening work:

- request idempotency cache;
- optional cryptographic signatures for release metadata;
- more granular least-privilege execution instead of requiring root for host
  changes.
