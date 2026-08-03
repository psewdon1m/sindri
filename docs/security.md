# Security

Sindri follows these rules in the foundation build:

- Machine mode accepts only registered actions.
- JSON decoder rejects unknown top-level request fields.
- User input is validated by scenario input definitions.
- System commands are executed through argument arrays, not through shell string composition.
- Dangerous actions require approval outside `--test` mode.
- Run logs pass through basic secret redaction.
- Change operations use a global operation lock.

Future hardening work:

- persistent approval tokens;
- request idempotency cache;
- stronger stale-lock validation by boot ID and PID;
- realpath checks for destructive filesystem operations;
- managed resources scope enforcement.

