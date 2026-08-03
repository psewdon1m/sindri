# Scenario Development

Every operation is a scenario registered in `internal/scenarios`.

A scenario defines:

- stable action id;
- CLI path and usage;
- inputs and validators;
- risk level;
- read-only flag;
- visible steps;
- execution handler.

Scenarios must not:

- read stdin directly;
- draw terminal UI directly;
- build JSON manually;
- run unchecked shell strings;
- manage sudo directly;
- log secrets.

CLI and machine JSON mode both enter the same executor in `internal/core/executor.go`.

