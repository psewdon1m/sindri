# Sindri

Sindri is a local system CLI assistant for Ubuntu Server. It is designed as the future server-side operator for Perimetr: a small native command-line tool with both a human CLI and a machine JSON interface over the same scenario registry.

The product UI is English-only by requirement.

## Current implementation

Implemented in this repository:

- Go project structure for a self-contained Linux `amd64` binary.
- Bootstrap launcher: `./sindri init`, `./sindri version`, `./sindri help`.
- Shared scenario registry for CLI and machine JSON mode.
- Input validation, risk levels, test mode, lock, run logs and history.
- Read commands: `version`, `help`, `info`, `doctor`, `history`,
  `firewall status`, `docker info` and bounded `docker logs`.
- Production system operations: base Ubuntu preparation, reboot, reversible
  network lockdown/recovery and managed-scope exterminatus.
- Production firewall operations: enable, disable, open and close.
- Production Docker operations: install, uninstall, up, down, clean and logs.
- Shared host Nginx operations: install, status, validated start, zero-downtime
  configuration reload and stop.
- Production local-user operations: add, delete and password change.
- Production certificate operations: issue, copy and delete.
- Self-update from a signed/checksummed release manifest.
- Validation, dry-run plans, operation locks, approval gates, recovery bundles
  and isolated adapter tests for destructive scenarios.
- Versioned `.deb` packaging and installer/update workflow.

Release creation and publication are documented in
[RELEASING.md](RELEASING.md).

Sindri manages only itself. Agent Node lifecycle commands are deliberately not
part of its registry, and Sindri never reads Kernel.

## Build

```bash
make test
make build
make deb VERSION=1.0.0
```

The local development machine must have Go installed. The target runtime does not need Go when installed from the built package.

## CLI examples

```bash
sindri version
sindri doctor
sindri firewall status
sindri firewall open 80 tcp --test
sindri nginx install --test
sindri nginx status
```

## Machine mode

```bash
printf '%s\n' '{"protocol_version":"1","request_id":"req-1","action":"firewall.open","test":true,"inputs":{"port":80,"protocol":"tcp"}}' | sindri machine
```
