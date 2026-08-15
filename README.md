# Sindri

Sindri is a local system CLI assistant for Ubuntu Server. It is designed as the future server-side operator for Perimetr: a small native command-line tool with both a human CLI and a machine JSON interface over the same scenario registry.

The product UI is English-only by requirement.

## Current implementation

Implemented in this repository:

- Go project structure for a self-contained Linux `amd64` binary.
- Bootstrap launcher: `./sindri init`, `./sindri version`, `./sindri help`.
- Shared scenario registry for CLI and machine JSON mode.
- Interactive CLI prompts, a fixed terminal progress line and a separate strict
  JSON machine interface.
- Input validation, one-time approvals, test mode, stale-lock recovery, bounded
  redacted run logs and concurrency-safe history.
- Read commands: `version`, `help`, `info`, `doctor`, `history`,
  `firewall status`, `docker info` and bounded `docker logs`.
- Production system operations: base Ubuntu preparation, reboot, reversible
  network lockdown/recovery and managed-scope exterminatus.
- Production firewall operations: enable, disable, open and close.
- Production Docker operations: install, uninstall, up, down, clean and logs.
- Shared host Nginx operations: install, status, validated start, zero-downtime
  configuration reload and stop, including trusted Cloudflare proxy ranges and
  restoration of the original visitor IP.
- Production local-user operations: add, delete and password change.
- Production certificate operations: issue, copy and delete.
- DNS and Let's Encrypt connectivity preflight with resolver retries before
  certificate issuance.
- Self-update from a checksummed HTTPS release manifest.
- Validation, dry-run plans, operation locks, approval gates, recovery bundles
  and isolated adapter tests for destructive scenarios.
- Versioned `.deb` packaging and installer/update workflow.

Release creation and publication are documented in
[RELEASING.md](RELEASING.md).

Sindri manages only itself. Agent Node lifecycle commands are deliberately not
part of its registry, and Sindri never reads Kernel.

## Production installation

Sindri has no editable runtime `.env`. Install the latest stable prebuilt
package with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/psewdon1m/sindri/main/install.sh | sudo sh -s -- install
```

The installer validates Ubuntu/amd64, downloads the `.deb` over HTTPS, checks
its SHA-256 and runs `sindri init`. Go is not installed on the target VPS.

## Build

```bash
make test
make build
make deb VERSION=1.2.0
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
sindri cert new example.com
```

When a required CLI argument is omitted, Sindri asks for it in the terminal.
Mutating commands show progress on one fixed bottom line and dangerous commands
ask for an explicit confirmation. JSON responses are emitted only by
`sindri machine`.

## Machine mode

```bash
printf '%s\n' '{"protocol_version":"1","request_id":"req-1","action":"firewall.open","test":true,"inputs":{"port":80,"protocol":"tcp"}}' | sindri machine
```
