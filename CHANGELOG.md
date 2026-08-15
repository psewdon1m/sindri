# Changelog

## Unreleased

## 1.2.0 - 2026-08-15

- Replace pathname-only operation locking with a kernel advisory lock that
  recovers automatically after forced process termination; diagnostic records
  include boot ID and process start time to distinguish PID identities.
- Add validated Cloudflare proxy ranges to Nginx, restore original visitor IPs
  and preserve per-client rate limiting behind the orange-cloud proxy.
- Add domain/ACME DNS and HTTPS preflight, retries, diagnostics and resolver
  retry options before Certbot execution.
- Add interactive CLI input, one-line command progress and interactive approval
  for dangerous operations while keeping JSON exclusive to machine mode.
- Add persisted single-use approvals, strict JSON/input validation,
  concurrency-safe history, stale-lock recovery and bounded redacted logs.
- Make APT and systemd operations non-interactive and time-bounded; avoid the
  self-update lock recursion.
- Manage Ubuntu's `default` Nginx site, install Certbot on demand during
  certificate issuance and enforce private-key permissions when copying.
- Correct firewall idempotency, managed inventory updates, recovery replay
  protection, doctor health checks and exterminatus result reporting.

## 1.1.0

- Install and update from a prebuilt checksummed Debian package.
- Remove Go compilation and source checkout from the target VPS workflow.
- Remove Cosign/Sigstore release artifacts from the current release pipeline.

## 1.0.0

- Initial Sindri foundation: repository structure, Go core, CLI, machine JSON mode, scenario registry, validation, logging, history, lock and packaging skeleton.
- Added lifecycle commands for one shared host-level Nginx and Certbot renewal
  hooks. Head-service containers no longer own public proxy processes.
