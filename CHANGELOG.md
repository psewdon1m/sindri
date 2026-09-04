# Changelog

## Unreleased

## 1.3.2 - 2026-09-04

- Add `sindri cert status` to list Let's Encrypt certificates with their X.509
  issuance time and full paths to `fullchain.pem` and `privkey.pem`.
- Add verified host Xray installation, root-only multi-link VLESS/REALITY
  profiles, interactive endpoint selection and persistent fail-closed TPROXY
  routing for host and Docker TCP/UDP/DNS traffic over IPv4 and IPv6.
- Add `sindri ip status` for proxy-only egress inspection plus Xray status,
  off and uninstall lifecycle commands.
- Add `sindri nginx uninstall` to purge Nginx configuration, cache and logs
  while preserving Let's Encrypt certificates.

## 1.3.1 - 2026-09-04

- Retry Fail2ban service and SSH jail readiness after startup so slow socket
  creation does not make `make_it_ready` or `mir` fail spuriously.

## 1.3.0 - 2026-09-02

- Add reusable CLI aliases, including `mir` for `make_it_ready` and `fw` for
  the complete firewall command group.
- Make base server preparation consistently update and upgrade APT packages,
  install and configure the Fail2ban SSH jail, and install Nano.
- Add framed human output with TTY-aware true-color success, failure and
  neutral states while preserving strict unformatted machine JSON.
- Add verified Xray geodata updates for an operator-selected Docker container,
  including checksum validation, retained backups, restart verification,
  no-op detection and automatic rollback.
- Add `sindri nginx conf` with automatic single-file editing and interactive
  numbered selection from `/etc/nginx/sites-available` when multiple site
  configurations exist.

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
