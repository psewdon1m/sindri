# Changelog

## 1.1.0

- Install and update from a prebuilt checksummed Debian package.
- Remove Go compilation and source checkout from the target VPS workflow.
- Remove Cosign/Sigstore release artifacts from the current release pipeline.

## 1.0.0

- Initial Sindri foundation: repository structure, Go core, CLI, machine JSON mode, scenario registry, validation, logging, history, lock and packaging skeleton.
- Added lifecycle commands for one shared host-level Nginx and Certbot renewal
  hooks. Head-service containers no longer own public proxy processes.
