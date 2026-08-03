# Exterminatus

`sindri exterminatus` is a dangerous decommission cleanup scenario.

The command must work from an immutable plan built from:

- Docker resources;
- Certbot certificates;
- Sindri-managed certificate copies;
- users created by Sindri;
- registered project paths;
- packages installed by Sindri;
- APT repositories and keys added by Sindri;
- systemd units created by Sindri;
- Sindri backups, recovery bundles, logs and history.

The foundation build registers the scenario, risk level, approval boundary and test-mode plan. It does not execute cleanup yet.

