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

Before execution, Sindri shows the immutable plan and requires both the phrase
`EXTERMINATUS` and the current hostname. The command removes only resources in
the plan or resources explicitly recorded in managed inventory, reports
already-absent items as skipped, continues after individual failures and
returns a partial-success result when cleanup was incomplete.
