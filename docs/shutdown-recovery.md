# Shutdown and Recovery

`sindri shutdown` is a reversible network lockdown operation. It does not power off the operating system.

The planned operation:

1. Create a recovery bundle.
2. Preserve SSH access.
3. Stop application services and Docker workloads.
4. Reduce externally exposed network surface.
5. Store recovery state.

`sindri recovery` restores the latest shutdown recovery bundle.

The real operation captures Docker workload state, active services, UFW rules
and policy in a recovery bundle before applying the lockdown. Only one active
bundle may exist. `recovery` restores the captured state and marks the bundle
recovered; a recovered bundle cannot be replayed.
