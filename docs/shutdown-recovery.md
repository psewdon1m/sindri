# Shutdown and Recovery

`sindri shutdown` is a reversible network lockdown operation. It does not power off the operating system.

The planned operation:

1. Create a recovery bundle.
2. Preserve SSH access.
3. Stop application services and Docker workloads.
4. Reduce externally exposed network surface.
5. Store recovery state.

`sindri recovery` restores the latest shutdown recovery bundle.

The foundation build registers both scenarios and supports test-mode planning. Full host-state capture and restore are future implementation work.

