# Sindri releases

Sindri releases use tags in the form `sindri-vMAJOR.MINOR.PATCH`.

1. Update `sindri-release-manifest.json`, Debian metadata and `CHANGELOG.md`.
2. Run `go test ./...` and `make deb VERSION=X.Y.Z`.
3. Recalculate the installer and package SHA-256 values.
4. Commit and push `sindri-vX.Y.Z` to the Sindri repository.
5. `.github/workflows/release.yml` publishes the `.deb`, checksum, manifest,
   provenance and Sigstore bundles.

The immutable release is `sindri-vX.Y.Z`. The workflow also refreshes the
`sindri-current` discovery release with only the signed manifest. The manifest
points to the root of this repository, pins the immutable version tag and
contains the installer checksum.

`sindri update` manages only Sindri. The bootstrap path verifies the tagged
source installer against the checksum in the manifest before executing it.
Detached Sigstore bundles are published for release-policy verification.
Sindri preserves recovery state, replaces its package and reports a structured
result. It does not install, remove or update Agent Node.
