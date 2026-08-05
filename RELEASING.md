# Sindri releases

Sindri releases use tags in the form `sindri-vMAJOR.MINOR.PATCH`.

1. Update `sindri-release-manifest.json`, Debian metadata and `CHANGELOG.md`.
2. Run `go test ./...` and `make deb VERSION=X.Y.Z`.
3. Recalculate the installer and package SHA-256 values.
4. Commit and push `sindri-vX.Y.Z` to the Sindri repository.
5. `.github/workflows/release.yml` publishes the `.deb`, checksum, manifest
   and provenance.

The immutable release is `sindri-vX.Y.Z`. The workflow also refreshes the
`sindri-current` discovery release with the checksummed package manifest. The manifest
points to the root of this repository, pins the immutable version tag and
contains the installer checksum.

`sindri update` manages only Sindri. The installer downloads the prebuilt
Debian package over HTTPS and verifies the SHA-256 stored in the release
manifest. Sindri preserves recovery state, replaces its package and reports a
structured result. It does not install, remove or update Agent Node.
