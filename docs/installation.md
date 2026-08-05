# Installation

Sindri is an independent local CLI. It does not contact Kernel and does not
install, update, or remove Agent Node.

Install the current prebuilt Debian package with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/psewdon1m/sindri/main/install.sh | sudo sh -s -- install
```

The VPS does not need Go, Make or a source checkout. The installer validates
Ubuntu/amd64, downloads the current release manifest and package over HTTPS,
checks the package SHA-256, installs it through APT and initializes Sindri.

Sindri discovers only its own releases. The built-in URL points to
`sindri-release-manifest.json`; that manifest contains Sindri's repository URL,
ref, source path, installer URL and installer SHA-256. Repository coordinates
are not stored in local ENV. `SINDRI_MANIFEST_URL` is reserved for an emergency
release mirror.

```bash
sudo sindri update
```
