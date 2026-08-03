# Installation

Sindri is an independent local CLI. It does not contact Kernel and does not
install, update, or remove Agent Node.

```bash
cd exocortex-sindri
sudo sh ./install.sh install
```

Sindri discovers only its own releases. The built-in URL points to
`sindri-release-manifest.json`; that manifest contains Sindri's repository URL,
ref, source path, installer URL and installer SHA-256. Repository coordinates
are not stored in local ENV. `SINDRI_MANIFEST_URL` is reserved for an emergency
release mirror.

```bash
sindri update
```
