# Shared host Nginx

One VPS runs one operating-system Nginx process. Kernel, Perimetr and any
future head services bind only to distinct `127.0.0.1` ports. Nginx owns public
TCP 80/443, selects a service by SNI/Host and terminates TLS. Do not run an
Nginx container per service.

## Command lifecycle

Run all mutating commands with `sudo`:

```bash
sudo sindri nginx install
sudo sindri nginx status
sudo sindri nginx start
sudo sindri nginx reload
sudo sindri nginx stop
```

`install` installs `nginx` and `certbot`, removes only Ubuntu's
`sites-enabled/default` symlink, installs shared Certbot pre/post hooks and
leaves a fresh Nginx stopped. It never interrupts a service that was already
active, overwrites a user-managed default-site file or creates the Exocortex
virtual hosts. `start` and `reload` always execute
`nginx -t` first and refuse to modify the running service when the complete
configuration is invalid.

The canonical site names are:

```text
/etc/nginx/sites-available/exocortex.conf
/etc/nginx/sites-enabled/exocortex.conf -> ../sites-available/exocortex.conf
```

The repository includes the complete two-service example at
[`examples/exocortex.conf`](examples/exocortex.conf). The Sindri Debian package
installs the same file as
`/usr/share/doc/sindri/examples/exocortex.conf`. Replace both example domains
before enabling it. A VPS that hosts only one head service uses the same
filename but keeps only that service's two server blocks. The complete
deployment order is maintained in the infrastructure deployment guide.

## Certificates

Sindri's current certificate command uses Certbot standalone HTTP-01:

```bash
sudo sindri nginx stop
sudo sindri cert new kernel.example.com
sudo sindri cert new perimetr.example.com
sudo sindri nginx start
```

DNS must already resolve to the VPS, TCP 80 must be reachable, and no other
process may listen on port 80 while a certificate is issued. Renewal hooks
installed by `nginx install` stop the one shared Nginx only when it was active
and start it again after Certbot finishes. Kernel, Perimetr and their updater
processes continue running on loopback during that short edge interruption.

After editing a site or renewing a certificate manually, use:

```bash
sudo sindri nginx reload
```

Never edit `/etc/nginx/nginx.conf` for an Exocortex service and never copy TLS
private keys into a service repository or container.
