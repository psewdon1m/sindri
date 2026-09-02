# Shared host Nginx

One VPS runs one operating-system Nginx process. Kernel, Perimetr and other
head services bind only to distinct `127.0.0.1` ports. Nginx owns public TCP
80/443, selects a service by SNI/Host and terminates TLS. Do not run a separate
Nginx container for every service.

## Command lifecycle

Run host-changing commands with `sudo`:

```bash
sudo sindri nginx install
sudo sindri nginx status
sudo sindri nginx conf
sudo sindri nginx start
sudo sindri nginx reload
sudo sindri nginx stop
```

`install` installs only the Ubuntu `nginx` package. APT is non-interactive,
package-lock waiting is bounded, and service calls have timeouts so the command
cannot wait forever. Sindri keeps an existing Ubuntu default site or creates a
minimal one, enables it, installs standalone Certbot renewal hooks and leaves a
fresh Nginx stopped. A service that was already active is not interrupted.
An already active service receives a validated zero-downtime reload so updated
Cloudflare ranges take effect immediately.

If Nginx is already installed, `nginx install` does not run APT again; it only
refreshes Sindri-managed configuration and reloads the active service.

`install` also writes
`/etc/nginx/conf.d/sindri-cloudflare-real-ip.conf`. Sindri downloads and
validates the current IPv4 and IPv6 proxy ranges from Cloudflare's official
[`ips-v4`](https://www.cloudflare.com/ips-v4) and
[`ips-v6`](https://www.cloudflare.com/ips-v6) endpoints. If that refresh is
temporarily unavailable, it uses the validated range list embedded in the
current Sindri release and records the fallback in the run log.

Only those ranges are trusted for `CF-Connecting-IP`; direct clients cannot
spoof that header. Nginx's `$remote_addr` and `$binary_remote_addr` consequently
contain the original visitor address for Cloudflare requests. Existing access
logs, upstream `X-Real-IP`/`X-Forwarded-For` headers and the example's rate and
connection limits therefore continue to operate per visitor instead of per
Cloudflare edge address.

Sindri manages the standard Ubuntu site paths:

```text
/etc/nginx/sites-available/default
/etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
```

Run `sindri nginx conf` to select and edit a regular file from
`sites-available`; when only one configuration exists it opens immediately.
You can also use `sindri nginx conf default` to select it directly. Sindri
opens the selected configuration in `nano` and reports whether the file was
changed. Then run `sindri nginx reload`.
`start` and `reload` execute `nginx -t` first and leave the service unchanged
when the complete configuration is invalid.

The repository includes a complete two-service example at
[`examples/exocortex.conf`](examples/exocortex.conf). The Debian package
installs it at `/usr/share/doc/sindri/examples/exocortex.conf`. Treat it as a
template: replace both example domains, then copy the desired contents into
`/etc/nginx/sites-available/default`. The example filename is not a
configuration path used by Sindri.

## Certificates

Certificate issuance uses Certbot standalone HTTP-01:

```bash
sudo sindri nginx stop
sudo sindri cert new kernel.example.com
sudo sindri cert new perimetr.example.com
sudo sindri nginx start
```

`cert new` installs Certbot automatically when it is missing. DNS must already
resolve to the VPS, TCP 80 must be reachable, and no process—including
Nginx—may listen on port 80 during issuance. Sindri reports a clear error when
Nginx is active instead of stopping it implicitly.

Before installing Certbot or requesting a certificate, Sindri:

1. retries DNS resolution for the requested domain;
2. retries resolution of `acme-v02.api.letsencrypt.org`;
3. validates the Let's Encrypt ACME directory over HTTPS;
4. runs APT and Certbot with `RES_OPTIONS="attempts:5 timeout:2"`.

On failure, resolver target, `/etc/resolv.conf` and `resolvectl status` are
written to the bounded Sindri run log. Sindri deliberately does not replace the
server's DNS configuration automatically: forcing public resolvers can break
private zones, VPNs and provider metadata. `sindri doctor` includes a lightweight
Let's Encrypt DNS check.

For an Ubuntu host where `systemd-resolved` is genuinely misconfigured, inspect
it first:

```bash
resolvectl status
resolvectl query acme-v02.api.letsencrypt.org
readlink -f /etc/resolv.conf
cat /etc/resolv.conf
```

The standard `/etc/resolv.conf` targets are
`/run/systemd/resolve/stub-resolv.conf` or
`/run/systemd/resolve/resolv.conf`. Resolver changes remain an explicit
operator action because they affect the entire host.

Renewal hooks installed by `nginx install` stop the shared Nginx only when it
was active and start it again after Certbot finishes. Both hook operations are
time-bounded. Kernel, Perimetr and their updater processes continue running on
loopback during that short edge interruption.

After editing the default site or renewing a certificate manually, use:

```bash
sudo sindri nginx reload
```

Never copy TLS private keys into a service repository or container.

## Cloudflare Proxy

The orange-cloud HTTP proxy is compatible with the shared host Nginx setup.
Enable it after the origin has a valid certificate and port 443 is reachable,
then select [Full (strict)](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/)
in Cloudflare. That mode requires a non-expired origin certificate matching the
hostname; otherwise Cloudflare returns error 526.

HTTP-01 can pass through the Cloudflare proxy while port 80 is forwarded to the
standalone Certbot listener. Edge redirects, Access policies or WAF rules that
intercept `/.well-known/acme-challenge/` can still prevent validation. In that
case temporarily disable proxying for issuance or move to a separately managed
DNS-01 flow.

Sindri restores real client addresses but does not automatically restrict UFW
ports 80/443 to Cloudflare ranges. Such a restriction can hide the origin, but
it is a separate firewall policy that must account for monitoring, trusted
partners and certificate-validation traffic.
