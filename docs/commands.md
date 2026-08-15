# Commands

## Release management

```text
sindri update
```

Sindri manages only its own release lifecycle. Agent Node installation,
updates, repair and removal are handled by Agent Node's installer.

CLI commands prompt for omitted required values. Mutating commands display a
single fixed progress line, and dangerous commands require an explicit
interactive confirmation. Scripts and agents should use `sindri machine` for
JSON requests and responses.

## Meta

- `sindri help`
- `sindri help [command]`
- `sindri version`
- `sindri history`

## System

- `sindri doctor`
- `sindri info`
- `sindri make_it_ready [--test]`
- `sindri reboot [--test]`
- `sindri shutdown [--test]`
- `sindri recovery [--test]`
- `sindri exterminatus [--test]`

## Firewall

- `sindri firewall on [--test]`
- `sindri firewall off [--test]`
- `sindri firewall status`
- `sindri firewall open [port] [protocol] [--test]`
- `sindri firewall close [port] [protocol] [--test]`

## Docker

- `sindri docker install [--test]`
- `sindri docker uninstall [--test]`
- `sindri docker info`
- `sindri docker logs [lines]`
- `sindri docker clean [--test]`
- `sindri docker up [path] [--test]`
- `sindri docker down [path] [--test]`

## Shared host Nginx

- `sindri nginx install [--test]`
- `sindri nginx status`
- `sindri nginx start [--test]`
- `sindri nginx reload [--test]`
- `sindri nginx stop [--test]`

`nginx install` installs only the Ubuntu Nginx package, keeps or creates
`/etc/nginx/sites-available/default`, enables it through
`/etc/nginx/sites-enabled/default`, installs bounded standalone-renewal hooks
and configures trusted Cloudflare proxy ranges in
`/etc/nginx/conf.d/sindri-cloudflare-real-ip.conf`. A fresh service is left
stopped and an already active Nginx is never interrupted. Package and service
operations are non-interactive and bounded by timeouts.
See [nginx.md](nginx.md) for the complete deployment procedure.

## Users

- `sindri user add [username] [--test]`
- `sindri user delete [username] [--test]`
- `sindri password_change [username] [--test]`

## Certificates

- `sindri cert new [domain] [--test]`
- `sindri cert cp [certificate-name] [destination] [--test]`
- `sindri cert delete [certificate-name] [--test]`

`cert new` installs Certbot automatically when it is absent. Certificate
issuance uses standalone HTTP-01 and therefore requires port 80 to be free;
stop Nginx before issuing the certificate. Before changing packages or calling
Certbot, Sindri retries DNS resolution for the requested domain and Let's
Encrypt, then validates the ACME HTTPS directory. Certbot and APT receive
`RES_OPTIONS="attempts:5 timeout:2"` automatically.
