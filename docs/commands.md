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

Human CLI responses are enclosed by separators. Interactive terminals use
true-color status highlighting: `#62FF8C` for successful states, `#F83D3D` for
failures, and white for neutral output. ANSI colors are omitted when output is
redirected, when `TERM=dumb`, or when the `NO_COLOR` environment variable is
present. Machine-mode JSON never contains terminal formatting.

## Meta

- `sindri help`
- `sindri help [command]`
- `sindri version`
- `sindri history`

## System

- `sindri doctor`
- `sindri info`
- `sindri make_it_ready [--test]`
- `sindri mir [--test]` (alias for `make_it_ready`)
- `sindri reboot [--test]`
- `sindri shutdown [--test]`
- `sindri recovery [--test]`
- `sindri exterminatus [--test]`

`make_it_ready` and `mir` also install Fail2ban, configure an SSH jail for the
ports declared by OpenSSH, validate the configuration, and enable the service.
They install `nano` for the interactive `sindri nginx conf` editor as well.
Sindri writes its override to
`/etc/fail2ban/jail.d/90-sindri-sshd.local` with the `systemd` backend, a
10-minute observation window, five retries, and a one-hour ban.

## Firewall

Every `sindri firewall ...` command also accepts the `sindri fw ...` alias.

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

## Xray geodata

- `sindri geo get [container] [--test]`

When the container argument is omitted, the interactive CLI asks for its name.
For scripts, pass it directly, for example `sindri geo get node`. The command
updates `geosite.dat` and `geoip.dat` under `/usr/local/share/xray` in the
selected container. It downloads both files and their published SHA-256
checksums from the
[`runetfreedom/russia-v2ray-rules-dat`](https://github.com/runetfreedom/russia-v2ray-rules-dat)
release branch. If both installed hashes already match, the command exits
without restarting the container.

When an update is required, Sindri writes a timestamped backup under
`/var/lib/sindri/backups/geodata`, stops the selected container, replaces and
verifies both files, then starts and checks it. A failed replacement or restart
triggers an automatic rollback to the saved pair. Updating causes a brief
container interruption. Sindri retains the three newest managed backups so an
operator can also restore them manually. If the files live only in the
container writable layer, recreating the container from its image will discard
the update; mount `/usr/local/share/xray` persistently when updates must survive
container recreation.

## Shared host Nginx

- `sindri nginx install [--test]`
- `sindri nginx status`
- `sindri nginx conf [config]`
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

`nginx conf` lists regular configuration files from
`/etc/nginx/sites-available`. If exactly one file exists, Sindri opens it in
`nano` immediately. If several files exist, it displays a numbered list and
accepts either the number or exact filename. A filename can also be supplied
directly, for example `sindri nginx conf default`. Temporary files, hidden
files, directories and symbolic links are not offered. The command only edits
the selected file; run `sindri nginx reload` afterwards to validate and apply
the configuration.

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
