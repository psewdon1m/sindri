# Commands

## Release management

```text
sindri update
```

Sindri manages only its own release lifecycle. Agent Node installation,
updates, repair and removal are handled by Agent Node's installer.

The foundation build registers the command surface required by the technical specification. Read-only commands are implemented first. Change and dangerous commands already pass through the shared registry, validation, test mode and approval boundaries.

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

`nginx install` installs the Ubuntu Nginx and Certbot packages, disables only
the distribution's default-site symlink, installs shared standalone-renewal
hooks and leaves a fresh service stopped. An already active Nginx is never
interrupted. Create and enable
`/etc/nginx/sites-available/exocortex.conf` before running `nginx start`.
See [nginx.md](nginx.md) for the complete deployment procedure.

## Users

- `sindri user add [username] [--test]`
- `sindri user delete [username] [--test]`
- `sindri password_change [username] [--test]`

## Certificates

- `sindri cert new [domain] [--test]`
- `sindri cert cp [certificate-name] [destination] [--test]`
- `sindri cert delete [certificate-name] [--test]`
