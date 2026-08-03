# JSON Protocol

Machine mode is started with:

```bash
sindri machine
```

The process reads one JSON request from stdin and writes one JSON response to stdout.

## Request

```json
{
  "protocol_version": "1",
  "request_id": "req-8472",
  "action": "firewall.open",
  "test": true,
  "inputs": {
    "port": 80,
    "protocol": "tcp"
  }
}
```

Only registered `action` values are accepted. Arbitrary shell commands are not part of the protocol.

## Success

```json
{
  "protocol_version": "1",
  "request_id": "req-8472",
  "status": "success",
  "action": "firewall.open",
  "changed": false,
  "message": "Port 80/tcp would be opened"
}
```

## Missing input

```json
{
  "protocol_version": "1",
  "request_id": "req-1",
  "status": "input_required",
  "action": "firewall.open",
  "fields": [
    {
      "name": "port",
      "type": "integer",
      "minimum": 1,
      "maximum": 65535,
      "required": true,
      "prompt": "Which port should be opened?"
    }
  ]
}
```

## Approval required

Dangerous non-test actions return `approval_required` until the approval store is implemented.

