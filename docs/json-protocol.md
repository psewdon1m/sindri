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

Dangerous non-test actions first return `approval_required` with a short-lived
one-time approval ID and a plan hash. Re-submit the same action and inputs with
both values to execute the approved plan. Approval IDs are persisted with a
five-minute lifetime, are bound to the action and exact plan, and cannot be
reused. A caller cannot manufacture an approval ID.

Machine mode accepts exactly one JSON object, rejects unknown fields and input
names, and does not coerce fractional numbers into integers. Human prompts and
progress rendering are intentionally available only in regular CLI mode.
