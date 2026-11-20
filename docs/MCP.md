# MCP server

`aa mcp serve` speaks JSON-RPC 2.0 over stdio. Protocol frames on stdout, logs on stderr.

## Methods

`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.

## Tools

21 operations, all prefixed `aa_`. They are split into read-only and write tools:

- Read-only (always available): `aa_status`, `aa_wallet_list`, `aa_wallet_balance`,
  `aa_quest_list`, `aa_gate_list`, `aa_session_status`, `aa_cf_status`.
- Write (everything else): identity/wallet create, tx, sign, telegram join, x follow,
  discord grind, email otp, quest run, radar scan, autopilot tick, gate approve, daily run,
  session warm.

Write tools are disabled by default. Set `MCP_ALLOW_WRITE=1` in the server env to enable
them. When write is off, a write tool returns a denial explaining that. The kill switch
blocks all write tools (read-only status checks still work), and in safe mode `aa_tx_send`,
`aa_autopilot_tick` and `aa_gate_approve` are blocked via MCP even when write is on.
`aa_wallet_new` is capped at 1..100 wallets, the same cap as the CLI.

## Errors

Tool failures come back as `result.isError = true` with the message; the transport stays alive.
Policy denials and gate prompts are not protocol errors — that's how a client distinguishes "ask the
human" from "server broke".

## Security

- No network listener; stdio only.
- Same policy/gate/KILL path as the CLI (KILL blocks write tools; read-only tools are exempt).
- `AIRDROP_HOME` must be passed in the client env, or the server uses `~/.airdrop-agent`.
- Tools never return private keys.
- `MCP_ALLOW_WRITE` (default `0`): set to `1` to enable write tools. Keep it `0` unless the
  MCP client genuinely needs to act, not just read.
- `MCP_TOKEN` (optional): when set, the server checks it on `initialize` — the client must
  send it as `params._meta.mcp_token`, `params._meta.token`, or `params.mcp_token`. A wrong
  or missing token returns JSON-RPC error `-32600` and blocks `tools/list` and `tools/call`
  for that session. When it is not set there is no token check and the server warns on
  stderr at startup.
- Token limit: standard MCP clients do not send a token in `initialize`, so a token cannot
  be made mandatory without breaking them. For stdio the real controls are the write
  opt-in above, the kill switch, and safe mode — the token is an extra layer for clients
  that can send it.

## Test by hand

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | aa mcp serve
```

## Not exposed

Browser-only flows (manual login, headful inspection), vault export/import, mode switches and
`kill/unkill`. Use the CLI for those; they are rare and benefit from a terminal.
