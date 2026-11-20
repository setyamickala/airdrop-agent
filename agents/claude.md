# Claude / MCP adapter

For Claude Desktop, Claude Code, Cursor, Zed, or any MCP stdio client.

## Config

Copy `mcp-claude.json` into the client config and fix both absolute paths:

- `command`: `<repo>/.venv/bin/python`
- `env.AIRDROP_HOME`: your agent home (default `~/.airdrop-agent`)

Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
Cursor: `.cursor/mcp.json`.

Restart the client. The server exposes 21 `aa_*` tools. Nothing is auto-run on start; there is no
background tick inside MCP — call `aa_autopilot_tick` if you want a pulse.

## Tools

`aa_status`, `aa_identity_new`, `aa_wallet_new`, `aa_wallet_list`, `aa_wallet_balance`, `aa_tx_send`,
`aa_sign_message`, `aa_telegram_join`, `aa_x_follow`, `aa_discord_grind`, `aa_email_otp`, `aa_quest_list`,
`aa_quest_run`, `aa_radar_scan`, `aa_autopilot_tick`, `aa_gate_list`, `aa_gate_approve`, `aa_daily_run`.

## Gate flow over MCP

`aa_tx_send` returns `isError: true` with `approval #N required — <summary>`. Approve out-of-band
(Telegram bot code) with `aa_gate_approve`, then call the same tool with identical arguments.
The payload hash is the lock; changing a parameter needs a new approval.

## Limits

MCP has no `--dry` flag on `aa_tx_send` (`broadcast: false` is the equivalent). `aa_quest_run` runs
headless and returns the run record; screenshots are on disk, not in the response.
