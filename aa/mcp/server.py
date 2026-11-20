"""Minimal MCP server (stdio JSON-RPC) so Hermes, Muse, Claude Desktop, Cursor or any
MCP client can drive the agent without shell access.

Tools return the same JSON envelope as the CLI. Nothing is printed on stdout except
protocol frames; logs go to stderr.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import sys

from .. import __version__, cli, config, guard, policy
from ..jsonio import Denied

TOOLS = [
    ("aa_status", "Agent status: mode, kill switch, identities, gates", {}),
    ("aa_identity_new", "Create a new identity (persona + proxy + wallet set)",
     {"label": {"type": "string"}, "with_email": {"type": "boolean"}, "wallet_count": {"type": "integer"}}),
    ("aa_wallet_new", "Generate burner wallets for an identity",
     {"identity": {"type": "string"}, "chain": {"type": "string"}, "count": {"type": "integer"}}),
    ("aa_wallet_list", "List wallets (addresses only)", {"identity": {"type": "string"}}),
    ("aa_wallet_balance", "Balances for an identity", {"identity": {"type": "string"}}),
    ("aa_tx_send", "Send native value through the guarded pipeline",
     {"chain": {"type": "string"}, "identity": {"type": "string"}, "label": {"type": "string"},
      "to": {"type": "string"}, "amount": {"type": "number"}, "broadcast": {"type": "boolean"}}),
    ("aa_sign_message", "Sign a message under the sign policy",
     {"identity": {"type": "string"}, "label": {"type": "string"}, "message": {"type": "string"}}),
    ("aa_telegram_join", "Join a Telegram channel/group", {"identity": {"type": "string"}, "target": {"type": "string"}}),
    ("aa_x_follow", "Follow X accounts", {"identity": {"type": "string"}, "handles": {"type": "array"}}),
    ("aa_discord_grind", "Grind chat roles in one server",
     {"identity": {"type": "string"}, "server": {"type": "string"}, "minutes": {"type": "integer"}}),
    ("aa_email_otp", "Read the latest OTP from the agent inbox",
     {"identity": {"type": "string"}, "sender": {"type": "string"}}),
    ("aa_quest_list", "List quests", {"status": {"type": "string"}}),
    ("aa_quest_run", "Run a quest", {"quest": {"type": "string"}, "identity": {"type": "string"}}),
    ("aa_radar_scan", "Scan radar sources and queue finds", {"identity": {"type": "string"}}),
    ("aa_autopilot_tick", "Run one autopilot tick", {}),
    ("aa_gate_list", "List pending approval gates", {}),
    ("aa_gate_approve", "Approve a gate with its code", {"id": {"type": "integer"}, "code": {"type": "string"}}),
    ("aa_daily_run", "Run daily check-ins for an identity", {"identity": {"type": "string"}}),
    ("aa_session_status", "Login state per platform for an identity", {"identity": {"type": "string"}}),
    ("aa_session_warm", "Warm logged-in sessions so they do not rot", {"identity": {"type": "string"}}),
    ("aa_cf_status", "Cached Cloudflare clearances", {}),
]


READ_ONLY = {
    "aa_status", "aa_wallet_list", "aa_wallet_balance", "aa_quest_list",
    "aa_gate_list", "aa_session_status", "aa_cf_status",
}
# In safe mode these write tools are blocked outright via MCP, even when
# MCP_ALLOW_WRITE=1 — safe mode means a human approves everything.
SAFE_BLOCKED = {"aa_tx_send", "aa_autopilot_tick", "aa_gate_approve"}


def write_enabled() -> bool:
    """Write tools are opt-in: MCP_ALLOW_WRITE=1 in the server env."""
    return config.env_bool("MCP_ALLOW_WRITE", False)


def token_ok(params: dict) -> bool:
    """Check the optional MCP_TOKEN against an initialize params dict.

    The token is accepted from params._meta.mcp_token, params._meta.token, or
    params.mcp_token. When MCP_TOKEN is not set there is no check (True) —
    standard MCP clients do not send a token in initialize, so a mandatory
    token would break them; for stdio the write opt-in is the main control.
    """
    token = config.env("MCP_TOKEN", "")
    if not token:
        return True
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta") or {}
    candidate = params.get("mcp_token")
    if candidate is None and isinstance(meta, dict):
        candidate = meta.get("mcp_token") or meta.get("token")
    if not isinstance(candidate, str) or not candidate:
        return False
    return hmac.compare_digest(candidate, token)


def _need(a: dict, name: str, *keys: str) -> None:
    for k in keys:
        if a.get(k) is None:
            raise Denied(f"missing required argument: {k} for {name}")


def _schema(params: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": params, "required": required or [],
            "additionalProperties": False}


def tool_list() -> list[dict]:
    out = []
    for name, desc, props in TOOLS:
        out.append({"name": name, "description": desc, "inputSchema": _schema(props)})
    return out


def dispatch(name: str, a: dict) -> dict:
    from .. import autopilot, gates, db
    from ..email import imap
    from ..quest import dsl, runner
    from ..radar import pipeline
    from ..social import discord, telegram, x
    from ..wallet import evm as evmw

    if name not in {t[0] for t in TOOLS}:
        raise KeyError(name)
    if name not in READ_ONLY:
        # Write tools are opt-in, honour the kill switch, and are partly
        # blocked in safe mode. Read-only tools skip all three so status can
        # still be checked while KILL is active or write is off.
        if not write_enabled():
            raise Denied("MCP write tools are disabled by default; set MCP_ALLOW_WRITE=1 "
                         "in the MCP server env to enable them")
        guard.check_kill()
        if policy.mode() == "safe" and name in SAFE_BLOCKED:
            raise Denied(f"{name} is blocked in safe mode via MCP")

    if name == "aa_status":
        return {"version": __version__, "guard": guard.status(), "identities": len(db.identities()),
                "gates_pending": len(gates.list_gates())}
    if name == "aa_identity_new":
        _need(a, name, "label")
        return cli.identity_new(a["label"], a.get("with_email", False), a.get("wallet_count", 1))
    if name == "aa_wallet_new":
        _need(a, name, "identity")
        try:
            count = int(a.get("count", 1))
        except (TypeError, ValueError):
            raise Denied("wallet count must be an integer 1..100")
        if count < 1 or count > 100:
            raise Denied("wallet count must be 1..100 (same cap as the CLI)")
        return {"wallets": evmw.derive(a["identity"], count)}
    if name == "aa_wallet_list":
        _need(a, name, "identity")
        return {"wallets": [{k: w[k] for k in ("label", "address", "chain")} for w in db.rows(
            "SELECT label,address,chain FROM wallets WHERE identity_id=?", (a["identity"],))]}
    if name == "aa_wallet_balance":
        _need(a, name, "identity")
        return cli.wallet_balance(a["identity"], a.get("chain"))
    if name == "aa_tx_send":
        _need(a, name, "chain", "identity", "to")
        return cli.do_send(a["chain"], a["identity"], a.get("label", "first"), a["to"],
                           a.get("amount", 0), broadcast=a.get("broadcast", False))
    if name == "aa_sign_message":
        _need(a, name, "identity", "message")
        return cli.do_sign(a["identity"], a.get("label", "first"), a["message"])
    if name == "aa_telegram_join":
        _need(a, name, "identity", "target")
        return asyncio.run(telegram.join(a["identity"], a["target"]))
    if name == "aa_x_follow":
        _need(a, name, "identity", "handles")
        return {"results": asyncio.run(x.follow(a["identity"], a["handles"]))}
    if name == "aa_discord_grind":
        _need(a, name, "identity", "server")
        return discord.grind(a["identity"], a["server"], minutes=a.get("minutes", 15))
    if name == "aa_email_otp":
        return imap.wait_otp(a.get("identity"), sender=a.get("sender", ""), timeout=120)
    if name == "aa_quest_list":
        return {"quests": dsl.listing(a.get("status"))}
    if name == "aa_quest_run":
        _need(a, name, "quest", "identity")
        q = dsl.load(a["quest"])
        return asyncio.run(runner.run(q, a["identity"], headless=True))
    if name == "aa_radar_scan":
        _need(a, name, "identity")
        return asyncio.run(pipeline.scan(a["identity"]))
    if name == "aa_autopilot_tick":
        return asyncio.run(autopilot.tick(headless=True))
    if name == "aa_gate_list":
        return {"gates": gates.list_gates()}
    if name == "aa_gate_approve":
        _need(a, name, "id", "code")
        return gates.approve(a["id"], a["code"])
    if name == "aa_daily_run":
        _need(a, name, "identity")
        return asyncio.run(cli.do_daily(a["identity"]))
    if name == "aa_session_status":
        _need(a, name, "identity")
        from .. import session

        return {"platforms": session.status(a["identity"])}
    if name == "aa_session_warm":
        _need(a, name, "identity")
        from .. import session

        return {"results": asyncio.run(session.warm_all(a["identity"]))}
    if name == "aa_cf_status":
        from ..browser import cf

        return {"clearance": cf.status()}
    raise KeyError(name)


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _token_error(rid) -> dict:
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32600, "message": "invalid request: MCP token required or incorrect"}}


def serve() -> None:
    if not config.env("MCP_TOKEN", ""):
        print("warning: MCP running without MCP_TOKEN (stdio only limits access; "
              "set MCP_TOKEN, and keep MCP_ALLOW_WRITE=0 unless write tools are needed)",
              file=sys.stderr)
    # When no token is configured the session starts authorised; when one is
    # configured, tools/list and tools/call stay rejected until initialize
    # presents the right token.
    authorized = not config.env("MCP_TOKEN", "")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        rid, method = req.get("id"), req.get("method")
        try:
            if method == "initialize":
                params = req.get("params") or {}
                authorized = token_ok(params)
                if not authorized:
                    _send(_token_error(rid))
                    continue
                _send({"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "airdrop-agent", "version": __version__}}})
            elif method in ("notifications/initialized", "initialized"):
                continue
            elif method == "tools/list":
                if not authorized:
                    _send(_token_error(rid))
                    continue
                _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": tool_list()}})
            elif method == "ping":
                _send({"jsonrpc": "2.0", "id": rid, "result": {}})
            elif method == "tools/call":
                if not authorized:
                    _send(_token_error(rid))
                    continue
                params = req.get("params") or {}
                name, args = params.get("name"), params.get("arguments") or {}
                result = dispatch(name, args)
                _send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps(result, default=str, indent=2)}],
                    "isError": False}})
            else:
                _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown method {method}"}})
        except Exception as e:  # noqa: BLE001
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}})


if __name__ == "__main__":
    serve()
