"""K5: MCP is read-only by default, write is opt-in (MCP_ALLOW_WRITE=1),
optional MCP_TOKEN is checked on initialize, KILL blocks write tools, safe
mode blocks tx/autopilot/gate-approve, and aa_wallet_new is capped 1..100."""
import pytest

from aa.jsonio import Denied, Kill
from aa.mcp.server import dispatch, token_ok


def _no_write(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_WRITE", raising=False)
    monkeypatch.delenv("MCP_TOKEN", raising=False)


def test_readonly_status_without_write_flag(home, monkeypatch):
    _no_write(monkeypatch)
    out = dispatch("aa_status", {})
    assert out["version"]


def test_readonly_tools_work_without_write_flag(home, monkeypatch):
    _no_write(monkeypatch)
    assert dispatch("aa_gate_list", {}) == {"gates": []}
    assert dispatch("aa_quest_list", {}) == {"quests": []}


def test_write_blocked_by_default(home, monkeypatch):
    _no_write(monkeypatch)
    with pytest.raises(Denied, match="MCP_ALLOW_WRITE"):
        dispatch("aa_wallet_new", {"identity": "x", "count": 1})


def test_write_enabled_cap_wallet_new(home, monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_WRITE", "1")
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    with pytest.raises(Denied, match="1..100"):
        dispatch("aa_wallet_new", {"identity": "x", "count": 0})
    with pytest.raises(Denied, match="1..100"):
        dispatch("aa_wallet_new", {"identity": "x", "count": 101})
    with pytest.raises(Denied, match="1..100"):
        dispatch("aa_wallet_new", {"identity": "x", "count": "abc"})


def test_token_ok(monkeypatch):
    monkeypatch.setenv("MCP_TOKEN", "secret123")
    assert not token_ok({})
    assert not token_ok({"_meta": {"token": "wrong"}})
    assert token_ok({"_meta": {"mcp_token": "secret123"}})
    assert token_ok({"_meta": {"token": "secret123"}})
    assert token_ok({"mcp_token": "secret123"})
    monkeypatch.delenv("MCP_TOKEN")
    assert token_ok({})


def test_kill_blocks_write_tool(home, monkeypatch):
    from aa import guard

    monkeypatch.setenv("MCP_ALLOW_WRITE", "1")
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    guard.kill("test")
    try:
        with pytest.raises(Kill):
            dispatch("aa_wallet_new", {"identity": "x", "count": 1})
    finally:
        guard.unkill()
    # Read-only still works while KILL is active.
    guard.kill("test")
    try:
        assert dispatch("aa_status", {})["guard"]["kill"] is True
    finally:
        guard.unkill()


def test_safe_mode_blocks_tx_autopilot_gate_approve(home, monkeypatch):
    from aa import policy

    monkeypatch.setenv("MCP_ALLOW_WRITE", "1")
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    policy.set_mode("safe")
    with pytest.raises(Denied, match="safe mode"):
        dispatch("aa_tx_send", {"chain": "sepolia", "identity": "x",
                                "to": "0x0000000000000000000000000000000000000001"})
    with pytest.raises(Denied, match="safe mode"):
        dispatch("aa_autopilot_tick", {})
    with pytest.raises(Denied, match="safe mode"):
        dispatch("aa_gate_approve", {"id": 1, "code": "AAAAAA"})


def test_missing_argument_is_denied_not_keyerror(home, monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_WRITE", "1")
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    with pytest.raises(Denied, match="missing required argument: message"):
        dispatch("aa_sign_message", {"identity": "x"})
    with pytest.raises(Denied, match="missing required argument: identity"):
        dispatch("aa_wallet_list", {})


def test_unknown_tool_raises_keyerror(home, monkeypatch):
    _no_write(monkeypatch)
    with pytest.raises(KeyError):
        dispatch("aa_nope", {})
