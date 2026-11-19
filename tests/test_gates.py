import json
import secrets

import pytest
from aa.jsonio import Gate


def make(payload=None):
    """Create a pending gate; the code arrives via the local delivery channel
    (encrypted-home code file when no Telegram bot is configured)."""
    from aa import gates, config
    payload = payload if payload is not None else {"rand": secrets.token_hex(4)}
    try:
        gates.require("tx", "kirim 0.001", payload)
    except Gate:
        from aa import db
        g = db.one("SELECT * FROM gates ORDER BY id DESC LIMIT 1")
        g["code"] = (config.HOME / "gates" / f"{g['id']}.code").read_text().strip()
        return g


def test_require_and_approve(home):
    from aa import gates, db
    g = make({"_kind": "tx", "chain": "sepolia"})
    assert g["status"] == "pending"
    assert len(g["code"]) == 6
    assert gates.consume({"_kind": "tx", "chain": "sepolia"}) is None
    gates.approve(g["id"], g["code"])
    out = gates.consume({"_kind": "tx", "chain": "sepolia"})
    assert out["gate"] == g["id"]


def test_code_never_stored_plaintext(home):
    from aa import db
    g = make({"plain": 1})
    row = db.one("SELECT code, code_hash, payload FROM gates WHERE id=?", (g["id"],))
    assert not row["code"], "gate code must not be stored in plaintext in SQLite"
    assert len(row["code_hash"]) == 64
    assert g["code"] not in (row["payload"] or "")


def test_approve_wrong_code(home):
    from aa import gates
    g = make({"_kind": "tx"})
    with pytest.raises(Exception):
        gates.approve(g["id"], "000000")
    assert gates.list_gates()[0]["status"] == "pending"


def test_double_use(home):
    from aa import gates
    g = make({"a": 1})
    gates.approve(g["id"], g["code"])
    assert gates.consume({"a": 1})
    assert gates.consume({"a": 1}) is None


def test_reject(home):
    from aa import gates
    g = make({"b": 2})
    gates.reject(g["id"])
    assert gates.consume({"b": 2}) is None


def test_expired_not_usable(home, monkeypatch):
    from aa import gates
    g = make({"c": 3})
    gates.approve(g["id"], g["code"])
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    assert gates.consume({"c": 3}) is None


def test_require_respects_ttl(home, monkeypatch):
    """require() must not resurrect an expired approval (consume() already checks TTL)."""
    from aa import gates, db
    g = make({"ttl": 1})
    gates.approve(g["id"], g["code"])
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    with pytest.raises(Gate):
        gates.require("tx", "kirim 0.001", {"ttl": 1})
    row = db.one("SELECT status FROM gates WHERE id=?", (g["id"],))
    assert row["status"] == "approved", "expired approval must stay unconsumed"


def test_approve_expired_rejected(home, monkeypatch):
    from aa import gates
    g = make({"exp": 1})
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    with pytest.raises(Exception):
        gates.approve(g["id"], g["code"])


def test_kill_blocks_require(home):
    from aa import gates, guard
    guard.kill("test")
    with pytest.raises(Exception):
        gates.require("tx", "x", {"z": 9})
    guard.unkill()
    assert make({"d": 4})
