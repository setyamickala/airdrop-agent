import datetime as dt
import hashlib
import secrets

import pytest

from aa.jsonio import Gate


def make(payload=None):
    """Create a gate and return its row + the code — the code comes from
    create()'s return value (the only time it exists), never from the DB."""
    from aa import gates

    payload = payload if payload is not None else {"rand": secrets.token_hex(4)}
    gid, code = gates.create("tx", "kirim 0.001", payload)
    assert code is not None and len(code) == 6
    return {"id": gid, "code": code, "status": "pending"}


def test_require_and_approve(home):
    from aa import gates

    g = make({"_kind": "tx", "chain": "sepolia"})
    assert g["status"] == "pending"
    assert len(g["code"]) == 6
    assert gates.consume({"_kind": "tx", "chain": "sepolia"}) is None
    gates.approve(g["id"], g["code"])
    out = gates.consume({"_kind": "tx", "chain": "sepolia"})
    assert out["gate"] == g["id"]


def test_code_never_stored_plaintext(home):
    """H2: the DB row must have no `code` column at all — only the hash."""
    from aa import db, gates

    g = make({"_kind": "tx", "chain": "sepolia"})
    row = db.one("SELECT * FROM gates WHERE id=?", (g["id"],))
    assert "code" not in row, "plaintext gate code must not be stored in the DB"
    assert row["code_hash"] == hashlib.sha256(g["code"].encode()).hexdigest()
    # And approval still works from the hash alone.
    gates.approve(g["id"], g["code"])
    assert db.one("SELECT status FROM gates WHERE id=?", (g["id"],))["status"] == "approved"


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


def test_require_reuses_fresh_approved(home):
    """H1 (fresh path): require() reuses an approved gate inside its TTL."""
    from aa import db, gates

    g = make({"_kind": "tx", "chain": "sepolia"})
    gates.approve(g["id"], g["code"])
    gates.require("tx", "kirim 0.001", {"chain": "sepolia"})  # must not raise
    assert db.one("SELECT status FROM gates WHERE id=?", (g["id"],))["status"] == "used"


def test_require_expired_gate_rejected(home):
    """H1: an approved gate past its TTL must NOT be reused by require() —
    it is marked expired and a fresh gate is created instead."""
    from aa import db, gates

    g = make({"_kind": "tx", "chain": "sepolia"})
    gates.approve(g["id"], g["code"])
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=800)).isoformat(timespec="seconds")
    db.execute("UPDATE gates SET created_at=? WHERE id=?", (old, g["id"]))
    with pytest.raises(Gate):
        gates.require("tx", "kirim 0.001", {"chain": "sepolia"})
    assert db.one("SELECT status FROM gates WHERE id=?", (g["id"],))["status"] == "expired"
    fresh = db.one("SELECT * FROM gates WHERE status='pending' ORDER BY id DESC")
    assert fresh is not None and fresh["id"] != g["id"]
    assert fresh["payload_hash"] == db.one("SELECT payload_hash FROM gates WHERE id=?", (g["id"],))["payload_hash"]


def test_kill_blocks_require(home):
    from aa import gates, guard

    guard.kill("test")
    with pytest.raises(Exception):
        gates.require("tx", "x", {"z": 9})
    guard.unkill()
    assert make({"d": 4})
