import re
import secrets

import pytest

from aa.jsonio import Gate


@pytest.fixture(autouse=True)
def capture_code(monkeypatch):
    """Capture the approval code the way the operator receives it (Telegram),
    not from the database — the DB must never hold the plaintext code."""
    from aa import gates, notify

    seen = []
    orig_send = notify.send

    def _capture(text, **kw):
        m = re.search(r"aa gate approve \d+ ([A-Z0-9]{6})", text)
        if m:
            seen.append(m.group(1))
        return orig_send(text, **kw)

    monkeypatch.setattr(gates.notify, "send", _capture)
    return seen


def make(payload=None, captured=None):
    from aa import gates

    payload = payload if payload is not None else {"rand": secrets.token_hex(4)}
    try:
        gates.require("tx", "kirim 0.001", payload)
    except Gate:
        from aa import db

        row = dict(db.one("SELECT * FROM gates ORDER BY id DESC LIMIT 1"))
        row["code"] = captured[-1] if captured else None
        return row


def test_require_and_approve(home, capture_code):
    from aa import gates

    g = make({"_kind": "tx", "chain": "sepolia"}, capture_code)
    assert g["status"] == "pending"
    assert len(g["code"]) == 6
    assert gates.consume({"_kind": "tx", "chain": "sepolia"}) is None
    gates.approve(g["id"], g["code"])
    out = gates.consume({"_kind": "tx", "chain": "sepolia"})
    assert out["gate"] == g["id"]


def test_code_not_stored_plaintext(home, capture_code):
    """K2: the plaintext approval code must not be recoverable from SQLite."""
    from aa import db

    g = make({"_kind": "tx", "chain": "sepolia"}, capture_code)
    row = db.one("SELECT code, code_hash FROM gates WHERE id=?", (g["id"],))
    assert row["code"] is None
    assert row["code_hash"]
    assert g["code"] not in (row["code_hash"] or "")


def test_approve_wrong_code(home, capture_code):
    from aa import gates

    g = make({"_kind": "tx"}, capture_code)
    with pytest.raises(Exception):
        gates.approve(g["id"], "000000")
    assert gates.list_gates()[0]["status"] == "pending"


def _rewind(gid: int) -> None:
    """Move a gate's last wrong-code attempt 10 minutes into the past, so the
    backoff window (round 4) does not interfere with a test that wants to
    count wrong attempts rather than wait out the cooldown."""
    import datetime as dt

    from aa import db

    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).isoformat(timespec="seconds")
    db.execute("UPDATE gates SET last_attempt_at=? WHERE id=?", (old, gid))


def test_five_wrong_codes_lock_out(home, capture_code):
    """Lockout: 5 wrong codes reject the gate; even the right code is refused after."""
    from aa import db, gates

    g = make({"lock": 1}, capture_code)
    for _ in range(5):
        _rewind(g["id"])
        with pytest.raises(Exception, match="wrong code|too many wrong"):
            gates.approve(g["id"], "000000")
    row = db.one("SELECT status, attempts FROM gates WHERE id=?", (g["id"],))
    assert row["status"] == "rejected"
    assert row["attempts"] == 5
    assert any(x["id"] == g["id"] for x in gates.list_gates("rejected"))
    with pytest.raises(Exception, match="too many wrong"):
        gates.approve(g["id"], g["code"])
    # Still locked out on a further attempt, and never consumable.
    with pytest.raises(Exception, match="too many wrong"):
        gates.approve(g["id"], g["code"])
    assert gates.consume({"lock": 1}) is None


def test_four_wrong_then_correct_code_still_approves(home, capture_code):
    """Below the limit (4 wrong) the correct code still approves the gate."""
    from aa import db, gates

    g = make({"lock": 2}, capture_code)
    for _ in range(4):
        _rewind(g["id"])
        with pytest.raises(Exception):
            gates.approve(g["id"], "000000")
    row = db.one("SELECT status, attempts FROM gates WHERE id=?", (g["id"],))
    assert row["status"] == "pending"
    assert row["attempts"] == 4
    _rewind(g["id"])
    gates.approve(g["id"], g["code"])
    assert gates.consume({"lock": 2})["gate"] == g["id"]


def test_double_use(home, capture_code):
    from aa import gates

    g = make({"a": 1}, capture_code)
    gates.approve(g["id"], g["code"])
    assert gates.consume({"a": 1})
    assert gates.consume({"a": 1}) is None


def test_reject(home, capture_code):
    from aa import gates

    g = make({"b": 2}, capture_code)
    gates.reject(g["id"])
    assert gates.consume({"b": 2}) is None


def test_expired_not_usable(home, monkeypatch, capture_code):
    from aa import gates

    g = make({"c": 3}, capture_code)
    gates.approve(g["id"], g["code"])
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    assert gates.consume({"c": 3}) is None


def test_require_rejects_expired_approved(home, monkeypatch, capture_code):
    """K2: require() must enforce TTL too — an expired approval is not
    silently reusable, it must raise Gate for a fresh approval."""
    from aa import gates

    g = make({"c": 3}, capture_code)
    gates.approve(g["id"], g["code"])
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    with pytest.raises(Gate):
        gates.require("tx", "kirim 0.001", {"_kind": "tx", "c": 3})


def test_kill_blocks_require(home, capture_code):
    from aa import gates, guard

    guard.kill("test")
    with pytest.raises(Exception):
        gates.require("tx", "x", {"z": 9})
    guard.unkill()
    assert make({"d": 4}, capture_code)
