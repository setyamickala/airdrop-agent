"""Gate backoff + global hourly rate limit (round 4, priority 3b)."""
import datetime as dt

import pytest

from aa.jsonio import Denied
from tests.test_gates import capture_code, make  # reuse the code-capture fixture


def test_wrong_code_starts_backoff(home, capture_code):
    from aa import db, gates

    g = make({"backoff": 1}, capture_code)
    with pytest.raises(Denied, match="wrong code"):
        gates.approve(g["id"], "000000")
    # Even the right code is refused inside the backoff window (base 5s).
    with pytest.raises(Denied, match="cooling down"):
        gates.approve(g["id"], capture_code[-1])
    # After the window passes, the right code works again.
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).isoformat(timespec="seconds")
    db.execute("UPDATE gates SET last_attempt_at=? WHERE id=?", (old, g["id"]))
    assert gates.approve(g["id"], capture_code[-1])["status"] == "approved"


def test_backoff_doubles_with_attempts(home, capture_code, monkeypatch):
    from aa import db, gates

    monkeypatch.setenv("GATE_BACKOFF_BASE_SECONDS", "10")
    g = make({"backoff": 2}, capture_code)
    for _ in range(2):
        with pytest.raises(Denied, match="wrong code"):
            gates.approve(g["id"], "000000")
        # Move the clock past the first window only, so the second attempt's
        # 20s window still blocks.
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=11)).isoformat(timespec="seconds")
        db.execute("UPDATE gates SET last_attempt_at=? WHERE id=?", (old, g["id"]))
    with pytest.raises(Denied, match="cooling down"):
        gates.approve(g["id"], capture_code[-1])


def test_global_hourly_rate_limit(home, capture_code, monkeypatch):
    from aa import gates

    monkeypatch.setenv("GATE_BACKOFF_BASE_SECONDS", "0")  # isolate the global cap
    monkeypatch.setenv("GATE_MAX_WRONG_PER_HOUR", "2")
    g1 = make({"gl": 1}, capture_code)
    g2 = make({"gl": 2}, capture_code)
    g3 = make({"gl": 3}, capture_code)
    with pytest.raises(Denied, match="wrong code"):
        gates.approve(g1["id"], "000000")
    with pytest.raises(Denied, match="wrong code"):
        gates.approve(g2["id"], "000000")
    # Two wrong codes this hour hit the cap: even a right code is refused.
    with pytest.raises(Denied, match="too many wrong approval codes"):
        gates.approve(g3["id"], capture_code[-1])
