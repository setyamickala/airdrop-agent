import asyncio

import pytest

from aa.jsonio import Denied
from aa.quest import runner


def _quest(qid="q-lock"):
    return {"id": qid, "url": "https://example.com", "steps": [{"wait": 0}]}


def test_acquire_lock_twice_denied(home):
    runner.acquire_run_lock("q-a", "id-x")
    try:
        with pytest.raises(Denied, match="already running"):
            runner.acquire_run_lock("q-a", "id-x")
        # A different quest (or identity) is a different lock.
        runner.acquire_run_lock("q-b", "id-x")
        runner.acquire_run_lock("q-a", "id-y")
    finally:
        runner.release_run_lock("q-a", "id-x")
        runner.release_run_lock("q-b", "id-x")
        runner.release_run_lock("q-a", "id-y")
    # After release the same lock can be taken again.
    runner.acquire_run_lock("q-a", "id-x")
    runner.release_run_lock("q-a", "id-x")


def test_run_denied_when_lock_held(home):
    runner.acquire_run_lock("q-lock", "id-x")
    try:
        with pytest.raises(Denied, match="already running"):
            asyncio.run(runner.run(_quest(), "id-x"))
    finally:
        runner.release_run_lock("q-lock", "id-x")


def test_dry_run_does_not_hold_lock(home):
    out = asyncio.run(runner.run(_quest(), "id-x", dry=True))
    assert out["dry"] is True
    runner.acquire_run_lock("q-lock", "id-x")
    runner.release_run_lock("q-lock", "id-x")


def test_park_broadcast_with_hash(home):
    from aa import db

    run_id = db.execute(
        "INSERT INTO runs(quest_id,identity_id,status,started_at) VALUES(?,?,?,?)",
        ("q-park", "id-x", "running", db.now()))
    db.execute("INSERT INTO quests(id,status,created_at,updated_at) VALUES(?,?,?,?)",
               ("q-park", "pending", db.now(), db.now()))
    txhash = "0x" + "ab" * 32
    out = runner._park_broadcast({"id": "q-park"}, "id-x", run_id, [], "tx",
                                 Denied(f"tx mined but reverted: {txhash}"))
    assert out is not None
    assert out["parked"] is True
    assert out["broadcast_tx"] == txhash
    assert db.one("SELECT status FROM runs WHERE id=?", (run_id,))["status"] == "parked"
    assert db.one("SELECT status FROM quests WHERE id=?", ("q-park",))["status"] == "pending"


def test_park_broadcast_without_hash_returns_none(home):
    from aa import db

    run_id = db.execute(
        "INSERT INTO runs(quest_id,identity_id,status,started_at) VALUES(?,?,?,?)",
        ("q-park2", "id-x", "running", db.now()))
    assert runner._park_broadcast({"id": "q-park2"}, "id-x", run_id, [], "tx",
                                  Denied("simulation reverted")) is None
    assert runner._park_broadcast({"id": "q-park2"}, "id-x", run_id, [], "sign",
                                  Denied("sign failed 0x" + "ab" * 32)) is None
