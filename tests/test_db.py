def test_identity_and_wallet_rows(ident):
    from aa import db

    assert db.identity(ident)["label"] == "tester"
    assert len(db.wallets(ident, "evm")) == 2
    assert len(db.wallets(ident, "sol")) == 1
    w = db.wallets(ident, "evm")[0]
    assert w["address"].startswith("0x")


def test_spend_window(ident):
    from aa import db

    w = db.wallets(ident, "evm")[0]
    db.add_spend("sepolia", w["address"], 10)
    assert db.spent_today("sepolia", w["address"]) == 10
    assert db.spent_today("base", w["address"]) == 0


def test_kv(ident):
    from aa import db

    assert db.kv_get("k") is None
    db.kv_set("k", "v")
    assert db.kv_get("k") == "v"


def test_identity_resolve_by_label(ident):
    from aa import db

    assert db.identity("tester")["id"] == ident
    assert db.identity(ident)["id"] == ident


def _fake_local_ahead(monkeypatch, db):
    """Simulate a machine whose local date is ahead of UTC (e.g. WIB after midnight)."""
    import datetime as real_dt
    import types

    class FakeDate(real_dt.date):
        @classmethod
        def today(cls):
            return real_dt.datetime.now(real_dt.timezone.utc).date() + real_dt.timedelta(days=1)

    monkeypatch.setattr(db, "dt", types.SimpleNamespace(
        date=FakeDate, datetime=real_dt.datetime, timedelta=real_dt.timedelta,
        timezone=real_dt.timezone))


def test_today_is_utc(home, monkeypatch):
    import datetime as real_dt
    from aa import db
    _fake_local_ahead(monkeypatch, db)
    assert db.today() == real_dt.datetime.now(real_dt.timezone.utc).date().isoformat(), \
        "day boundaries must match the UTC timestamps used in events/spend"


def test_daily_budget_counts_utc_events(home, monkeypatch):
    from aa import db, autopilot
    db.event("quest", "start x")
    _fake_local_ahead(monkeypatch, db)
    assert autopilot._count_today("quest") == 1, \
        "events written now (UTC) must count toward today's budget even when local date differs"


def test_connections_closed(home):
    import gc
    import sqlite3
    from aa import db

    def live():
        return sum(1 for o in gc.get_objects() if isinstance(o, sqlite3.Connection))

    base = live()
    for _ in range(50):
        db.scalar("SELECT 1")
    assert live() - base <= 2, "db helpers must close their connections, not leak them to the GC"


def test_add_spend_atomic(home):
    import threading
    from aa import db
    n_threads, n_ops = 8, 100
    barrier = threading.Barrier(n_threads)

    def worker():
        barrier.wait()
        for _ in range(n_ops):
            db.add_spend("sepolia", "w-atomic", 1)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert db.spent_today("sepolia", "w-atomic") == n_threads * n_ops, \
        "concurrent spend updates must not lose increments (daily cap integrity)"
