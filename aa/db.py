"""SQLite state: identities, wallets, socials, quests, runs, gates, spend, radar.

All platform state lives here so an agent can resume after a restart. Secrets never
land in this DB — only paths/handles and encrypted blobs in the vault.
"""
from __future__ import annotations

import datetime as dt
import json
import random
import sqlite3
import string

from . import config
from .jsonio import Denied

DB_PATH = config.DATA_DIR / "state.sqlite3"

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS identities(
  id TEXT PRIMARY KEY, label TEXT UNIQUE, persona TEXT, proxy TEXT, status TEXT DEFAULT 'active',
  notes TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS wallets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id TEXT, chain TEXT, address TEXT, label TEXT,
  kind TEXT DEFAULT 'burner', created_at TEXT, UNIQUE(identity_id, chain, address));
CREATE TABLE IF NOT EXISTS emails(
  id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id TEXT, address TEXT, provider TEXT,
  status TEXT DEFAULT 'active', created_at TEXT, UNIQUE(identity_id, address));
CREATE TABLE IF NOT EXISTS socials(
  id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id TEXT, platform TEXT, handle TEXT,
  status TEXT DEFAULT 'active', meta TEXT, created_at TEXT, UNIQUE(identity_id, platform));
CREATE TABLE IF NOT EXISTS quests(
  id TEXT PRIMARY KEY, project TEXT, platform TEXT, url TEXT, chain TEXT, status TEXT DEFAULT 'pending',
  score INTEGER DEFAULT 0, source TEXT, yaml TEXT, meta TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, quest_id TEXT, identity_id TEXT, status TEXT DEFAULT 'running',
  proof TEXT, error TEXT, started_at TEXT, ended_at TEXT);
CREATE TABLE IF NOT EXISTS run_locks(
  quest_id TEXT, identity_id TEXT, started_at TEXT, PRIMARY KEY(quest_id, identity_id));
CREATE TABLE IF NOT EXISTS gates(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, summary TEXT, payload TEXT, payload_hash TEXT,
  code_hash TEXT, code TEXT, status TEXT DEFAULT 'pending', created_at TEXT, decided_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0, last_attempt_at TEXT);
CREATE TABLE IF NOT EXISTS spend(day TEXT, chain TEXT, wallet TEXT, wei TEXT, PRIMARY KEY(day, chain, wallet));
CREATE TABLE IF NOT EXISTS checkins(project TEXT, day TEXT, status TEXT, proof TEXT, PRIMARY KEY(project, day));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, level TEXT DEFAULT 'info', kind TEXT,
  identity_id TEXT, msg TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS radar_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, source TEXT, url TEXT, text TEXT, score INTEGER DEFAULT 0,
  verdict TEXT, status TEXT DEFAULT 'new', created_at TEXT, UNIQUE(url));
CREATE TABLE IF NOT EXISTS chat_memory(
  id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id TEXT, channel TEXT, author TEXT, text TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS follows(
  identity_id TEXT, platform TEXT, target TEXT, status TEXT, ts TEXT, PRIMARY KEY(identity_id, platform, target));
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
"""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def today() -> str:
    return dt.date.today().isoformat()


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    # Migration: databases created before the wrong-code lockout fix have no
    # `attempts` column — CREATE TABLE IF NOT EXISTS never alters an existing
    # table, so add it once here. The PRAGMA check makes this idempotent:
    # db() runs on every access, and the ALTER is skipped once the column
    # exists, so pre-existing gates keep their rows/status untouched.
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(gates)")]
        if "attempts" not in cols:
            con.execute("ALTER TABLE gates ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            con.commit()
        if "last_attempt_at" not in cols:
            con.execute("ALTER TABLE gates ADD COLUMN last_attempt_at TEXT")
            con.commit()
    except sqlite3.Error:
        pass
    # One-way scrub for databases created before the gates fix: plaintext
    # approval codes must never sit in SQLite. New rows store NULL already.
    try:
        con.execute("UPDATE gates SET code=NULL WHERE code IS NOT NULL")
        con.commit()
    except sqlite3.Error:
        pass
    return con


def rows(sql: str, args: tuple = ()) -> list[dict]:
    with db() as con:
        return [dict(r) for r in con.execute(sql, args)]


def one(sql: str, args: tuple = ()) -> dict | None:
    r = rows(sql, args)
    return r[0] if r else None


def scalar(sql: str, args: tuple = (), default=None):
    r = one(sql, args)
    return next(iter(r.values())) if r else default


def execute(sql: str, args: tuple = ()) -> int:
    with db() as con:
        cur = con.execute(sql, args)
        return cur.lastrowid or cur.rowcount


def new_id(prefix: str) -> str:
    s = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{prefix}-{s}"


def event(kind: str, msg: str, identity_id: str | None = None, level: str = "info", data: dict | None = None) -> None:
    execute("INSERT INTO events(ts,level,kind,identity_id,msg,data) VALUES(?,?,?,?,?,?)",
            (now(), level, kind, identity_id, msg[:1000], json.dumps(data or {}, default=str)))
    if level in ("warn", "error"):
        import logging

        logging.getLogger("aa.events").log(20 if level == "warn" else 40, "%s: %s", kind, msg)


def kv_get(key: str, default=None):
    r = one("SELECT value FROM kv WHERE key=?", (key,))
    if not r:
        return default
    try:
        return json.loads(r["value"])
    except (TypeError, ValueError):
        return r["value"]


def kv_set(key: str, value) -> None:
    execute("INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)", (key, json.dumps(value, default=str)))


# ---------- identities ----------
def create_identity(label: str, persona: str = "casual-id", proxy: str = "", notes: str = "") -> dict:
    iid = new_id("id")
    execute("INSERT INTO identities(id,label,persona,proxy,notes,created_at) VALUES(?,?,?,?,?,?)",
            (iid, label, persona, proxy, notes, now()))
    event("identity", f"created {label}", iid)
    return {"id": iid, "label": label}


def identity(ident: str) -> dict:
    r = one("SELECT * FROM identities WHERE id=? OR label=?", (ident, ident))
    if not r:
        raise Denied(f"identity not found: {ident}")
    return r


def identities(active_only: bool = True) -> list[dict]:
    q = "SELECT * FROM identities" + (" WHERE status='active'" if active_only else "") + " ORDER BY id"
    return rows(q)


def add_wallet(identity_id: str, chain: str, address: str, label: str, kind: str = "burner") -> None:
    execute("INSERT OR IGNORE INTO wallets(identity_id,chain,address,label,kind,created_at) VALUES(?,?,?,?,?,?)",
            (identity_id, chain, address, label, kind, now()))


def wallets(identity_id: str, chain: str | None = None) -> list[dict]:
    if chain:
        return rows("SELECT * FROM wallets WHERE identity_id=? AND chain=? ORDER BY id", (identity_id, chain))
    return rows("SELECT * FROM wallets WHERE identity_id=? ORDER BY id", (identity_id,))


def add_social(identity_id: str, platform: str, handle: str, meta: dict | None = None) -> None:
    execute("INSERT OR REPLACE INTO socials(identity_id,platform,handle,meta,created_at) VALUES(?,?,?,?,?)",
            (identity_id, platform, handle, json.dumps(meta or {}), now()))


def social(identity_id: str, platform: str) -> dict | None:
    return one("SELECT * FROM socials WHERE identity_id=? AND platform=?", (identity_id, platform))


def add_email(identity_id: str, address: str, provider: str) -> None:
    execute("INSERT OR IGNORE INTO emails(identity_id,address,provider,created_at) VALUES(?,?,?,?)",
            (identity_id, address, provider, now()))


def email_of(identity_id: str) -> dict | None:
    return one("SELECT * FROM emails WHERE identity_id=? ORDER BY id LIMIT 1", (identity_id,))


# ---------- spend ----------
def add_spend(chain: str, wallet: str, wei: int) -> None:
    d = today()
    cur = int(scalar("SELECT wei FROM spend WHERE day=? AND chain=? AND wallet=?", (d, chain, wallet), 0) or 0)
    execute("INSERT OR REPLACE INTO spend VALUES(?,?,?,?)", (d, chain, wallet, str(cur + wei)))


def spent_today(chain: str, wallet: str) -> int:
    return int(scalar("SELECT wei FROM spend WHERE day=? AND chain=? AND wallet=?", (today(), chain, wallet), 0) or 0)


# ---------- checkins ----------
def record_checkin(project: str, ok: bool, proof: dict | None = None) -> None:
    execute("INSERT OR REPLACE INTO checkins VALUES(?,?,?,?)",
            (project, today(), "ok" if ok else "fail", json.dumps(proof or {}, default=str)))


def streak(project: str) -> int:
    days = {r["day"] for r in rows("SELECT day FROM checkins WHERE project=? AND status='ok'", (project,))}
    n = 0
    d = dt.date.today()
    while d.isoformat() in days:
        n += 1
        d -= dt.timedelta(days=1)
    return n


def checked_in_today(project: str) -> bool:
    return bool(one("SELECT 1 FROM checkins WHERE project=? AND day=? AND status='ok'", (project, today())))


def reset() -> None:
    """Wipe all rows (tests only; the schema is recreated by db())."""
    with db() as con:
        for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            con.execute(f"DELETE FROM {name}")
