"""Approval gates: a human code, bound to the exact payload hash.

The code is delivered only through the operator's Telegram bot. Reusing an approved
gate requires an identical payload — a changed recipient/amount/domain is a new gate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from . import config, db, notify, policy
from .jsonio import Denied, Gate
from .log import get_logger

log = get_logger("gates")

# Wrong-code lockout: after this many wrong approval codes a pending gate is
# automatically rejected and can no longer be approved, even with the right
# code. On top of the count, each wrong code also starts a backoff window
# (doubling, capped at 5 minutes) during which even the right code is refused,
# and a global cap on wrong codes per hour across all gates slows down
# guessing against many gates at once. Both are deliberately small and
# testable; the backoff base / hourly cap are env-tunable for tests.
MAX_WRONG_ATTEMPTS = 5
MAX_BACKOFF_SECONDS = 300
MAX_WRONG_PER_HOUR = 20


def _backoff_seconds(attempts: int) -> int:
    try:
        base = int(config.env("GATE_BACKOFF_BASE_SECONDS", "5"))
    except ValueError:
        base = 5
    if base <= 0:
        return 0
    return min(base * (2 ** max(0, attempts - 1)), MAX_BACKOFF_SECONDS)


def _wrong_in_last_hour() -> int:
    import datetime as dt

    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat(timespec="seconds")
    row = db.one("SELECT COUNT(*) c FROM events WHERE kind='gate' AND msg LIKE '%wrong code attempt%'"
                 " AND ts > ?", (cutoff,))
    return int((row or {}).get("c") or 0)


def _age_seconds(ts: str | None) -> int | None:
    import datetime as dt

    if not ts:
        return None
    try:
        t = dt.datetime.fromisoformat(ts)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return int((dt.datetime.now(dt.timezone.utc) - t).total_seconds())


def _hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _ttl() -> int:
    return int(policy.limits().get("gate_ttl_minutes", 720))


def pending_for(payload: dict) -> dict | None:
    return db.one("SELECT * FROM gates WHERE payload_hash=? AND status='pending' ORDER BY id DESC",
                  (_hash(payload),))


def create(kind: str, summary: str, payload: dict) -> int:
    existing = pending_for(payload)
    if existing:
        return int(existing["id"])
    code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
    # Only the hash is stored. The plaintext code lives in memory just long
    # enough to be sent to the operator's Telegram bot, and is never written
    # to SQLite (previously the `code` column held it in plaintext).
    gid = db.execute(
        "INSERT INTO gates(kind,summary,payload,payload_hash,code_hash,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (kind, summary, json.dumps(payload, default=str), _hash(payload),
         hashlib.sha256(code.encode()).hexdigest(), db.now()))
    db.event("gate", f"#{gid} {kind}: {summary[:160]}", payload.get("identity_id"), level="warn")
    notify.send(notify.gate_message(gid, kind, summary, code), silent=False)
    return gid


def require(kind: str, summary: str, payload: dict) -> None:
    """Gate unless an identical approved payload is still fresh, else raise Gate."""
    p = {**payload, "_kind": kind} if not payload.get("_kind") else payload
    h = _hash(p)
    with db.db() as con:
        r = con.execute("SELECT id,created_at FROM gates WHERE payload_hash=? AND status='approved'"
                        " ORDER BY id DESC", (h,)).fetchone()
        if r:
            if _age_min(r["created_at"]) <= _ttl():
                # Atomic single-use: only proceed if this row is still approved.
                cur = con.execute("UPDATE gates SET status='used', decided_at=? WHERE id=? AND status='approved'",
                                  (db.now(), r["id"]))
                if cur.rowcount == 1:
                    return
            else:
                # Expired approvals must not be silently reusable (previously
                # require() ignored TTL entirely, unlike consume()).
                con.execute("UPDATE gates SET status='expired' WHERE id=?", (r["id"],))
    gid = create(kind, summary, p)
    raise Gate(f"approval #{gid} required — {summary}")


def _record_wrong_attempt(gid: int) -> int:
    """Atomically count one wrong code; lock the gate out at the limit.

    The increment and the pending -> rejected flip run in a single
    connection/transaction, guarded by `status='pending'`, so concurrent
    wrong attempts cannot overshoot the limit or revive a decided gate.
    Returns the new attempt count (0 if the gate is no longer pending).
    """
    with db.db() as con:
        cur = con.execute(
            "UPDATE gates SET attempts = COALESCE(attempts, 0) + 1, last_attempt_at=?"
            " WHERE id=? AND status='pending'", (db.now(), gid))
        if cur.rowcount != 1:
            row = con.execute("SELECT attempts FROM gates WHERE id=?", (gid,)).fetchone()
            return int(row["attempts"] or 0) if row else 0
        attempts = int(con.execute(
            "SELECT attempts FROM gates WHERE id=?", (gid,)).fetchone()["attempts"] or 0)
        if attempts >= MAX_WRONG_ATTEMPTS:
            con.execute("UPDATE gates SET status='rejected', decided_at=?"
                        " WHERE id=? AND status='pending'", (db.now(), gid))
    if attempts >= MAX_WRONG_ATTEMPTS:
        db.event("gate", f"#{gid} rejected after {attempts} wrong code attempts", level="warn")
    else:
        db.event("gate", f"#{gid} wrong code attempt {attempts}/{MAX_WRONG_ATTEMPTS}", level="warn")
    return attempts


def _check_code(gid: int, code: str) -> dict:
    r = db.one("SELECT * FROM gates WHERE id=?", (gid,))
    if not r:
        raise Denied(f"gate #{gid} not found")
    if r["status"] == "rejected" and (r.get("attempts") or 0) >= MAX_WRONG_ATTEMPTS:
        raise Denied(f"gate #{gid} rejected after too many wrong code attempts")
    if r["status"] != "pending":
        raise Denied(f"gate #{gid} already {r['status']}")
    # Backoff: a wrong code buys a cooling-down window (doubling per attempt)
    # in which even the right code is refused — guessing fast is pointless.
    attempts = int(r.get("attempts") or 0)
    if attempts:
        age = _age_seconds(r.get("last_attempt_at"))
        wait = _backoff_seconds(attempts)
        if age is not None and age < wait:
            raise Denied(f"gate #{gid} cooling down after wrong code — wait {wait - age}s")
    # Global rate limit: too many wrong codes across all gates in the last
    # hour blocks further attempts (right code included) until the hour passes.
    try:
        hourly_cap = int(config.env("GATE_MAX_WRONG_PER_HOUR", str(MAX_WRONG_PER_HOUR)))
    except ValueError:
        hourly_cap = MAX_WRONG_PER_HOUR
    if hourly_cap > 0 and _wrong_in_last_hour() >= hourly_cap:
        raise Denied("too many wrong approval codes in the last hour — try again later")
    given = code.strip().upper()
    # Hash-only comparison: the plaintext code is never stored (see create()).
    # Legacy rows created before this fix still carry a code_hash, so they
    # keep working; their stale plaintext `code` value is scrubbed on read
    # by db.db() and must not be trusted.
    ok = hmac.compare_digest(hashlib.sha256(given.encode()).hexdigest(), r["code_hash"] or "")
    if not ok:
        attempts = _record_wrong_attempt(gid)
        if attempts >= MAX_WRONG_ATTEMPTS:
            raise Denied(f"gate #{gid} rejected after too many wrong code attempts")
        raise Denied(f"wrong code for gate #{gid}")
    # A correct code on attempt 1..4 still approves: the gate becomes
    # approved and the attempt count no longer matters.
    return r


def approve(gid: int, code: str) -> dict:
    r = _check_code(gid, code)
    db.execute("UPDATE gates SET status='approved', decided_at=? WHERE id=?", (db.now(), gid))
    db.event("gate", f"#{gid} approved", level="info")
    try:
        payload = json.loads(r["payload"] or "{}")
    except ValueError:
        payload = {}
    if payload.get("domain"):
        policy.allow_domain(payload["domain"])
    if payload.get("quest_yaml"):
        db.execute("UPDATE quests SET status='pending', updated_at=? WHERE id=?", (db.now(), payload["quest_id"]))
    return {"gate": gid, "status": "approved", "kind": r["kind"]}


def reject(gid: int, reason: str = "") -> dict:
    db.execute("UPDATE gates SET status='rejected', decided_at=? WHERE id=?", (db.now(), gid))
    if reason:
        db.execute("UPDATE gates SET summary=summary||? WHERE id=?", (f" (reject: {reason})", gid))
    db.event("gate", f"#{gid} rejected {reason}")
    return {"gate": gid, "status": "rejected"}


def consume(payload: dict) -> dict | None:
    candidates = [payload]
    if not payload.get("_kind"):
        candidates.append({**payload, "_kind": "tx"})
    with db.db() as con:
        r = None
        for p in candidates:
            r = con.execute("SELECT id,created_at FROM gates WHERE payload_hash=? AND status='approved'"
                            " ORDER BY id DESC", (_hash(p),)).fetchone()
            if r and _age_min(r["created_at"]) <= _ttl():
                break
            r = None
        if not r:
            return None
        # Atomic single-use: only the caller that flips approved -> used wins.
        cur = con.execute("UPDATE gates SET status='used' WHERE id=? AND status='approved'", (r["id"],))
        if cur.rowcount != 1:
            return None
        return {"gate": r["id"]}


def list_gates(status: str = "pending") -> list[dict]:
    out = db.rows("SELECT id,kind,summary,status,created_at FROM gates WHERE status=? ORDER BY id DESC LIMIT 50",
                  (status,))
    for g in out:
        age = _age_min(g["created_at"])
        g["age_min"] = age
        g["expired"] = age > _ttl()
    return out


def _age_min(ts: str) -> int:
    import datetime as dt

    try:
        t = dt.datetime.fromisoformat(ts)
    except ValueError:
        return 0
    return int((dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 60)


def expire_old() -> int:
    cutoff = _ttl()
    n = 0
    # Expire both pending and approved gates past TTL; previously approved
    # gates were never expired, which is what let require() reuse them.
    for g in db.rows("SELECT id FROM gates WHERE status IN ('pending', 'approved')"):
        if _age_min(db.one("SELECT created_at FROM gates WHERE id=?", (g["id"],))["created_at"]) > cutoff:
            db.execute("UPDATE gates SET status='expired' WHERE id=?", (g["id"],))
            n += 1
    return n


def poll_telegram() -> dict:
    """Ingest `approve <id> <CODE>` / `reject <id>` / `mode ...` from the owner only."""
    token, owner = config.env("TG_REPORT_BOT_TOKEN"), config.env("TG_OWNER_USER_ID")
    if not (token and owner):
        return {"updated": {}, "note": "TG_OWNER_USER_ID/TG_REPORT_BOT_TOKEN unset"}
    import requests

    state_file = config.DATA_DIR / "tg_offset.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {"offset": 0}
    r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates",
                     params={"offset": state["offset"], "timeout": 0,
                             "allowed_updates": '["message"]'}, timeout=20).json()
    changed: dict = {}
    for upd in r.get("result", []):
        state["offset"] = upd["update_id"] + 1
        msg = upd.get("message") or {}
        if str((msg.get("from") or {}).get("id")) != str(owner):
            continue
        parts = (msg.get("text") or "").strip().lstrip("/").split()
        if not parts:
            continue
        cmd = parts[0].lower()
        if cmd == "approve" and len(parts) == 3 and parts[1].isdigit():
            try:
                changed[parts[1]] = approve(int(parts[1]), parts[2])["status"]
            except SystemExit as e:
                changed[parts[1]] = str(e)
        elif cmd == "reject" and len(parts) == 2 and parts[1].isdigit():
            changed[parts[1]] = reject(int(parts[1]))["status"]
        elif cmd == "mode" and len(parts) >= 2:
            try:
                changed["mode"] = policy.set_mode(parts[1])
            except SystemExit as e:
                changed["mode"] = str(e)
        elif cmd == "stop":
            config.KILL_FILE.touch()
            changed["kill"] = "on"
        elif cmd == "go":
            config.KILL_FILE.unlink(missing_ok=True)
            changed["kill"] = "off"
    state_file.write_text(json.dumps(state))
    return {"updated": changed}
