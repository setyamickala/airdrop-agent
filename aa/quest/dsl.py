"""Quest DSL: declare a garapan once, run it forever.

Shape (YAML file in ~/.airdrop-agent/quests or inline in the DB):

  id: my-project           # slug, unique
  name: My Project
  url: https://app.example.com/tasks
  platform: generic        # galxe | zealy | layer3 | questn | intract | generic
  chain: base-sepolia
  daily: true              # re-arm every day for points
  cooldown_hours: 24
  steps:
    - goto: https://app.example.com/tasks
    - dismiss: true
    - wallet: connect
    - switch: base-sepolia
    - click: "Claim points"
    - assert_text: "Claimed"
    - screenshot: claimed

Step vocabulary is validated here so a typo fails before a browser opens.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .. import config, db
from ..jsonio import Denied

PLATFORMS = ("generic", "galxe", "zealy", "layer3", "questn", "intract", "custom")
STEP_KEYS = {
    "goto": str, "click": str, "fill": dict, "form": dict, "wallet": (str, dict), "switch": str,
    "follow": str, "like": str, "retweet": str, "post": str, "join": str, "react": str,
    "type": dict, "press": str, "select": dict, "scroll": int, "wait": (int, float),
    "assert_text": str, "screenshot": str, "faucet": dict, "tx": dict,
    "deploy": dict, "checkin": str, "manual": str, "dismiss": bool, "upload": dict,
    "sleep_rand": list, "sign": dict, "api": dict, "if_text": dict, "back": bool,
}
REQUIRED = {"id", "url", "steps"}


def _is_private_host(host: str) -> bool:
    """True for literal private/loopback/link-local addresses and local names.

    This only inspects the literal hostname. A name that resolves to a private
    address at request time is NOT caught here — the narrow allowlist in
    api_allowed() is the main defence, so only hosts the operator explicitly
    trusts (quest host, domain_allowlist, api_allowlist) can be reached at all.
    """
    h = host.strip().lower().rstrip(".")
    if h in ("localhost", "0.0.0.0", "::1"):
        return True
    if h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified)


def _host_in_list(host: str, entries) -> bool:
    h = host.lower().rstrip(".")
    for e in entries or []:
        e = str(e).strip().lower().rstrip(".").removeprefix("www.")
        if not e:
            continue
        if h == e or h.endswith("." + e):
            return True
    return False


def api_allowed(q: dict, val) -> tuple[bool, str]:
    """Check an `api` step against the allowlist rules.

    Returns (True, "") when allowed, else (False, reason). Used by validate()
    and again by the runner (defence in depth), so a quest that slips past
    validation cannot run an unapproved call.
    """
    if not isinstance(val, dict):
        return False, "api step must be a mapping with 'url'"
    url = val.get("url")
    if not isinstance(url, str) or not url:
        return False, "api step needs a 'url' string"
    method = str(val.get("method", "GET")).upper()
    if method not in ("GET", "POST"):
        return False, f"api method '{method}' is not allowed (only GET/POST)"
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "api url is not a valid URL"
    if parsed.scheme != "https":
        return False, "api url must use https"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "api url has no host"
    if _is_private_host(host):
        return False, f"api host '{host}' is a private/local address and is never allowed"
    try:
        quest_host = (urlparse(str(q.get("url") or "")).hostname or "").lower()
    except ValueError:
        quest_host = ""
    if quest_host and (host == quest_host or host.endswith("." + quest_host)):
        return True, ""
    from .. import policy

    if policy.domain_ok(host):
        return True, ""
    if _host_in_list(host, policy.cfg().get("api_allowlist") or []):
        return True, ""
    return False, (f"api host '{host}' is not allowed (must match the quest url host, "
                   "domain_allowlist, or api_allowlist in policy.yaml)")


def path_for(qid: str) -> Path:
    return config.QUEST_DIR / f"{qid}.yaml"


def validate(q: dict) -> list[str]:
    errs = []
    for k in REQUIRED:
        if k not in q:
            errs.append(f"missing required key: {k}")
    if not q.get("url"):
        errs.append("url is required")
    elif not str(q["url"]).startswith(("http://", "https://")):
        errs.append("url must start with http(s)://")
    if q.get("platform") and q["platform"] not in PLATFORMS:
        errs.append(f"platform must be one of {PLATFORMS}")
    if q.get("chain"):
        from .. import policy

        if q["chain"] not in (policy.cfg().get("chains") or {}):
            errs.append(f"chain {q['chain']} not in policy.yaml")
    steps = q.get("steps") or []
    if not isinstance(steps, list) or not steps:
        errs.append("steps must be a non-empty list")
    for i, st in enumerate(steps if isinstance(steps, list) else []):
        if not isinstance(st, dict) or len(st) != 1:
            errs.append(f"step {i}: must be a mapping with exactly one action")
            continue
        key, val = next(iter(st.items()))
        if key == "eval":
            errs.append(f"step {i}: 'eval' was removed — arbitrary JS is no longer allowed; "
                        "use click/assert_text/manual instead")
            continue
        if key not in STEP_KEYS:
            errs.append(f"step {i}: unknown action '{key}' (known: {', '.join(sorted(STEP_KEYS))})")
        elif not isinstance(val, STEP_KEYS[key]):
            errs.append(f"step {i}: '{key}' expects {STEP_KEYS[key]}")
        elif key == "api":
            ok, reason = api_allowed(q, val)
            if not ok:
                errs.append(f"step {i}: api not allowed: {reason}")
    return errs


def import_file(path: Path, *, status: str = "pending", source: str = "file") -> dict:
    q = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if q.get("id") and db.one("SELECT 1 FROM quests WHERE id=?", (q["id"],)):
        raise Denied(f"quest exists: {q['id']} (remove it first)")
    errs = validate(q)
    if errs:
        raise Denied("invalid quest: " + "; ".join(errs))
    q["id"] = str(q["id"])
    save(q, status=status, source=source, raw=Path(path).read_text(encoding="utf-8"))
    return {"id": q["id"], "name": q.get("name"), "steps": len(q["steps"]), "status": status}


def save(q: dict, *, status: str = "pending", source: str = "cli", raw: str | None = None,
         cooldown_hours: int | None = None) -> None:
    if cooldown_hours is not None:
        q["cooldown_hours"] = cooldown_hours
    body = raw or yaml.safe_dump(q, sort_keys=False, allow_unicode=True)
    now = db.now()
    db.execute(
        "INSERT INTO quests(id,project,platform,url,chain,status,score,source,yaml,meta,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(id) DO UPDATE SET url=excluded.url, chain=excluded.chain, yaml=excluded.yaml,"
        " status=excluded.status, updated_at=excluded.updated_at",
        (q["id"], q.get("project") or q.get("name") or q["id"], q.get("platform", "generic"), q.get("url"),
         q.get("chain", ""), status, int(q.get("score") or 0), source, body,
         json.dumps({k: v for k, v in q.items() if k not in ("steps",)}, default=str), now, now))


def load(qid: str) -> dict:
    r = db.one("SELECT * FROM quests WHERE id=? OR project=?", (qid, qid))
    if not r:
        raise Denied(f"quest not found: {qid}")
    q = yaml.safe_load(r["yaml"])
    q["_status"] = r["status"]
    q["_runs"] = int(db.scalar("SELECT COUNT(*) FROM runs WHERE quest_id=?", (qid,), 0) or 0)
    return q


def listing(status: str | None = None) -> list[dict]:
    q = "SELECT id,project,platform,url,chain,status,score,source,updated_at FROM quests"
    args: tuple = ()
    if status:
        q += " WHERE status=?"
        args = (status,)
    return db.rows(q + " ORDER BY score DESC, id", args)


def remove(qid: str) -> dict:
    db.execute("DELETE FROM quests WHERE id=?", (qid,))
    p = path_for(qid)
    if p.exists():
        p.unlink()
    return {"deleted": qid}


def set_status(qid: str, status: str) -> None:
    db.execute("UPDATE quests SET status=?, updated_at=? WHERE id=?", (status, db.now(), qid))


def due(q: dict) -> bool:
    if q.get("_status") in ("done", "skipped", "blocked"):
        return False
    last = db.one("SELECT started_at,status FROM runs WHERE quest_id=? ORDER BY id DESC", (q.get("id"),))
    if not last:
        return True
    if q.get("daily") and db.checked_in_today(q["id"]):
        return False
    hrs = float(q.get("cooldown_hours") or (20 if q.get("daily") else 0))
    if not last["started_at"] or not hrs:
        return True
    try:
        t = dt.datetime.fromisoformat(last["started_at"])
    except ValueError:
        return True
    return (dt.datetime.now(dt.timezone.utc) - t) > dt.timedelta(hours=hrs)


def next_due(limit: int = 5) -> list[dict]:
    out = []
    for r in listing("pending"):
        q = load(r["id"])
        if due(q):
            out.append(q)
        if len(out) >= limit:
            break
    return out


def scaffold(name: str, url: str, platform: str = "generic", chain: str = "") -> dict:
    qid = config.slug(name)
    q = {"id": qid, "name": name, "url": url, "platform": platform, "chain": chain,
         "daily": False, "steps": [
             {"goto": url},
             {"dismiss": True},
             {"wallet": "connect"},
             {"screenshot": "start"},
             {"manual": "describe the remaining manual steps"},
         ]}
    return q


def write_file(q: dict) -> Path:
    p = path_for(q["id"])
    p.write_text(yaml.safe_dump(q, sort_keys=False, allow_unicode=True))
    return p


def fingerprint(q: dict) -> str:
    return hashlib.sha256(json.dumps(q, sort_keys=True, default=str).encode()).hexdigest()[:16]
