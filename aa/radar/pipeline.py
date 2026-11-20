"""Radar pipeline: dedupe -> scam check -> score -> queue -> digest.

Auto-queued quests are deliberately generic (visit, connect, screenshot, note): the
agent still has to look at the page. High-score finds can be queued straight into the
executor when `auto_queue` is on, and the operator sees a code-gated digest in safe mode.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from .. import config, db, notify, policy, scam_check

from ..log import get_logger
from ..quest import dsl
from . import score as scoring
from . import sources

log = get_logger("radar")


def _hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:10]


def _primary_link(item: dict) -> str | None:
    order = {"quest": 0, "web": 1, "nft": 2, "telegram": 3, "x": 4, "discord": 5, "docs": 6}
    ls = sorted([l for l in item.get("links", []) if l["type"] != "docs"], key=lambda l: order.get(l["type"], 9))
    return ls[0]["url"] if ls else None


def _auto_queue(auto: bool | None) -> bool:
    """Effective auto_queue: the radar_sources.yaml value wins when the file
    mentions it; otherwise the explicit `auto` argument, else the old
    behaviour (True — queue everything worth it)."""
    try:
        cfg = config.load_yaml("radar_sources.yaml")
    except SystemExit:
        cfg = {}
    if "auto_queue" in cfg:
        return bool(cfg.get("auto_queue"))
    return True if auto is None else bool(auto)


def _check_links(item: dict) -> dict:
    """Scam-check every link in the item (not just the primary one).

    Non-allowlisted hosts get a deep check (RDAP domain age); allowlisted
    hosts stay shallow so ingest stays fast. Returns the worst verdict.
    """
    worst = {"verdict": "ok", "reasons": [], "host": ""}
    for link in item.get("links") or []:
        url = link.get("url") if isinstance(link, dict) else None
        if not url:
            continue
        host = (urlparse(url).hostname or "").lower()
        deep = not policy.domain_ok(host) if host else False
        v = scam_check.check_url(url, deep=deep)
        if v["verdict"] == "bad":
            return v
        if v["verdict"] == "warn" and worst["verdict"] == "ok":
            worst = v
    return worst


def ingest(items: list[dict], *, auto: bool | None = None) -> dict:
    """Store + score items. Returns counts and the created quest ids."""
    auto_queue = _auto_queue(auto)
    stored, queued, rejected = 0, [], 0
    for it in items:
        url = _primary_link(it)
        if not url:
            rejected += 1
            continue
        if db.one("SELECT 1 FROM radar_items WHERE url=?", (url,)):
            rejected += 1
            continue
        verdict = _check_links(it)
        ok, s, why = scoring.worth_it(it, int(it.get("trust") or 1))
        nid = db.execute("INSERT OR IGNORE INTO radar_items(kind,source,url,text,score,verdict,created_at)"
                         " VALUES(?,?,?,?,?,?,?)",
                         (it.get("kind"), it.get("source"), url, (it.get("text") or "")[:2000], s,
                          verdict["verdict"], db.now()))
        if not nid:
            continue
        stored += 1
        db.event("radar", f"{s} {url}", data={"why": why})
        if not ok or verdict["verdict"] == "bad":
            rejected += 1
            continue
        if not auto_queue:
            # Stored (and scored) but deliberately not turned into a quest:
            # the operator reviews it from `aa radar latest` first.
            continue
        qid = create_quest(it, url, s)
        db.execute("UPDATE radar_items SET status='queued' WHERE url=?", (url,))
        queued.append(qid)
    if queued:
        digest(queued)
    return {"stored": stored, "queued": queued, "rejected": rejected}


def create_quest(item: dict, url: str, s: int) -> str:
    qid = f"radar-{config.slug(item.get('project') or urlparse(url).hostname or 'find')[:24]}-{_hash(url)[:6]}"
    steps: list[dict] = [{"goto": url}, {"dismiss": True}, {"screenshot": "landing"}]
    kinds = {l["type"] for l in item.get("links", [])}
    if "x" in kinds:
        handle = next((urlparse(l["url"]).path.strip("/") for l in item["links"] if l["type"] == "x"), "")
        if handle:
            steps.append({"follow": "@" + handle})
    if "telegram" in kinds:
        tg = next((l["url"] for l in item["links"] if l["type"] == "telegram"), "")
        if tg:
            steps.append({"join": tg})
    steps += [{"wallet": "connect"},
              {"manual": f"review {item.get('kind')} flow; score {s}. {item.get('text', '')[:300]}"},
              {"screenshot": "after_connect"}]
    q = {"id": qid, "name": item.get("project") or qid, "url": url, "platform": "generic",
         "chain": (item.get("hints") or {}).get("chains", [""])[0] if item.get("hints") else "",
         "source": item.get("source"), "score": s, "gate": policy.mode() != "turbo",
         "steps": steps}
    dsl.save(q, status="pending", source="radar")
    dsl.write_file(q)
    return qid


def digest(quest_ids: list[str]) -> None:
    if not quest_ids:
        return
    lines = [f"🛰 <b>{len(quest_ids)} temuan radar baru</b> (mode {policy.mode()})"]
    for qid in quest_ids[:8]:
        r = db.one("SELECT q.score, q.project, q.url, r.kind FROM quests q LEFT JOIN radar_items r"
                   " ON q.url=r.url WHERE q.id=?", (qid,))
        if r:
            lines.append(f"• [{r['score']}] {r['project']} ({r['kind']}) {r['url'][:90]}\n  <code>aa quest run {qid}</code>")
    lines.append("\nSumber tetap UNTRUSTED — kode approval hanya dari bot ini.")
    notify.send("\n".join(lines), digest=True)


async def scan(radar_identity: str, *, include_x: bool = True, include_tg: bool = True,
               auto: bool | None = None) -> dict:
    items: list[dict] = []
    errors = []
    if include_tg:
        try:
            items += await sources.scan_telegram(radar_identity)
        except Exception as e:  # noqa: BLE001
            errors.append(f"tg: {e}")
    if include_x:
        items += sources.scan_x_accounts()
        try:
            items += await sources.scan_x_queries(radar_identity)
        except Exception as e:  # noqa: BLE001
            errors.append(f"x-search: {e}")
    res = ingest(items, auto=auto)
    res["errors"] = errors
    res["kinds"] = {}
    for it in items:
        res["kinds"][it.get("kind", "?")] = res["kinds"].get(it.get("kind", "?"), 0) + 1
    db.event("radar", f"scan items={len(items)} queued={len(res['queued'])}")
    return res


def latest(limit: int = 20, min_score: int = 0) -> list[dict]:
    return db.rows("SELECT * FROM radar_items WHERE score>=? ORDER BY id DESC LIMIT ?", (min_score, limit))


def by_kind() -> list[dict]:
    return db.rows("SELECT kind, COUNT(*) n, ROUND(AVG(score),1) avg FROM radar_items GROUP BY kind ORDER BY n DESC")


def clear(status: str = "new") -> dict:
    n = db.execute("DELETE FROM radar_items WHERE status=?", (status,))
    return {"deleted": n}
