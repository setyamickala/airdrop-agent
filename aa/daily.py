"""Daily loop: streaks, check-ins, faucet top-ups and low-risk on-chain activity.

`run` is what a cron/systemd timer calls. It is idempotent per day and stops at the
first blocked gate so the operator only sees one prompt.
"""
from __future__ import annotations

import asyncio

from . import config, db, guard, policy, ratelimit
from .jsonio import Denied, Kill
from .log import get_logger
from .quest import dsl, runner
from .testnet import faucets

log = get_logger("daily")


def plan(identity_id: str) -> dict:
    due_quests = [q for q in dsl.next_due(20) if q.get("daily") and not db.checked_in_today(q["id"])]
    chains = [c for c in policy.testnets() if db.wallets(identity_id, "evm")]
    faucet_targets = []
    for c in chains:
        try:
            faucet_targets += [f for f in faucets.for_chain(c) if f["due"]][:1]
        except Denied:
            continue
    return {"quests": [q["id"] for q in due_quests], "faucets": [f["name"] for f in faucet_targets],
            "chains": chains}


async def run(identity_id: str, *, max_quests: int = 3, faucets_on: bool = True,
              headless: bool = True) -> dict:
    guard.check_kill()
    if not ratelimit.in_window(identity_id):
        return {"skipped": "outside active hours", "retry_in_s": ratelimit.until_window()}
    p = plan(identity_id)
    done, failed = [], []
    for qid in p["quests"][:max_quests]:
        q = dsl.load(qid)
        try:
            guard.check_kill()
            await runner.run(q, identity_id, headless=headless)
            done.append(qid)
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            failed.append({"quest": qid, "error": str(e)[:200]})
            if type(e).__name__ == "Gate":
                break
        await asyncio.sleep(15)
    faucet_out = []
    if faucets_on:
        for chain in p["chains"]:
            try:
                guard.check_kill()
                faucet_out.append(await faucets.run_due(identity_id, chain))
            except Kill:
                raise
            except Exception as e:  # noqa: BLE001
                faucet_out.append({"chain": chain, "error": str(e)[:160]})
    summary = {"identity": identity_id, "quests_done": done, "quests_failed": failed,
               "faucets": len([f for f in faucet_out if any(r.get("claimed") for r in f.get("results", []))]),
               "streaks": streaks()}
    db.event("daily", f"done={len(done)} failed={len(failed)}", identity_id)
    return summary


def streaks() -> dict:
    return {r["project"]: db.streak(r["project"])
            for r in db.rows("SELECT DISTINCT project FROM checkins")}


def all_identities() -> list[str]:
    return [i["id"] for i in db.identities()]


async def run_all(**kw) -> list[dict]:
    out = []
    for iid in all_identities():
        try:
            out.append(await run(iid, **kw))
        except Exception as e:  # noqa: BLE001
            out.append({"identity": iid, "error": str(e)[:200]})
        await asyncio.sleep(30)
    return out


def status() -> dict:
    return {"today": db.today(),
            "checkins": db.rows("SELECT project,status,day FROM checkins WHERE day=? ORDER BY project", (db.today(),)),
            "streaks": streaks(), "mode": policy.mode(), "kill": config.KILL_FILE.exists()}
