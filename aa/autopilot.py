"""Autopilot: one loop that keeps farming while the operator sleeps.

Tick order is deliberate — discovery, then cheap social, then daily streaks, then
quests, then (optional) funded activity. Every module is individually switchable and
daily budgets are enforced from the events table.

    aa autopilot plan            # what would happen now
    aa autopilot run --minutes 120
    aa autopilot daemon          # foreground 24/7 loop
"""
from __future__ import annotations

import asyncio
import datetime as dt
import random
import time

from . import config, db, gates, guard, notify, policy, ratelimit
from .daily import run as daily_run
from .jsonio import Denied, Gate, Kill
from .log import get_logger
from .quest import dsl, runner
from .radar import pipeline as radar
from .social import discord, telegram, x
from .testnet import campaign

log = get_logger("autopilot")


def cfg() -> dict:
    return config.load_yaml("autopilot.yaml")


def mods() -> dict:
    return cfg().get("modules") or {}


def _wallet_kind(chain_kind: str) -> str:
    """db.wallets() kind for a policy chain kind ('solana' -> 'sol')."""
    return "sol" if chain_kind == "solana" else chain_kind


def _due(key: str, minutes: float) -> bool:
    last = float(db.kv_get(f"ap:last:{key}", 0) or 0)
    return (time.time() - last) >= minutes * 60


def _mark(key: str) -> None:
    db.kv_set(f"ap:last:{key}", time.time())


def _count_today(kind: str) -> int:
    return int(db.scalar("SELECT COUNT(*) FROM events WHERE kind=? AND ts>=?",
                         (kind, db.today() + "T00:00:00"), 0) or 0)


def _over_daily(kind: str, key: str) -> bool:
    limit = int((cfg().get("limit_per_day") or {}).get(key, 99))
    return _count_today(kind) >= limit


def identity_pool() -> list[dict]:
    out = []
    for i in db.identities():
        if not ratelimit.in_window(i["id"]):
            continue
        if not db.wallets(i["id"], "evm") and not db.wallets(i["id"], "sol"):
            continue
        out.append(i)
    return out


def pick_identity(seed: str = "") -> dict:
    pool = identity_pool()
    if not pool:
        raise Denied("no usable identity (need active identity + wallet inside active hours)")
    pool.sort(key=lambda i: db.scalar("SELECT MAX(ts) FROM events WHERE identity_id=?", (i["id"],), "") or "")
    return pool[0]


def plan() -> dict:
    p = {"mode": policy.mode(), "kill": config.KILL_FILE.exists(), "modules": mods(),
         "due": {}, "identity": None, "budgets": {}}
    for key in ("radar", "follow", "quests", "daily", "faucet", "campaign", "chat"):
        p["due"][key] = _due(key, float((cfg().get("intervals") or {}).get(f"{key}_min", 60)))
    p["budgets"] = {"quests_today": _count_today("quest"), "tx_today": _count_today("tx"),
                    "quest_limit": (cfg().get("limit_per_day") or {}).get("quests")}
    try:
        p["identity"] = pick_identity()["label"]
        p["due_quests"] = [q["id"] for q in dsl.next_due(5)]
    except Denied as e:
        p["error"] = str(e)
    return p


async def tick(*, headless: bool = True) -> dict:
    guard.check_kill()
    if not ratelimit.in_window():
        return {"skipped": "outside active hours", "retry_in_s": ratelimit.until_window()}
    gates.expire_old()
    actions: list[str] = []
    errors: list[str] = []

    # 1. discovery
    if mods().get("radar", True) and _due("radar", float((cfg().get("intervals") or {}).get("radar_min", 25))):
        guard.check_kill()
        try:
            ident = pick_identity()
            r = await radar.scan(ident["id"], auto=True)
            actions.append(f"radar stored={r['stored']} queued={len(r['queued'])}")
            _mark("radar")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"radar: {e}")

    # 2. social follows from config
    if mods().get("follow", True) and _due("follow", float((cfg().get("intervals") or {}).get("follow_min", 180))):
        guard.check_kill()
        try:
            ident = pick_identity()
            tg_targets = [t for t in (config.load_yaml("radar_sources.yaml").get("tg_channels") or [])
                          if t.get("auto_join")]
            if tg_targets and db.social(ident["id"], "telegram"):
                res = await telegram.follow_many(ident["id"], [t["target"] for t in tg_targets][:6])
                actions.append(f"tg_join {sum(1 for r in res if r.get('status') == 'joined')}")
            xa = [a["handle"] for a in (config.load_yaml("radar_sources.yaml").get("x_accounts") or [])
                  if a.get("auto_follow")]
            if xa and db.social(ident["id"], "x"):
                res = await x.follow(ident["id"], xa[:8])
                actions.append(f"x_follow {sum(1 for r in res if r.get('status') == 'following')}")
            _mark("follow")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"follow: {e}")

    # 2b. keep sessions warm so logins do not rot
    if mods().get("warm", True) and _due("warm", float((cfg().get("intervals") or {}).get("warm_min", 240))):
        guard.check_kill()
        try:
            from . import session as session_mod

            ident = pick_identity()
            res = await session_mod.warm_all(ident["id"], headless=headless)
            actions.append(f"warm {len(res)}")
            _mark("warm")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"warm: {e}")

    # 3. daily streaks
    if mods().get("daily", True) and _due("daily", float((cfg().get("intervals") or {}).get("daily_min", 480))):
        guard.check_kill()
        try:
            for i in identity_pool()[:2]:
                r = await daily_run(i["id"], headless=headless, max_quests=1, faucets_on=False)
                actions.append(f"daily {i['label']}: q={len(r.get('quests_done', []))}")
            _mark("daily")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"daily: {e}")

    # 4. due quests
    if mods().get("quests", True) and _due("quests", float((cfg().get("intervals") or {}).get("quests_min", 8))):
        guard.check_kill()
        if not _over_daily("quest", "quests"):
            n = int(cfg().get("max_quests_per_run", 3))
            for q in dsl.next_due(n):
                parked = db.one("SELECT 1 FROM runs WHERE quest_id=? AND status='parked' AND started_at>?",
                                (q["id"], (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=6)).isoformat(timespec="seconds")))
                if parked:
                    actions.append(f"skip {q['id']} (parked)")
                    continue
                try:
                    guard.check_kill()
                    ident = pick_identity()
                    await runner.run(q, ident["id"], headless=headless)
                    actions.append(f"quest {q['id']}")
                except Kill:
                    raise
                except Gate as e:
                    errors.append(f"gate: {e}")
                    break
                except Exception as e:  # noqa: BLE001
                    errors.append(f"quest {q.get('id')}: {e}")
                await asyncio.sleep(random.uniform(10, 30))
            _mark("quests")

    # 5. faucet top-ups
    if mods().get("faucet", True) and _due("faucet", float((cfg().get("intervals") or {}).get("faucet_min", 360))):
        guard.check_kill()
        try:
            ident = pick_identity()
            from .testnet import faucets

            chains_ = [c for c in policy.testnets()
                       if db.wallets(ident["id"], _wallet_kind(policy.chain(c).get("kind", "evm")))]
            for chain in chains_[:2]:
                guard.check_kill()
                out = await faucets.run_due(ident["id"], chain)
                got = sum(1 for r in out.get("results", []) if r.get("claimed"))
                actions.append(f"faucet {chain}: {got}/{len(out.get('results', []))}")
            _mark("faucet")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"faucet: {e}")

    # 6. funded campaign (off by default — needs gas)
    if mods().get("campaign", False) and _due("campaign", float((cfg().get("intervals") or {}).get("campaign_min", 720))):
        guard.check_kill()
        if not _over_daily("tx", "tx"):
            try:
                ident = pick_identity()
                for chain in policy.testnets()[:2]:
                    if db.wallets(ident["id"], "evm"):
                        await campaign.run(chain, ident["id"], "daily", rounds=1)
                _mark("campaign")
            except Kill:
                raise
            except Exception as e:  # noqa: BLE001
                errors.append(f"campaign: {e}")

    # 7. discord grind (opt-in)
    if mods().get("chat", False) and _due("chat", float((cfg().get("intervals") or {}).get("chat_min", 240))):
        guard.check_kill()
        try:
            for i in db.identities():
                if db.social(i["id"], "discord"):
                    discord.grind_all(i["id"], minutes_per_server=10)
                    break
            _mark("chat")
        except Kill:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"chat: {e}")

    result = {"actions": actions, "errors": errors, "mode": policy.mode()}
    db.event("autopilot", f"tick actions={len(actions)} errors={len(errors)}")
    if errors or actions:
        notify.send("🤖 autopilot tick\n" + "\n".join(actions[:10]) +
                    (("\n⚠️ " + "\n⚠️ ".join(errors[:5])) if errors else ""), silent=not errors)
    return result


async def run(minutes: int = 60, *, headless: bool = True, max_ticks: int = 0) -> dict:
    start, ticks, log_lines = time.time(), 0, []
    interval = int(cfg().get("tick_seconds", 120))
    while (time.time() - start) < minutes * 60:
        if config.KILL_FILE.exists():
            log_lines.append("KILL")
            break
        try:
            r = await tick(headless=headless)
            log_lines.append(r)
            if r.get("actions"):
                ticks += 1
        except Exception as e:  # noqa: BLE001
            log_lines.append({"error": str(e)[:300]})
        if max_ticks and ticks >= max_ticks:
            break
        await asyncio.sleep(interval + random.uniform(-20, 40))
    return {"minutes": round((time.time() - start) / 60, 1), "productive_ticks": ticks,
            "log": log_lines[-30:]}


async def daemon(*, headless: bool = True) -> None:
    notify.send(f"🟢 autopilot daemon up (mode {policy.mode()})")
    while True:
        if config.KILL_FILE.exists():
            await asyncio.sleep(60)
            continue
        try:
            await tick(headless=headless)
        except Exception as e:  # noqa: BLE001
            log.exception("tick failed")
            notify.send(f"🔴 autopilot tick error: {str(e)[:300]}")
        await asyncio.sleep(int(cfg().get("tick_seconds", 120)))


def status() -> dict:
    return {"last": {k: db.kv_get(f"ap:last:{k}") for k in ("radar", "follow", "quests", "daily", "faucet",
                                                             "campaign", "chat")},
            "kill": config.KILL_FILE.exists(), "mode": policy.mode(),
            "quests_today": _count_today("quest"), "tx_today": _count_today("tx"),
            "pool": len(identity_pool())}
