"""Quest runner: turns declarative steps into browser + chain actions.

Every step is recorded as proof. A failed step retries once, screenshots, then either
continues (soft) or aborts the quest (hard). Nothing here bypasses `safe_send`/guards.
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import sqlite3
from urllib.parse import urlparse

from .. import config, db, gates, guard, policy
from ..browser import flows
from ..browser.engine import Browser
from ..jsonio import Denied, Gate
from ..log import get_logger
from ..social import telegram, x
from ..testnet import faucets
from ..wallet import send as sender
from . import adapters

log = get_logger("quest")
HARD = {"assert_text", "goto", "tx", "deploy", "sign"}
# Steps that move value or sign: exactly one attempt, never retried blindly —
# a second attempt could broadcast a second transaction. If the single
# attempt fails after a broadcast, run() parks on the tx hash instead.
NO_RETRY_STEPS = {"tx", "deploy", "sign"}
_TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")


def acquire_run_lock(quest_id: str, identity_id: str) -> None:
    """Atomic per-quest+identity lock (run_locks PK). A second concurrent run
    for the same quest+identity is denied instead of double-executing."""
    try:
        db.execute("INSERT INTO run_locks(quest_id,identity_id,started_at) VALUES(?,?,?)",
                   (quest_id, identity_id, db.now()))
    except sqlite3.IntegrityError:
        raise Denied(f"quest {quest_id} is already running for {identity_id} (run lock held)")


def release_run_lock(quest_id: str, identity_id: str) -> None:
    db.execute("DELETE FROM run_locks WHERE quest_id=? AND identity_id=?", (quest_id, identity_id))


def _park_broadcast(q: dict, identity_id: str, run_id: int, proof: list[dict],
                    step: str, exc: Exception) -> dict | None:
    """Park a run whose tx/deploy step failed after broadcasting, instead of
    failing it (and never re-broadcasting). Returns the parked result dict,
    or None when there is no evidence of a broadcast (no tx hash)."""
    if step not in ("tx", "deploy"):
        return None
    m = _TX_HASH_RE.search(str(exc))
    if not m:
        for p in proof:
            if isinstance(p, dict) and p.get("tx"):
                m = _TX_HASH_RE.search(str(p["tx"]))
                if m:
                    break
    if not m:
        return None
    txhash = m.group(0)
    proof.append({"broadcast_tx": txhash,
                  "parked": "broadcast, receipt/confirm failed — check explorer before retrying"})
    db.execute("UPDATE runs SET status='parked', proof=?, ended_at=? WHERE id=?",
               (json.dumps(proof, default=str), db.now(), run_id))
    db.execute("UPDATE quests SET status='pending', updated_at=? WHERE id=?", (db.now(), q["id"]))
    db.event("quest", f"parked {q['id']}: broadcast {txhash}, confirm failed", identity_id, level="warn")
    return {"quest": q["id"], "ok": True, "parked": True, "broadcast_tx": txhash,
            "proof": proof, "run": run_id,
            "next": [f"check the tx on the explorer, then re-run only if it never landed: "
                     f"aa quest run {q['id']}"]}


def _render(val, identity_id: str, q: dict):
    """Substitute {{url}}, {{email}}, {{wallet}} … in step values."""
    from ..browser import flows

    if not isinstance(val, (str, dict, list)):
        return val
    values = flows.identity_values(identity_id)
    values["url"] = q.get("url", "")
    if isinstance(val, str):
        for k, v in values.items():
            if v or k != "url":
                val = val.replace("{{" + k + "}}", str(v or ""))
        return val
    if isinstance(val, list):
        return [_render(v, identity_id, q) for v in val]
    return {k: _render(v, identity_id, q) for k, v in val.items()}


def _login_needs(q: dict) -> list[str]:
    out: list[str] = []
    for raw in q.get("steps") or []:
        step, val = next(iter(raw.items()))
        target = val.get("target", "") if isinstance(val, dict) else str(val or "")
        if step in ("follow", "like", "retweet", "post", "repost", "join"):
            if "x.com" in target or "twitter.com" in target or step in ("like", "retweet"):
                if "x" not in out:
                    out.append("x")
            elif "t.me" in target:
                if "telegram" not in out:
                    out.append("telegram")
            elif target.startswith("@"):
                if "x" not in out:
                    out.append("x")
        if step in ("discord", "discord_post"):
            if "discord" not in out:
                out.append("discord")
    return out


async def _do_social(step: str, val: str, identity_id: str) -> dict:
    kind = step
    if kind == "follow":
        if val.startswith("@"):
            out = await x.follow(identity_id, [val], limit=1)
            return out[0] if out else {"status": "failed"}
        return await telegram.join(identity_id, telegram.parse_target(val))
    if kind == "like":
        return await x.like(identity_id, val)
    if kind == "retweet":
        return await x.repost(identity_id, val)
    if kind == "post":
        return await x.post(identity_id, val)
    if kind == "join":
        return await telegram.join(identity_id, telegram.parse_target(val))
    if kind == "react":
        return await telegram.react(identity_id, val)
    return {"skipped": kind}


_SENSITIVE_API_HEADERS = {"authorization", "cookie", "api-key", "x-api-key"}
_SENSITIVE_API_JSON_KEYS = {"token", "password", "secret", "api_key", "apikey", "authorization"}


def _api_needs_gate(val: dict) -> bool:
    """True when an `api` step carries credentials, so a human must approve it.

    The gate summary never includes header/body contents — only method + host
    + path are shown to the operator.
    """
    headers = val.get("headers") or {}
    if isinstance(headers, dict):
        if any(str(k).lower() in _SENSITIVE_API_HEADERS for k in headers):
            return True

    def _scan(obj) -> bool:
        if isinstance(obj, dict):
            return any(str(k).lower() in _SENSITIVE_API_JSON_KEYS or _scan(v)
                       for k, v in obj.items())
        if isinstance(obj, list):
            return any(_scan(v) for v in obj)
        return False

    return _scan(val.get("json"))


async def _do_step(b: Browser, step: str, val, identity_id: str, q: dict, proof: list[dict]) -> dict:
    ad = adapters.get(q.get("platform", "generic"))
    if step == "goto":
        r = await b.goto(val)
        await flows.dismiss(b)
        cap = await b.solve_captcha_if_present()
        if cap.get("present"):
            proof.append({"captcha": cap})
        return r
    if step == "dismiss":
        n = await flows.dismiss(b)
        return {"dismissed": n}
    if step == "click":
        await b.click(text=val, exact=False)
        cap = await b.solve_captcha_if_present()
        return {"clicked": val, "captcha": cap}
    if step == "wallet":
        wants = val.get("connect") if isinstance(val, dict) else val in ("connect", "connect_wallet")
        if not wants:
            return {"wallet": val}
        out = await b.connect_wallet()
        need = [e for e in out.get("events", []) if "approval needed" in str(e.get("result", ""))]
        if need:
            raise Gate(f"wallet connect needs approval: {need[-1].get('method')} @ {need[-1].get('origin')}")
        if not out.get("clicked"):
            accts = await b.page.evaluate("window.ethereum.request({method:'eth_requestAccounts'})")
            out["provider"] = {"accounts": accts}
        return out
    if step == "switch":
        return {"chain": val, "note": "chain pinned at session start"}
    if step == "fill":
        await b.fill(val.get("value", ""), selector=val.get("selector"))
        return {"filled": val.get("selector")}
    if step == "form":
        r = await flows.fill_form(b, identity_id, overrides=val.get("values"),
                                  otp_sender=val.get("otp_sender", ""), otp_subject=val.get("otp_subject", ""))
        if r["missing"]:
            proof.append({"missing_fields": r["missing"]})
        return r
    if step == "type":
        await b.type_into(val.get("selector", "input"), val.get("value", ""))
        return {"typed": val.get("selector")}
    if step == "press":
        await b.press(val)
        return {"pressed": val}
    if step == "select":
        await b.select(val.get("selector", "select"), val.get("value", ""))
        return {"selected": val.get("selector")}
    if step == "scroll":
        await b.scroll(val)
        return {"scrolled": val}
    if step == "wait":
        await asyncio.sleep(float(val))
        return {"waited": val}
    if step == "sleep_rand":
        lo, hi = float(val[0]), float(val[1])
        d = random.uniform(lo, hi)
        await asyncio.sleep(d)
        return {"slept": round(d, 1)}
    if step == "assert_text":
        ok = await b.wait_for(val)
        if not ok:
            shot = await b.screenshot(f"fail_{config.slug(val)}")
            raise Denied(f"expected text not found: {val} (screenshot {shot})")
        return {"asserted": val}
    if step == "screenshot":
        p = await b.screenshot(val)
        proof.append({"screenshot": p})
        return {"screenshot": p}
    if step == "eval":
        # Defence in depth: `eval` was removed from the DSL, so a quest that
        # reaches the runner with this step must fail, never execute YAML JS.
        raise Denied("eval step was removed — arbitrary JS is no longer allowed; "
                     "use click/assert_text/manual instead")
    if step == "back":
        await b.back()
        return {"back": True}
    if step == "upload":
        await b.upload(val.get("selector", "input[type=file]"), val.get("path", ""))
        return {"uploaded": val.get("path")}
    if step == "manual":
        shot = await b.screenshot("manual")
        proof.append({"manual": val, "screenshot": shot})
        return {"manual": val}
    if step == "faucet":
        return await faucets.claim(b, identity_id, val.get("chain") or q.get("chain"), val.get("name", ""))
    if step == "tx":
        out = await asyncio.to_thread(sender.send, val.get("chain") or q.get("chain"), identity_id,
                                      val.get("label", ""), val["to"], value_wei=int(float(val.get("value", 0)) * 10 ** policy.decimals(val.get("chain") or q.get("chain") or "sepolia")),
                                      calldata=val.get("data", "0x"), broadcast=True, task=q["id"], via="quest")
        proof.append({"tx": out.get("tx")})
        return out
    if step == "deploy":
        from ..testnet import deploy

        return await asyncio.to_thread(deploy.run, val.get("chain") or q.get("chain"), identity_id,
                                       val.get("kind", "erc20"), val.get("args", {}))
    if step == "sign":
        from ..wallet import sign as signer

        return await asyncio.to_thread(signer.personal, identity_id, val.get("label", ""), val.get("message", ""),
                                       val.get("origin", b.page.url))
    if step == "api":
        from . import dsl as quest_dsl

        ok, reason = quest_dsl.api_allowed(q, val)
        if not ok:
            raise Denied(f"api step not allowed: {reason}")
        method = str(val.get("method", "GET")).upper()
        if _api_needs_gate(val):
            parsed = urlparse(val["url"])
            host = parsed.hostname or ""
            path = parsed.path or "/"
            payload = {"_kind": "api", "method": method, "url": val["url"],
                       "host": host, "path": path}
            # Summary shows method + host + path only — never header/body contents.
            gates.require("api", f"API {method} {host}{path}", payload)
        import requests

        r = requests.request(method, val["url"], headers=val.get("headers"), json=val.get("json"), timeout=30)
        return {"status": r.status_code, "body": r.text[:300]}
    if step == "if_text":
        found = await b.wait_for(val.get("text", ""), timeout=val.get("timeout", 5000))
        if found:
            return {"branch": "found", "next": ad.hint}
        return {"branch": "not-found"}
    if step == "checkin":
        try:
            await b.click(text=val, exact=False)
            db.record_checkin(q["id"], True, {"step": val})
            return {"checkin": val}
        except Exception:  # noqa: BLE001
            db.record_checkin(q["id"], False, {"step": val})
            return {"checkin": val, "already": True}
    if step in ("follow", "like", "retweet", "post", "join", "react"):
        return await _do_social(step, val, identity_id)
    raise Denied(f"unhandled step {step}")


async def run(q: dict, identity_id: str, *, dry: bool = False, headless: bool = True) -> dict:
    guard.check_kill()
    errs = __import__("aa.quest.dsl", fromlist=["validate"]).validate(q)
    if errs:
        raise Denied("invalid quest: " + "; ".join(errs))
    chain = q.get("chain") or ""
    if chain:
        policy.chain(chain)

    proof: list[dict] = []
    if dry:
        return {"quest": q["id"], "steps": [next(iter(s)) for s in q["steps"]], "dry": True}

    acquire_run_lock(q["id"], identity_id)
    try:
        return await _run_locked(q, identity_id, headless=headless, proof=proof)
    finally:
        release_run_lock(q["id"], identity_id)


async def _run_locked(q: dict, identity_id: str, *, headless: bool, proof: list[dict]) -> dict:
    # Login pre-flight: a quest that needs X/Telegram/Discord parks before burning steps.
    needs = _login_needs(q)
    if needs and not dry:
        from .. import session

        for platform in needs:
            res = await session.ensure(identity_id, platform)
            if res["state"] != "ok":
                db.execute("INSERT INTO runs(quest_id,identity_id,status,started_at,proof) VALUES(?,?,?,?,?)",
                           (q["id"], identity_id, "parked", db.now(), json.dumps([{"login": platform, **res}])))
                db.event("quest", f"parked {q['id']}: {platform} {res['state']}", identity_id, level="warn")
                return {"quest": q["id"], "ok": True, "parked": True, "needs_login": platform,
                        "login_state": res["state"], "proof": [{"login": platform, **res}],
                        "next": [f"aa social login {platform} --identity {identity_id}"]}
    run_id = db.execute("INSERT INTO runs(quest_id,identity_id,status,started_at) VALUES(?,?,?,?)",
                        (q["id"], identity_id, "running", db.now()))
    db.event("quest", f"start {q['id']}", identity_id)

    try:
        if q.get("gate") or (policy.mode() == "safe" and q.get("platform") in adapters.GATED):
            payload = {"_kind": "quest", "quest_id": q["id"], "identity": identity_id}
            gates.require("quest", f"Jalankan quest {q.get('name') or q['id']} di {q.get('platform')} "
                                   f"({len(q['steps'])} langkah, chain {chain or '-'})", payload)
        async with Browser(identity_id, profile=f"quest-{config.slug(q['id'])[:18]}", chain=chain or "sepolia",
                           headless=headless) as b:
            ad = adapters.get(q.get("platform", "generic"))
            await ad.prepare(b, q)
            for idx, raw in enumerate(q["steps"]):
                step, val = next(iter(raw.items()))
                val = _render(val, identity_id, q)
                # tx/deploy/sign get exactly one attempt (NO_RETRY_STEPS); a
                # failure after broadcast parks on the hash instead of
                # re-sending. Every other step keeps the old one-retry.
                max_attempts = 1 if step in NO_RETRY_STEPS else 2
                for attempt in range(1, max_attempts + 1):
                    try:
                        out = await _do_step(b, step, val, identity_id, q, proof)
                        proof.append({"i": idx, "step": step, "ok": True, "out": out})
                        break
                    except Gate:
                        raise
                    except Exception as e:  # noqa: BLE001
                        proof.append({"i": idx, "step": step, "ok": False,
                                      "error": f"{type(e).__name__}: {str(e)[:200]}"})
                        shot = await b.screenshot(f"err_{idx}")
                        proof.append({"screenshot": shot})
                        if step in HARD and attempt == max_attempts:
                            parked = _park_broadcast(q, identity_id, run_id, proof, step, e)
                            if parked is not None:
                                return parked
                            raise
                        await asyncio.sleep(2)
                        if attempt == max_attempts:
                            log.warning("soft-fail step %s: %s", step, e)
            await ad.after(b, q, proof)
            parked = any(p.get("step") == "manual" for p in proof)
            if parked:
                db.execute("UPDATE runs SET status='parked', proof=?, ended_at=? WHERE id=?",
                           (json.dumps(proof, default=str), db.now(), run_id))
                db.execute("UPDATE quests SET status='pending', updated_at=? WHERE id=?", (db.now(), q["id"]))
                db.event("quest", f"parked {q['id']} (manual step)", identity_id, level="warn")
                return {"quest": q["id"], "ok": True, "parked": True, "proof": proof, "run": run_id,
                        "next": ["finish the manual step in the browser profile", "aa quest run " + q["id"]]}
            if q.get("daily"):
                db.record_checkin(q["id"], True, {"proof": len(proof)})
            db.execute("UPDATE runs SET status='done', proof=?, ended_at=? WHERE id=?",
                       (json.dumps(proof, default=str), db.now(), run_id))
            db.execute("UPDATE quests SET status=?, updated_at=? WHERE id=?",
                       ("pending" if q.get("daily") else "done", db.now(), q["id"]))
            db.event("quest", f"done {q['id']}", identity_id)
            return {"quest": q["id"], "ok": True, "proof": proof, "run": run_id}
    except Exception as e:
        db.execute("UPDATE runs SET status='failed', error=?, proof=?, ended_at=? WHERE id=?",
                   (str(e)[:500], json.dumps(proof, default=str), db.now(), run_id))
        db.execute("UPDATE quests SET status='blocked', updated_at=? WHERE id=?", (db.now(), q["id"]))
        db.event("quest", f"fail {q['id']}: {e}", identity_id, level="error")
        raise


async def run_daily(identity_id: str, limit: int = 3) -> dict:
    from . import dsl

    done, failed = [], []
    for q in dsl.next_due(limit):
        if not q.get("daily"):
            continue
        try:
            await run(q, identity_id, headless=config.env_bool("BROWSER_HEADLESS", True))
            done.append(q["id"])
        except Exception as e:  # noqa: BLE001
            failed.append({"id": q["id"], "error": str(e)[:160]})
    return {"done": done, "failed": failed}
