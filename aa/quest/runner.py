"""Quest runner: turns declarative steps into browser + chain actions.

Every step is recorded as proof. A failed step retries once, screenshots, then either
continues (soft) or aborts the quest (hard). Nothing here bypasses `safe_send`/guards.
"""
from __future__ import annotations

import asyncio
import json
import random
from decimal import Decimal

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


def _wei(chain: str, value) -> int:
    """Exact decimal -> base units. float multiplication loses wei at 18 decimals."""
    return int(Decimal(str(value)) * (10 ** policy.decimals(chain)))


def _login_needs(q: dict) -> list[str]:
    out: list[str] = []
    for raw in q.get("steps") or []:
        step, val = next(iter(raw.items()))
        target = val.get("target", "") if isinstance(val, dict) else str(val or "")
        if step in ("follow", "like", "retweet", "post", "repost", "join", "react"):
            if step in ("like", "retweet", "post", "repost") or "x.com" in target or "twitter.com" in target \
                    or (step == "follow" and target.startswith("@")):
                if "x" not in out:
                    out.append("x")
            elif step in ("follow", "join", "react"):
                # plain handles / t.me links go through Telegram in _do_social
                if "telegram" not in out:
                    out.append("telegram")
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


async def _do_step(b: Browser, step: str, val, identity_id: str, q: dict, proof: list[dict]) -> dict:
    ad = adapters.get(q.get("platform", "generic"))
    if step == "goto":
        r = await b.goto(val)
        if (r.get("scam") or {}).get("verdict") == "bad":
            raise Denied(f"refusing flagged URL {val}: {'; '.join((r['scam'].get('reasons') or [])[:3])}")
        if r.get("cf") == "blocked":
            raise Denied(f"cloudflare blocked {val} — run: aa cf assist --identity {identity_id} --url {val}")
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
        return {"eval": str(await b.page.evaluate(val))[:300]}
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
        chain = val.get("chain") or q.get("chain")
        if not chain:
            raise Denied("tx step needs a chain (set quest.chain or step.chain)")
        out = await asyncio.to_thread(sender.send, chain, identity_id,
                                      val.get("label", ""), val["to"],
                                      value_wei=_wei(chain, val.get("value", 0)),
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
        import requests

        method = val.get("method", "GET").upper()
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
        except Exception as e:  # noqa: BLE001
            # "Already done" is a claim that needs evidence from the page, not a
            # blanket assumption — otherwise a broken selector fakes the streak.
            text = ""
            try:
                text = (await b.text()).lower()
            except Exception:  # noqa: BLE001
                pass
            markers = ("already checked in", "already claimed", "checked in today",
                       "come back tomorrow", "already completed", "claim again in")
            if any(m in text for m in markers):
                db.record_checkin(q["id"], True, {"step": val, "evidence": "already-marker"})
                return {"checkin": val, "already": True}
            db.record_checkin(q["id"], False, {"step": val, "error": str(e)[:200]})
            shot = await b.screenshot("checkin_fail")
            raise Denied(f"checkin '{val}' failed: {str(e)[:160]} (screenshot {shot})")
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
                for attempt in (1, 2):
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
                        if step in HARD and attempt == 2:
                            raise
                        await asyncio.sleep(2)
                        if attempt == 2:
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
