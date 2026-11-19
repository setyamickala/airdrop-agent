"""Keep logins alive.

Two problems make agents log out constantly: a fresh profile per action, and no
warm-up. v4.1 fixes both — every module shares one profile per identity, and this
module refreshes the sessions that profiles carry.

- `save` / `restore` seal `storage_state` (cookies + localStorage) into the vault, so a
  wiped profile can be rebuilt without re-login.
- `check` visits the platform and answers `ok | logged_out | challenge`.
- `warm` scrolls a real page like a person, which is what keeps rolling sessions fresh.
- `ensure` is the pre-flight a quest runner calls: it never guesses, it reports
  `needs_login` so the caller can park instead of failing halfway.
"""
from __future__ import annotations

import asyncio
import json
import random
import time

from . import config, db, vault
from .jsonio import Denied
from .log import get_logger

log = get_logger("session")

PROFILES = {
    "x": {"url": "https://x.com/home", "ok": ["/home", "data-testid=SideNav_AccountSwitcher_Button",
                                              "data-testid=AppTabBar_Home_Link"]},
    "discord": {"url": "https://discord.com/app", "ok": ["app-mount", "data-list-id=guildsnav"]},
    "telegram": {"url": "https://web.telegram.org/k/", "ok": ["chatlist", "ChatList"]},
    "gmail": {"url": "https://mail.google.com/mail/u/0/#inbox", "ok": ["[gh=cm]", "[aria-label*=Inbox]"]},
    "google": {"url": "https://myaccount.google.com/", "ok": ["[data-email]", "Manage your Google Account"]},
}

STATE = "session-{identity}"


def platforms() -> list[str]:
    return list(PROFILES)


async def _alive(page, name: str) -> bool:
    low = page.url.lower()
    if "/login" in low or "accounts.google.com" in low or "/i/flow/" in low:
        return False
    if name == "x":
        if await page.locator('[data-testid=loginButton], a[href="/login"]').count():
            return False
    cfg = PROFILES[name]
    for sel in cfg["ok"]:
        try:
            if sel.startswith("/"):
                if page.url.rstrip("/").endswith(sel):
                    return True
                continue
            if await page.locator(sel).count():
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


async def check(identity_id: str, name: str, *, headless: bool | None = None, browser=None) -> dict:
    from .browser.engine import Browser

    if name not in PROFILES:
        raise Denied(f"unknown platform {name}")
    own = browser is None
    if own:
        browser = Browser(identity_id, headless=headless)
        await browser.start()
    try:
        b = browser
        out = await b.goto(PROFILES[name]["url"], check_scam=False)
        if out.get("cf") == "blocked":
            return {"platform": name, "state": "challenge", "screenshot": out.get("cf_detail", {}).get("screenshot")}
        await b.human_wait(1.5, 3.0)
        alive = await _alive(b.page, name)
        if alive:
            await warm(identity_id, name, browser=b, _quiet=True)
        await save(identity_id, b)
        return {"platform": name, "state": "ok" if alive else "logged_out", "url": b.page.url}
    finally:
        if own:
            await browser.close()


async def warm(identity_id: str, name: str, *, browser=None, _quiet: bool = False) -> dict:
    """Human-ish scroll + dwell. Reuses a browser when one is already open."""
    own = browser is None
    if own:
        from .browser.engine import Browser

        browser = Browser(identity_id)
        await browser.start()
    try:
        page = browser.page
        for _ in range(random.randint(2, 4)):
            await page.mouse.move(random.randint(100, 900), random.randint(100, 700), steps=random.randint(4, 12))
            await page.mouse.wheel(0, random.randint(180, 600))
            await page.wait_for_timeout(random.randint(400, 1100))
        await page.mouse.wheel(0, -random.randint(100, 400))
        await browser.human_wait(1.0, 2.5)
        saved = await save(identity_id, browser)
        db.event("session", f"warm {name}", identity_id)
        return {"platform": name, "warmed": True, **saved}
    finally:
        if own:
            await browser.close()


async def save(identity_id: str, browser) -> dict:
    try:
        state = await browser.context.storage_state()
    except Exception as e:  # noqa: BLE001
        return {"saved": False, "error": str(e)[:80]}
    blob = {"at": time.time(), "state": state}
    vault.put_secret(STATE.format(identity=identity_id), json.dumps(blob))
    db.event("session", "state saved", identity_id)
    return {"saved": True, "cookies": len(state.get("cookies") or [])}


async def restore(identity_id: str, browser) -> int:
    raw = vault.get_secret(STATE.format(identity=identity_id), "")
    if not raw:
        return 0
    try:
        blob = json.loads(raw)
        state = blob.get("state") or {}
        cookies = state.get("cookies") or []
        ttl_days = int(config.env("SESSION_STATE_DAYS", "14"))
        if time.time() - blob.get("at", 0) > ttl_days * 86400:
            return 0
        await browser.context.add_cookies(cookies)
        # localStorage is origin-bound and cannot be injected cross-origin; seed it
        # with an init script that runs before page scripts on each matching origin.
        seeds = []
        for o in state.get("origins") or []:
            items = o.get("localStorage") or []
            if not items or not o.get("origin"):
                continue
            pairs = "".join(
                f"localStorage.setItem({json.dumps(i.get('name', ''))},{json.dumps(i.get('value', ''))});"
                for i in items)
            seeds.append(f"if (location.origin === {json.dumps(o['origin'])}) {{ try {{ {pairs} }} catch (_) {{}} }}")
        if seeds:
            await browser.context.add_init_script("(() => {" + "".join(seeds) + "})()")
        return len(cookies)
    except Exception as e:  # noqa: BLE001
        log.warning("state restore failed: %s", e)
        return 0


async def ensure(identity_id: str, name: str, *, headless: bool | None = None) -> dict:
    """Pre-flight for quests: ok / needs_login / challenge (never raises for logout)."""
    res = await check(identity_id, name, headless=headless)
    if res["state"] != "ok":
        res["next"] = [f"aa social login {name} --identity {identity_id}"]
    return res


def status(identity_id: str) -> list[dict]:
    row = db.identity(identity_id)
    socials = row.get("socials") or {}
    if isinstance(socials, str):
        socials = json.loads(socials or "{}")
    rows = []
    for name in PROFILES:
        have = bool(socials.get(name))
        rows.append({"platform": name, "linked": have,
                     "action": "warm" if have else f"aa social login {name}"})
    state = vault.get_secret(STATE.format(identity=identity_id), "")
    return rows + [{"state_blob": bool(state)}]


async def warm_all(identity_id: str, *, headless: bool | None = None) -> list[dict]:
    row = db.identity(identity_id)
    socials = json.loads(row.get("socials") or "{}")
    out = []
    for name in socials:
        if name not in PROFILES:
            continue
        try:
            out.append(await warm(identity_id, name))
        except Denied as e:
            out.append({"platform": name, "error": str(e)[:120]})
        await asyncio.sleep(random.uniform(3, 8))
    return out
