"""Cloudflare / Turnstile clearance that survives restarts.

Own implementation, three independent layers:

1. **Persist** — a solved `cf_clearance` cookie is bound to (IP, user-agent, host).
   We store it in the encrypted vault together with the UA, re-inject it on the next
   visit, and never trust it beyond `CF_TTL_MINUTES` or a UA change.
2. **Solve** — managed challenges often clear after real interaction. We jiggle,
   scroll, focus and click the Turnstile checkbox like a person, then fall back to a
   captcha provider token (Turnstile with `action`/`cdata`) and finally to
   FlareSolverr for headless boxes. Both fallbacks are OPT-IN ONLY
   (`CF_ALLOW_SOLVER=1` / `CF_ALLOW_FLARESOLVERR=1`, default off): with neither
   set, `ensure()` goes straight from the natural interaction to blocked/assist.
   See docs/CLOUDFLARE.md for why (account bans, target ToS).
3. **Assist** — when all of that fails, `aa cf assist` opens one visible window on the
   *same profile*, the operator clicks once, the clearance is captured and reused.

No third-party code is vendored; everything talks to public endpoints directly.
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import time
from urllib.parse import urlparse

import requests

from .. import config, db, vault
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("cf")

CF_HOST = "challenges.cloudflare.com"
TITLE_MARKERS = ("just a moment", "attention required", "checking your browser",
                 "verifying you are human", "please wait", "performing security verification")
HTML_MARKERS = ("cf-challenge", "challenge-platform", "/cdn-cgi/challenge-platform",
                "performing security verification", "verifies you are not a bot")
WIDGET_MARKERS = ('class="cf-turnstile', "class='cf-turnstile", "data-turnstile",
                  "challenges.cloudflare.com/turnstile", "cf-turnstile-widget")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_challenge_title(title: str) -> bool:
    t = (title or "").lower()
    return any(m in t for m in TITLE_MARKERS)


def detect(html: str, title: str = "", status: int = 0) -> str:
    """Return `managed|turnstile|blocked|""` from page facts (no network)."""
    low = (html or "").lower()
    if is_challenge_title(title):
        return "managed" if "cf-challenge" in low or "challenge-platform" in low else "turnstile"
    if status == 403 and "cloudflare" in low:
        return "blocked"
    if any(m in low for m in WIDGET_MARKERS):
        return "turnstile"
    if any(m in low for m in HTML_MARKERS):
        return "managed"
    return ""


async def page_state(page) -> dict:
    try:
        title = await page.title()
        html = await page.content()
    except Exception:  # noqa: BLE001
        return {"kind": "", "clearance": False, "url": ""}
    cookies = await page.context.cookies()
    clear = any(c.get("name") == "cf_clearance" for c in cookies)
    kind = detect(html, title, 0)
    # A page that renders normally while holding the cookie is fine even if the widget
    # markup is still in the bundle.
    if clear and not is_challenge_title(title):
        kind = ""
    if any(m in html.lower() for m in WIDGET_MARKERS) and not clear:
        kind = kind or "turnstile"
    return {"kind": kind, "clearance": clear, "title": title[:120], "url": page.url}


# ---------------- persistence ----------------
TTL_NAME = "cf/{identity}/{host}"


def _name(identity_id: str, host: str) -> str:
    return config.slug(f"cf-{identity_id}-{host}")


def cached(identity_id: str, host: str, ua: str) -> list[dict]:
    raw = vault.get_secret(_name(identity_id, host), "")
    if not raw:
        return []
    try:
        blob = json.loads(raw)
    except ValueError:
        return []
    ttl = int(config.env("CF_TTL_MINUTES", "45")) * 60
    if time.time() - blob.get("at", 0) > ttl or blob.get("ua") != ua or blob.get("host") != host:
        return []
    return blob.get("cookies") or []


def remember(identity_id: str, host: str, cookies: list[dict], ua: str) -> int:
    keep = [c for c in cookies if c.get("name") in ("cf_clearance", "__cf_bm", "cf_chl_2", "cf_chl_prog")]
    if not any(c.get("name") == "cf_clearance" for c in keep):
        return 0
    vault.put_secret(_name(identity_id, host),
                     json.dumps({"cookies": keep, "ua": ua, "at": time.time(), "host": host}))
    db.event("cf", f"clearance saved for {host}", identity_id)
    return len(keep)


def forget(identity_id: str, host: str = "") -> int:
    root = config.VAULT_DIR / "secrets"
    n = 0
    if root.exists():
        for p in root.glob("cf-*.enc"):
            name = p.stem
            if identity_id and not name.startswith(f"cf-{identity_id}-"):
                continue
            if host and name != _name(identity_id, host):
                continue
            p.unlink(missing_ok=True)
            n += 1
    return n


def status(identity_id: str = "") -> list[dict]:
    root = config.VAULT_DIR / "secrets"
    out = []
    if not root.exists():
        return out
    for p in sorted(root.glob("cf-*.enc")):
        name = p.stem
        m = re.match(r"^cf-(id-[a-z0-9]+)-(.+)$", name)
        if not m:
            continue
        who, hostname = m.group(1), m.group(2)
        if identity_id and who != identity_id:
            continue
        raw = vault.get_secret(name, "")
        blob = {}
        try:
            blob = json.loads(raw) if raw else {}
        except ValueError:
            pass
        out.append({"identity": who, "host": blob.get("host", hostname),
                    "age_min": round((time.time() - blob["at"]) / 60, 1) if blob.get("at") else None})
    return out


# ---------------- interaction ----------------
async def _human_nudge(page) -> None:
    try:
        await page.mouse.move(random.randint(120, 900), random.randint(120, 600), steps=random.randint(8, 22))
        await page.mouse.wheel(0, random.randint(80, 240))
        await page.wait_for_timeout(random.randint(250, 700))
        await page.mouse.wheel(0, -random.randint(30, 120))
    except Exception:  # noqa: BLE001
        pass


async def click_turnstile(page) -> bool:
    """Click the Turnstile checkbox inside its iframe, if one is present."""
    frames = [f for f in page.frames if CF_HOST in (f.url or "")]
    if not frames:
        return False
    for f in frames:
        try:
            el = await f.frame_element()
            box = await el.bounding_box()
            if not box:
                continue
            # checkbox sits ~30px from the left, vertically centred
            await page.mouse.move(box["x"] + 30 + random.uniform(-4, 4),
                                  box["y"] + box["height"] / 2 + random.uniform(-3, 3),
                                  steps=random.randint(6, 14))
            await page.wait_for_timeout(random.randint(120, 380))
            await page.mouse.click(box["x"] + 30, box["y"] + box["height"] / 2)
            return True
        except Exception:  # noqa: BLE001
            try:
                await f.locator("input[type=checkbox]").first.click(timeout=2000)
                return True
            except Exception:  # noqa: BLE001
                continue
    return False


async def _wait_clear(page, seconds: int) -> bool:
    deadline = time.time() + seconds
    seen_at = 0.0
    reloaded = False
    while time.time() < deadline:
        st = await page_state(page)
        if st["clearance"] and not st["kind"]:
            return True
        if st["clearance"]:
            seen_at = seen_at or time.time()
            # Clearance cookie is set but this document still shows the interstitial.
            # One reload commits it instead of waiting on a callback that never fires.
            if not reloaded and time.time() - seen_at > 3:
                reloaded = True
                try:
                    await page.reload(wait_until="domcontentloaded")
                except Exception:  # noqa: BLE001
                    pass
        await asyncio.sleep(1.5)
    return False


async def _token_solve(page, kind: str, proxy: str = "") -> dict:
    # Opt-in only: a captcha-solving service is a ToS / account-ban risk on
    # the target, so it never runs just because a provider key is configured.
    if not config.env_bool("CF_ALLOW_SOLVER", False):
        return {"state": "unsolved", "reason": "solver disabled (set CF_ALLOW_SOLVER=1 to opt in)"}
    from . import captcha

    prov = config.env("CAPTCHA_PROVIDER", "").lower()
    key = config.env("CAPTCHA_API_KEY")
    if not prov or not key:
        return {"state": "unsolved", "reason": "no captcha provider"}
    html = await page.content()
    sitekey = captcha.sitekey_of(html, kind)
    if not sitekey:
        return {"state": "unsolved", "reason": "sitekey not found"}
    action = captcha.attr_of(html, "data-action") or ""
    cdata = captcha.attr_of(html, "data-cdata") or ""
    try:
        # Pass the identity's proxy so the task is solved from the same IP
        # the browser uses (see captcha._solve); empty proxy keeps the old
        # proxyless task for setups without a proxy.
        token = await asyncio.to_thread(captcha.solve_token, prov, key, kind, sitekey, page.url,
                                        action=action, cdata=cdata, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"state": "unsolved", "reason": str(e)[:120]}
    injected = await captcha.inject_token(page, token)
    return {"state": "injected" if injected else "solved-no-field", "token_len": len(token)}


def _flare(url: str) -> dict:
    # Opt-in only (see _token_solve): FlareSolverr automates a challenge
    # bypass and must never run just because FLARESOLVERR_URL is set.
    if not config.env_bool("CF_ALLOW_FLARESOLVERR", False):
        raise Denied("flaresolverr disabled (set CF_ALLOW_FLARESOLVERR=1 to opt in)")
    base = config.env("FLARESOLVERR_URL")
    if not base:
        raise Denied("FLARESOLVERR_URL not set")
    r = requests.post(base.rstrip("/") + "/v1", timeout=90,
                      json={"cmd": "request.get", "url": url, "maxTimeout": 60_000})
    r.raise_for_status()
    sol = (r.json() or {}).get("solution") or {}
    if not sol.get("cookies"):
        raise Denied("flaresolverr returned no cookies")
    return sol


async def ensure(b, url: str) -> dict:
    """Clear a challenge on an already-navigated page. Returns {state, kind, ...}."""
    st = await page_state(b.page)
    if not st["kind"]:
        return {"state": "clear", **{k: st[k] for k in ("kind", "clearance")}}

    host = _host(url)
    log.warning("cloudflare %s on %s", st["kind"], host)
    db.event("cf", f"{st['kind']} challenge on {host}", b.identity_id)

    wait = int(config.env("CF_WAIT_SECONDS", "28"))
    deadline = time.time() + wait
    clicked = False
    while time.time() < deadline:
        await _human_nudge(b.page)
        if not clicked:
            clicked = await click_turnstile(b.page)
        if await _wait_clear(b.page, 4):
            n = remember(b.identity_id, host, await b.page.context.cookies(), b.user_agent)
            db.event("cf", f"passed {host} naturally ({n} cookies)", b.identity_id)
            return {"state": "passed", "kind": st["kind"], "cookies": n}

    # Both fallbacks are opt-in (default off): without CF_ALLOW_SOLVER=1 /
    # CF_ALLOW_FLARESOLVERR=1 this goes straight to blocked/assist.
    res = {"state": "unsolved", "reason": "solver disabled"}
    if config.env_bool("CF_ALLOW_SOLVER", False):
        res = await _token_solve(b.page, st["kind"], proxy=b._proxy() or "")
    if res.get("state", "").startswith(("injected", "solved")):
        if await _wait_clear(b.page, 12):
            n = remember(b.identity_id, host, await b.page.context.cookies(), b.user_agent)
            return {"state": "solved", "kind": st["kind"], "cookies": n, "token": res.get("state")}

    if config.env_bool("CF_ALLOW_FLARESOLVERR", False) and config.env("FLARESOLVERR_URL"):
        try:
            sol = await asyncio.to_thread(_flare, url)
            await b.page.context.add_cookies(sol["cookies"])
            await b.page.reload(wait_until="domcontentloaded")
            if await _wait_clear(b.page, 15):
                n = remember(b.identity_id, host, await b.page.context.cookies(), b.user_agent)
                return {"state": "flaresolverr", "kind": st["kind"], "cookies": n}
        except Exception as e:  # noqa: BLE001
            log.warning("flaresolverr failed: %s", e)

    shot = await b.screenshot("cf_challenge")
    return {"state": "blocked", "kind": st["kind"], "screenshot": shot,
            "next": ["aa cf assist --identity %s --url %s" % (b.identity_id, url)]}


async def inject_cached(b, url: str) -> int:
    host = _host(url)
    cookies = cached(b.identity_id, host, b.user_agent)
    if not cookies:
        return 0
    try:
        await b.page.context.add_cookies(cookies)
        db.event("cf", f"cached clearance injected for {host}", b.identity_id)
        return len(cookies)
    except Exception:  # noqa: BLE001
        return 0
