"""Captcha handling: detect, then solve with 2captcha / anti-captcha, else hand off.

No bypass tricks — a real solving service. Without a key the runner returns
`manual` and the quest pauses for the operator (screenshot included).
"""
from __future__ import annotations

import asyncio
import re
import time

import requests

from .. import config, db
from ..log import get_logger

log = get_logger("captcha")

PROVIDERS = ("2captcha", "anticaptcha")
SITEKEYS = {
    "recaptcha": r'(?:data-sitekey="([^"]+)"|g-recaptcha"[^>]*data-sitekey="([^"]+)")',
    "hcaptcha": r'data-sitekey="([^"]+)"[^>]*class="[^"]*h-captcha',
    "turnstile": r'cf-turnstile[^>]*data-sitekey="([^"]+)"',
}


def sitekey_of(html: str, kind: str) -> str:
    rx = SITEKEYS.get(kind) or r'data-sitekey="([^"]+)"'
    m = re.search(rx, html, re.I | re.S)
    if m:
        return next((g for g in m.groups() if g), "")
    m = re.search(r'data-sitekey="([^"]+)"', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'sitekey["\']?\s*[:=]\s*["\'](0x[0-9A-Za-z_-]{10,})', html)
    return m.group(1) if m else ""


def attr_of(html: str, name: str) -> str:
    m = re.search(rf'{name}="([^"]*)"', html, re.I)
    return m.group(1) if m else ""


def detect(page_html: str, url: str) -> dict | None:
    if "cf-challenge" in page_html or "Just a moment" in page_html:
        return {"type": "cloudflare", "sitekey": ""}
    for kind, rx in SITEKEYS.items():
        m = re.search(rx, page_html, re.I)
        if m:
            return {"type": kind, "sitekey": next(g for g in m.groups() if g)}
    if "g-recaptcha" in page_html:
        return {"type": "recaptcha", "sitekey": ""}
    if "h-captcha" in page_html:
        return {"type": "hcaptcha", "sitekey": ""}
    if "cf-turnstile" in page_html:
        return {"type": "turnstile", "sitekey": ""}
    return None


async def solve_on_page(page) -> dict:
    html = await page.content()
    found = detect(html, page.url)
    if not found:
        return {"present": False}
    log.info("captcha detected: %s on %s", found["type"], page.url)
    db.event("captcha", f"{found['type']} on {page.url}")
    if found["type"] == "cloudflare" and not found["sitekey"]:
        for _ in range(4):
            await asyncio.sleep(4)
            if "Just a moment" not in await page.title():
                return {"present": True, "type": "cloudflare", "state": "auto-cleared"}
        return {"present": True, "type": "cloudflare", "state": "manual"}
    if not found["sitekey"]:
        return {"present": True, "type": found["type"], "state": "manual", "reason": "sitekey not found"}
    prov = config.env("CAPTCHA_PROVIDER", "").lower()
    key = config.env("CAPTCHA_API_KEY")
    if prov not in PROVIDERS or not key:
        return {"present": True, "type": found["type"], "state": "manual",
                "reason": "set CAPTCHA_PROVIDER + CAPTCHA_API_KEY"}
    try:
        token = await asyncio.to_thread(_solve, prov, key, found["type"], found["sitekey"], page.url)
    except Exception as e:  # noqa: BLE001
        log.warning("captcha solve failed: %s", e)
        return {"present": True, "type": found["type"], "state": "manual", "reason": str(e)}
    await _inject(page, found["type"], token)
    return {"present": True, "type": found["type"], "state": "solved"}


def _proxy_parts(proxy: str) -> dict | None:
    """Split "scheme://user:pass@host:port" (or bare "host:port") for solver APIs."""
    if not proxy:
        return None
    from urllib.parse import unquote, urlparse

    u = urlparse(proxy if "://" in proxy else "http://" + proxy)
    if not u.hostname or not u.port:
        return None
    return {"scheme": (u.scheme or "http").lower(), "host": u.hostname, "port": u.port,
            "username": unquote(u.username) if u.username else "",
            "password": unquote(u.password) if u.password else ""}


def _solve(provider: str, key: str, kind: str, sitekey: str, url: str, timeout: int = 180,
           action: str = "", cdata: str = "", proxy: str = "") -> str:
    """Solve one captcha. With a proxy, the task is created *with* that proxy
    (same IP as the browser identity) instead of proxyless — a proxyless
    token solved from the solver's datacenter IP is a classic mismatch flag.
    Without a proxy the old proxyless task is kept (some setups have none)."""
    px = _proxy_parts(proxy)
    if provider == "2captcha":
        method = {"recaptcha": "userrecaptcha", "hcaptcha": "hcaptcha", "turnstile": "turnstile"}[kind]
        form = {"key": key, "method": method, "googlekey" if kind == "recaptcha" else "sitekey": sitekey,
                "pageurl": url, "json": 1}
        if action:
            form["action"] = action
        if cdata:
            form["data"] = cdata
        if px:
            form["proxy"] = (f"{px['username']}:{px['password']}@{px['host']}:{px['port']}"
                             if px["username"] else f"{px['host']}:{px['port']}")
            form["proxytype"] = {"http": "HTTP", "https": "HTTPS"}.get(px["scheme"], "SOCKS5")
        r = requests.post("https://2captcha.com/in.php", timeout=30, data=form).json()
        if r.get("status") != 1:
            raise RuntimeError(f"2captcha: {r.get('request')}")
        cid = r["request"]
        end = time.time() + timeout
        while time.time() < end:
            time.sleep(5)
            q = requests.get("https://2captcha.com/res.php", timeout=30,
                             params={"key": key, "action": "get", "id": cid, "json": 1}).json()
            if q.get("status") == 1:
                return q["request"]
            if q.get("request") != "CAPCHA_NOT_READY":
                raise RuntimeError(f"2captcha: {q.get('request')}")
        raise TimeoutError("2captcha timeout")
    # anticaptcha
    base = {"recaptcha": "RecaptchaV2Task", "hcaptcha": "HCaptchaTask",
            "turnstile": "TurnstileTask"}[kind]
    task = {"type": base if px else base + "Proxyless",
            "websiteURL": url, "websiteKey": sitekey}
    if px:
        task.update({"proxyType": {"http": "http", "https": "https"}.get(px["scheme"], "socks5"),
                     "proxyAddress": px["host"], "proxyPort": px["port"],
                     "proxyLogin": px["username"], "proxyPassword": px["password"]})
    if action:
        task["action"] = action
    if cdata:
        task["data"] = cdata
    r = requests.post("https://api.anti-captcha.com/createTask", timeout=30,
                      json={"clientKey": key, "task": task}).json()
    if r.get("errorId"):
        raise RuntimeError(f"anticaptcha: {r.get('errorDescription')}")
    tid = r["taskId"]
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(5)
        q = requests.post("https://api.anti-captcha.com/getTaskResult", timeout=30,
                          json={"clientKey": key, "taskId": tid}).json()
        if q.get("status") == "ready":
            sol = q["solution"]
            return sol.get("gRecaptchaResponse") or sol.get("token") or ""
        if q.get("errorId"):
            raise RuntimeError(f"anticaptcha: {q.get('errorDescription')}")
    raise TimeoutError("anticaptcha timeout")


async def _inject(page, kind: str, token: str) -> None:
    js = {
        "recaptcha": """(t) => { document.querySelectorAll('[name=g-recaptcha-response],#g-recaptcha-response')
            .forEach(e => { e.style.display='block'; e.value=t; e.innerHTML=t; });
            if (window.___grecaptcha_cfg) for (const k in ___grecaptcha_cfg.clients||{}) {
              const c = ___grecaptcha_cfg.clients[k]; const cb = c && (c.callback||(c.c1&&c.c1.callback));
              if (cb) try { cb(t); } catch(_){} } }""",
        "hcaptcha": """(t) => { document.querySelectorAll('[name=h-captcha-response],[name=g-recaptcha-response]')
            .forEach(e => { e.value=t; e.innerHTML=t; });
            if (window.hcaptcha && hcaptcha.getResponse) {} }""",
        "turnstile": """(t) => { document.querySelectorAll('[name=cf-turnstile-response]')
            .forEach(e => { e.value=t; });
            document.querySelectorAll('input[type=hidden]').forEach(e => {
              if (e.name && e.name.includes('turnstile')) e.value = t; }); }""",
    }.get(kind)
    if js:
        try:
            await page.evaluate(js, token)
        except Exception as e:  # noqa: BLE001
            log.warning("captcha inject failed: %s", e)


def solve_token(provider: str, key: str, kind: str, sitekey: str, url: str, *,
                action: str = "", cdata: str = "", timeout: int = 180, proxy: str = "") -> str:
    """Public provider call used by the Cloudflare layer (turnstile kind)."""
    return _solve(provider, key, "turnstile" if kind in ("turnstile", "managed") else kind,
                  sitekey, url, timeout, action, cdata, proxy)


async def inject_token(page, token: str) -> int:
    """Write a token into every turnstile field in every frame and fire callbacks."""
    js = """(t) => {
      let n = 0;
      document.querySelectorAll('input[name*=turnstile],textarea[name*=turnstile]').forEach(e => {
        e.value = t; e.dispatchEvent(new Event('input', {bubbles:true}));
        e.dispatchEvent(new Event('change', {bubbles:true})); n++;
      });
      const cb = window.__aaTsCallback || window.turnstileCallback;
      if (typeof cb === 'function') { try { cb(t); } catch (_) {} }
      const ts = window.turnstile;
      if (ts && ts.getResponse) {
        document.querySelectorAll('.cf-turnstile,[data-turnstile]').forEach(el => {
          const id = el.getAttribute('data-callback');
          if (id && typeof window[id] === 'function') { try { window[id](t); } catch (_) {} }
        });
      }
      return n;
    }"""
    total = 0
    for frame in page.frames:
        try:
            total += await frame.evaluate(js, token) or 0
        except Exception:  # noqa: BLE001
            continue
    return total
