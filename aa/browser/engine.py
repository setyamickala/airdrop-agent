"""Stealth browser engine (patchright / playwright) with wallet injection.

One persistent profile per identity+profile, optional proxy, optional unpacked wallet
extensions, and human-ish input (mouse path, per-char typing, wheel scrolling).

Everything a page asks the wallet is forwarded to `guards.WalletBridge`, never signed
by the extension silently.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from .. import chains, config, db
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("browser")
JS_DIR = Path(__file__).parent

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

SNAPSHOT_JS = r"""
() => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none' && !e.disabled; };
  const label = (e) => (e.innerText || e.value || e.getAttribute('aria-label') || e.placeholder ||
                        e.name || e.id || '').trim().replace(/\s+/g, ' ').slice(0, 100);
  const els = [...document.querySelectorAll('a,button,input,textarea,select,[role=button],[role=link],[role=checkbox],[onclick]')].filter(vis);
  els.forEach((e, i) => e.setAttribute('data-aa-idx', String(i)));
  return {
    url: location.href, title: document.title,
    text: (document.body ? document.body.innerText : '').replace(/\n{3,}/g, '\n\n').slice(0, 12000),
    fields: els.map((e, i) => ({ i, tag: e.tagName.toLowerCase(), type: e.type || '', label: label(e),
      name: e.name || '', id: e.id || '', placeholder: e.placeholder || '', required: e.required || false })),
    links: [...document.querySelectorAll('a[href]')].slice(0, 200).map(a => ({ text: label(a), href: a.href })),
    frames: [...document.querySelectorAll('iframe')].map(f => f.src).filter(Boolean).slice(0, 20)
  };
}
"""


class Browser:
    """Async browser session. Use as async context manager."""

    def __init__(self, identity_id: str, *, profile: str | None = None, chain: str = "sepolia",
                 headless: bool | None = None, extensions: list[str] | None = None):
        self.identity_id = identity_id
        # One profile per identity keeps every login alive across modules. Set
        # BROWSER_SEPARATE_PROFILES=1 to get the old per-module isolation back.
        self.profile = (profile or "main") if config.env_bool("BROWSER_SEPARATE_PROFILES", False) \
            else config.env("BROWSER_PROFILE", "main")
        self.chain = chain
        self.headless = config.env_bool("BROWSER_HEADLESS", True) if headless is None else headless
        self.extension_paths = extensions if extensions is not None else self._default_extensions()
        self.bridge = None
        self._pw = None
        self._ctx = None
        self.pages: list = []
        self.started = False

    # ---------- setup ----------
    def _default_extensions(self) -> list[str]:
        from ..wallet import ext

        return ext.paths(self.identity_id) if config.env_bool("BROWSER_USE_EXTENSIONS", False) else []

    def _proxy(self) -> str:
        row = db.identity(self.identity_id)
        return row.get("proxy") or config.env(f"PROXY_{self.identity_id.upper().replace('-', '_')}") \
            or config.env("BROWSER_PROXY")

    def _profile_dir(self) -> Path:
        d = config.PROFILE_DIR / self.identity_id / self.profile
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        self._clear_stale_lock(d)
        return d

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if sys.platform == "win32":
            # os.kill(pid, 0) on Windows calls TerminateProcess — it KILLS the pid
            # instead of probing it. Query the process handle instead.
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
                return True
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    @staticmethod
    def _clear_stale_lock(d: Path) -> None:
        """A killed browser leaves SingletonLock behind and blocks the next launch."""
        lock = d / "SingletonLock"
        if not lock.exists():
            return
        pid = 0
        try:
            target = os.readlink(lock)
            pid = int(str(target).rsplit("-", 1)[-1])
        except Exception:  # noqa: BLE001
            pass
        alive = Browser._pid_alive(pid) if pid else False
        if alive:
            return
        for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            (d / name).unlink(missing_ok=True)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def start(self) -> "Browser":
        from .. import guard

        guard.check_kill()
        if config.env("AA_BROWSERS_PATH"):
            os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", config.env("AA_BROWSERS_PATH"))
        # patchright's stealth is good but its add_init_script is unreliable, so the
        # default path is plain playwright + our own stealth shim (injection matters more).
        if config.env("AA_BROWSER", "playwright") == "patchright":
            from patchright.async_api import async_playwright
        else:
            from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        args = ["--disable-blink-features=AutomationControlled", "--no-first-run",
                "--no-default-browser-check", "--disable-dev-shm-usage",
                f"--lang={config.env('BROWSER_LANG', 'en-US')}"]
        if self.extension_paths:
            joined = ",".join(self.extension_paths)
            args += [f"--disable-extensions-except={joined}", f"--load-extension={joined}"]
        proxy = self._proxy()
        kw = {"headless": self.headless, "args": args,
              "viewport": {"width": 1366 + random.randint(-40, 60), "height": 768 + random.randint(-30, 40)},
              "locale": config.env("BROWSER_LOCALE", "en-US"),
              "timezone_id": config.env("TZ", "Asia/Jakarta"),
              "ignore_https_errors": True,
              "permissions": ["clipboard-read", "clipboard-write"]}
        if config.env("BROWSER_UA"):
            kw["user_agent"] = self.user_agent
        if proxy:
            kw["proxy"] = {"server": proxy} if "@" not in proxy else _proxy_obj(proxy)
        self._ctx = await self._pw.chromium.launch_persistent_context(str(self._profile_dir()),
                                                                      channel=config.env("AA_BROWSER_CHANNEL", "chromium"), **kw)
        from .guards import WalletBridge

        self.bridge = WalletBridge(self)
        if config.env("AA_WALLET_LABEL"):
            self.bridge.label = config.env("AA_WALLET_LABEL")
        if config.env_bool("SESSION_RESTORE", True):
            try:
                from .. import session

                n = await session.restore(self.identity_id, self)
                if n:
                    log.info("restored %s session cookies", n)
            except Exception:  # noqa: BLE001
                pass
        await self._ctx.expose_binding("__aaWallet", self.bridge.evm)
        await self._ctx.expose_binding("__aaSolana", self.bridge.solana)
        conf = {"address": self.bridge.address, "chainId": hex(int(chains.cfg(self.chain)["chain_id"])),
                "connected": False, "solAddress": self.bridge.sol_address, "solConnected": False}
        await self._ctx.add_init_script(f"window.__AA_CONF = {json.dumps(conf)};")
        await self._ctx.add_init_script((JS_DIR / "stealth.js").read_text())
        for js_name in ("provider.js", "sol_provider.js"):
            await self._ctx.add_init_script((JS_DIR / js_name).read_text())
        self.pages = self._ctx.pages or []
        if not self.pages:
            self.pages.append(await self._ctx.new_page())
        for p in self._ctx.pages:
            p.set_default_timeout(int(config.env("BROWSER_TIMEOUT_MS", "45000")))
        self._ctx.on("page", self._on_popup)
        if not config.env("BROWSER_UA"):
            # Keep the real browser UA: a hardcoded UA that contradicts the
            # sec-ch-ua client hints is a strong bot signal (and burns CF clearance).
            try:
                self._native_ua = await self.pages[0].evaluate("navigator.userAgent")
            except Exception:  # noqa: BLE001
                self._native_ua = UA
        self.started = True
        db.event("browser", f"started profile={self.profile} ext={len(self.extension_paths)}", self.identity_id)
        return self

    async def close(self) -> None:
        try:
            if self._ctx and self.started and config.env_bool("SESSION_AUTOSAVE", True):
                try:
                    from .. import session

                    await session.save(self.identity_id, self)
                except Exception:  # noqa: BLE001
                    pass
            if self._ctx:
                await self._ctx.close()
        finally:
            if self._pw:
                await self._pw.stop()
            self.started = False

    # ---------- navigation ----------
    @property
    def page(self):
        if not self.pages:
            raise Denied("no open page")
        return self.pages[-1]

    @property
    def context(self):
        if not self._ctx:
            raise Denied("browser not started")
        return self._ctx

    @property
    def user_agent(self) -> str:
        return config.env("BROWSER_UA") or getattr(self, "_native_ua", "") or UA

    def _on_popup(self, p) -> None:
        """Tabs/popups opened by the page become the active page; closed ones drop out."""
        self.pages.append(p)
        try:
            p.set_default_timeout(int(config.env("BROWSER_TIMEOUT_MS", "45000")))
        except Exception:  # noqa: BLE001
            pass
        p.on("close", lambda: self._forget_page(p))

    def _forget_page(self, p) -> None:
        if p in self.pages:
            self.pages.remove(p)

    async def goto(self, url: str, *, check_scam: bool = True, wait_until: str = "domcontentloaded") -> dict:
        from .. import scam_check

        if not url.startswith("http"):
            url = "https://" + url
        host = urlparse(url).hostname or ""
        verdict = scam_check.check_url(url)
        if verdict["verdict"] == "bad" and check_scam:
            log.warning("suspicious URL %s: %s", host, verdict["reasons"])
        from . import cf

        cf_cookies = 0
        try:
            cf_cookies = await cf.inject_cached(self, url)
        except Exception:  # noqa: BLE001
            pass
        await self.page.goto(url, wait_until=wait_until, timeout=int(config.env("BROWSER_NAV_TIMEOUT_MS", "60000")))
        await self.human_wait(0.6, 2.0)
        out = {"url": self.page.url, "scam": verdict, "cf_cookies": cf_cookies}
        if config.env_bool("CF_ENABLED", True):
            state = await cf.ensure(self, url)
            out["cf"] = state.get("state")
            if state.get("state") == "clear":
                try:
                    st = await cf.page_state(self.page)
                    if st["clearance"]:
                        cf.remember(self.identity_id, host, await self.page.context.cookies(), self.user_agent)
                except Exception:  # noqa: BLE001
                    pass
            if state.get("state") == "blocked":
                out["cf_detail"] = state
                log.warning("cloudflare blocked %s", host)
        db.event("page", f"goto {host}", self.identity_id,
                 data={"verdict": verdict["verdict"], "cf": out.get("cf", "clear")})
        return out

    async def back(self) -> None:
        await self.page.go_back()

    async def new_tab(self, url: str | None = None):
        p = await self._ctx.new_page()
        self.pages.append(p)
        if url:
            await p.goto(url if "://" in url else "https://" + url)
        return p

    async def close_tab(self, index: int = -1) -> None:
        p = self.pages.pop(index)
        await p.close()

    # ---------- reading ----------
    async def snapshot(self) -> dict:
        data = await self.page.evaluate(SNAPSHOT_JS)
        data["scam"] = (await asyncio.to_thread(__import__("aa.scam_check", fromlist=["check_url"]).check_url, self.page.url))
        return data

    async def text(self) -> str:
        return await self.page.inner_text("body")

    async def visible(self, selector: str, timeout: int = 5000) -> bool:
        try:
            await self.page.wait_for_selector(selector, timeout=timeout, state="visible")
            return True
        except Exception:  # noqa: BLE001
            return False

    # ---------- interaction ----------
    async def _locator(self, *, index: int | None = None, selector: str | None = None,
                       text: str | None = None, exact: bool = False):
        p = self.page
        if selector:
            return p.locator(selector).first
        if index is not None:
            return p.locator(f'[data-aa-idx="{index}"]').first
        if text:
            rx = f"^{re_escape(text)}$" if exact else re_escape(text)
            for loc in (p.get_by_role("button", name=re_text(rx)),
                        p.get_by_role("link", name=re_text(rx)),
                        p.get_by_text(re_text(rx))):
                if await loc.count():
                    return loc.first
            return p.get_by_text(re_text(rx)).first
        raise Denied("click needs index, selector or text")

    async def click(self, *, index: int | None = None, selector: str | None = None, text: str | None = None,
                    exact: bool = False, human: bool = True) -> dict:
        loc = await self._locator(index=index, selector=selector, text=text, exact=exact)
        if human:
            try:
                box = await loc.bounding_box()
                if box:
                    await self.page.mouse.move(box["x"] + box["width"] / 2 + random.uniform(-6, 6),
                                               box["y"] + box["height"] / 2 + random.uniform(-4, 4), steps=random.randint(6, 18))
                    await self.human_wait(0.08, 0.35)
            except Exception:  # noqa: BLE001
                pass
        await loc.click(timeout=15000)
        await self.human_wait(0.25, 0.9)
        return {"clicked": text or selector or index}

    async def fill(self, value: str, *, index: int | None = None, selector: str | None = None,
                   text: str | None = None, human: bool = True) -> dict:
        loc = await self._locator(index=index, selector=selector, text=text)
        if human:
            await loc.click()
            await loc.fill("")
            await loc.type(value, delay=random.randint(35, 120))
        else:
            await loc.fill(value)
        return {"filled": (text or selector or index), "chars": len(value)}

    async def type_into(self, selector: str, value: str) -> dict:
        loc = self.page.locator(selector).first
        await loc.click()
        await loc.type(value, delay=random.randint(40, 130))
        return {"typed": selector}

    async def press(self, key: str, *, selector: str | None = None) -> None:
        if selector:
            await self.page.locator(selector).first.press(key)
        else:
            await self.page.keyboard.press(key)

    async def select(self, selector: str, value: str) -> None:
        await self.page.select_option(selector, value)

    async def check(self, selector: str) -> None:
        loc = self.page.locator(selector).first
        if not await loc.is_checked():
            await loc.check()

    async def scroll(self, dy: int | None = None) -> None:
        chunks = abs(dy or random.randint(300, 900))
        direction = 1 if (dy or 1) > 0 else -1
        while chunks > 0:
            step = min(chunks, random.randint(120, 260)) * direction
            await self.page.mouse.wheel(0, step)
            chunks -= abs(step)
            await asyncio.sleep(random.uniform(0.08, 0.3))

    async def upload(self, selector: str, path: str) -> None:
        await self.page.set_input_files(selector, path)

    async def screenshot(self, name: str) -> str:
        safe = config.slug(name)
        p = config.PROOF_DIR / f"{self.identity_id}_{safe}_{int(time.time())}.png"
        await self.page.screenshot(path=str(p), full_page=False)
        return str(p)

    async def human_wait(self, lo: float = 0.4, hi: float = 1.8) -> None:
        await asyncio.sleep(random.uniform(lo, hi))

    async def wait_for(self, text: str, timeout: int = 45000) -> bool:
        try:
            await self.page.get_by_text(re_text(re_escape(text))).first.wait_for(timeout=timeout)
            return True
        except Exception:  # noqa: BLE001
            return False

    async def solve_captcha_if_present(self) -> dict:
        from .captcha import solve_on_page

        return await solve_on_page(self.page)

    # ---------- wallet helpers ----------
    async def connect_wallet(self, label: str | None = None) -> dict:
        """Click the page's connect button, then approve via the injected provider."""
        if label:
            self.bridge.label = label
        clicked = False
        for txt in ("Connect Wallet", "Connect", "Hubungkan Wallet", "Hubungkan", "Connect wallet"):
            try:
                if await self._locator(text=txt) and await self.page.get_by_text(re_text(txt)).count():
                    await self.click(text=txt)
                    clicked = True
                    break
            except Exception:  # noqa: BLE001
                continue
        if not clicked:
            return {"clicked": False, "note": "connect button not found — call window.ethereum.request manually"}
        await self.human_wait(1.0, 2.5)
        # wallet picker modal
        for txt in ("Injected", "MetaMask", "Rabby", "Browser Wallet", "WalletConnect"):
            try:
                loc = self.page.get_by_text(re_text(txt)).first
                if await loc.count() and await loc.is_visible():
                    await loc.click()
                    break
            except Exception:  # noqa: BLE001
                continue
        await self.human_wait(0.8, 2.0)
        events = await self.bridge.events()
        return {"clicked": True, "events": events[-5:]}


def _proxy_obj(proxy: str) -> dict:
    from urllib.parse import unquote

    u = urlparse(proxy if "://" in proxy else "http://" + proxy)
    d = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
    if u.username:
        d["username"] = unquote(u.username)
        d["password"] = unquote(u.password or "")
    return d


def re_escape(s: str) -> str:
    import re

    return re.escape(s)


def re_text(s: str):
    import re

    return re.compile(s, re.I)


def token() -> str:
    return secrets.token_urlsafe(24)
