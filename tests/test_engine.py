"""Browser engine regression tests (no real browser needed)."""
import asyncio
import time
from pathlib import Path

from aa.browser.engine import Browser


def test_stale_lock_windows_never_kills(home, monkeypatch, tmp_path):
    import os
    import sys
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(os, "readlink", lambda p: "host-424242424")

    def no_kill(pid, sig):
        raise AssertionError("os.kill on Windows TERMINATES processes — must not be used to probe liveness")

    monkeypatch.setattr(os, "kill", no_kill)
    d = tmp_path / "profile"
    d.mkdir()
    (d / "SingletonLock").write_text("x")
    Browser._clear_stale_lock(d)
    assert not (d / "SingletonLock").exists(), "stale lock should be removed without killing anything"


def test_screenshot_name_uses_epoch(home, ident):
    b = Browser(ident)
    seen = {}

    class FakePage:
        async def screenshot(self, path=None, full_page=False):
            seen["path"] = path

    b.pages = [FakePage()]
    out = asyncio.run(b.screenshot("probe"))
    ts = int(Path(out).stem.rsplit("_", 1)[-1])
    assert abs(ts - time.time()) < 10, "proof filenames must use wall-clock epoch, not loop-relative time"


def test_user_agent_prefers_native(home, ident, monkeypatch):
    monkeypatch.delenv("BROWSER_UA", raising=False)
    b = Browser(ident)
    b._native_ua = "NativeUA/159"
    assert b.user_agent == "NativeUA/159"
    monkeypatch.setenv("BROWSER_UA", "CustomUA")
    assert b.user_agent == "CustomUA", "explicit BROWSER_UA must still win"


def test_popup_tracked_and_removed(home, ident):
    b = Browser(ident)
    b.pages = []

    class FakePage:
        def __init__(self):
            self.handlers = {}

        def set_default_timeout(self, ms):
            pass

        def on(self, ev, fn):
            self.handlers[ev] = fn

    p = FakePage()
    b._on_popup(p)
    assert b.pages[-1] is p, "popups opened by the page must become the active page"
    p.handlers["close"]()
    assert p not in b.pages, "closed popups must not stay active"
