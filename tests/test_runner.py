"""Quest runner regression tests: no fake successes, honest parking, precise wei."""
import asyncio

import pytest

from aa.jsonio import Denied
from aa.quest import runner


class FakeB:
    def __init__(self, goto_out=None, click_exc=None, page_text=""):
        self.goto_out = goto_out or {"url": "https://x.test", "scam": {"verdict": "ok"}}
        self.click_exc = click_exc
        self.page_text = page_text

    async def goto(self, url):
        return self.goto_out

    async def click(self, **kw):
        if self.click_exc:
            raise self.click_exc
        return {"clicked": kw.get("text")}

    async def text(self):
        return self.page_text

    async def screenshot(self, name):
        return f"proofs/{name}.png"

    async def solve_captcha_if_present(self):
        return {"present": False}


@pytest.fixture
def no_dismiss(monkeypatch):
    async def nodismiss(b):
        return 0
    monkeypatch.setattr(runner.flows, "dismiss", nodismiss)


Q = {"id": "tq", "url": "https://x.test"}


def test_goto_cloudflare_blocked_stops(home, ident, no_dismiss):
    b = FakeB(goto_out={"url": "https://x.test", "cf": "blocked",
                        "cf_detail": {"screenshot": "s.png"}, "scam": {"verdict": "ok"}})
    with pytest.raises(Denied, match="cf assist"):
        asyncio.run(runner._do_step(b, "goto", "https://x.test", ident, Q, []))


def test_goto_scam_bad_stops(home, ident, no_dismiss):
    b = FakeB(goto_out={"url": "https://evil.test", "scam": {"verdict": "bad", "reasons": ["punycode"]}})
    with pytest.raises(Denied, match="flagged"):
        asyncio.run(runner._do_step(b, "goto", "https://evil.test", ident, Q, []))


def test_checkin_failure_is_not_success(home, ident):
    from aa import db
    b = FakeB(click_exc=RuntimeError("button not found"), page_text="Welcome to the app")
    with pytest.raises(Denied):
        asyncio.run(runner._do_step(b, "checkin", "Check in", ident, Q, []))
    row = db.one("SELECT status FROM checkins WHERE project='tq'")
    assert row["status"] == "fail", "a failed check-in must never be recorded as ok"


def test_checkin_already_with_evidence(home, ident):
    from aa import db
    b = FakeB(click_exc=RuntimeError("gone"), page_text="You already checked in today. Come back tomorrow!")
    out = asyncio.run(runner._do_step(b, "checkin", "Check in", ident, Q, []))
    assert out.get("already") is True
    assert db.one("SELECT status FROM checkins WHERE project='tq'")["status"] == "ok"


def test_login_needs_detects_post(home):
    assert "x" in runner._login_needs({"steps": [{"post": "gm everyone"}]})


def test_login_needs_detects_repost_text(home):
    assert "x" in runner._login_needs({"steps": [{"repost": "spread the word"}]})


def test_login_needs_follow_plain_target(home):
    assert "telegram" in runner._login_needs({"steps": [{"follow": "somechannel"}]})


def test_wei_precision(home):
    assert runner._wei("sepolia", "0.123456789123456789") == 123456789123456789
    assert runner._wei("sepolia", "1") == 10 ** 18
    assert runner._wei("solana-devnet", "0.000000001") == 1


def test_tx_step_without_chain_denied(home, ident):
    b = FakeB()
    with pytest.raises(Denied, match="chain"):
        asyncio.run(runner._do_step(b, "tx", {"to": "0x" + "11" * 20, "value": "0.001"},
                                    ident, {"id": "tq"}, []))
