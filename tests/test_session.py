import asyncio
import json
import time

from aa import db, session, vault


class FakeCtx:
    def __init__(self):
        self.added = []

    async def storage_state(self):
        return {"cookies": [{"name": "auth_token", "value": "t", "domain": ".x.com", "path": "/"}], "origins": []}

    async def add_cookies(self, cookies):
        self.added.extend(cookies)


class FakeBrowser:
    def __init__(self):
        self.context = FakeCtx()


def test_save_and_restore_roundtrip():
    b = FakeBrowser()
    out = asyncio.run(session.save("id-sess", b))
    assert out["saved"] is True
    b2 = FakeBrowser()
    assert asyncio.run(session.restore("id-sess", b2)) == 1
    assert b2.context.added[0]["name"] == "auth_token"
    vault.put_secret("session-id-sess", json.dumps({"at": 0, "state": {"cookies": []}}))


def test_status_shape():
    iid = db.create_identity("sess")["id"]
    rows = session.status(iid)
    assert any(r.get("platform") == "x" for r in rows)
    assert any("state_blob" in r for r in rows)


class FakePage:
    def __init__(self):
        self.visited = []
        self.stored = []

    async def goto(self, url, wait_until=None, timeout=None):
        self.visited.append(url)

    async def evaluate(self, js, items):
        self.stored.extend(items)


class FakeBrowser2:
    def __init__(self):
        self.context = FakeCtx()
        self.page = FakePage()


def test_restore_restores_origins():
    vault.put_secret("session-id-orig", json.dumps({
        "at": time.time(),
        "state": {"cookies": [{"name": "c", "value": "v", "domain": ".x.com", "path": "/"}],
                  "origins": [{"origin": "https://x.com",
                               "localStorage": [{"name": "k", "value": "v"}]}]}}))
    b = FakeBrowser2()
    assert asyncio.run(session.restore("id-orig", b)) == 1
    assert b.page.visited == ["https://x.com"]
    assert b.page.stored == [{"name": "k", "value": "v"}]
