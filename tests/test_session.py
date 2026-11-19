import asyncio
import json
import time

from aa import db, session, vault


class FakeCtx:
    def __init__(self):
        self.added = []
        self.scripts = []

    async def storage_state(self):
        return {"cookies": [{"name": "auth_token", "value": "t", "domain": ".x.com", "path": "/"}], "origins": []}

    async def add_cookies(self, cookies):
        self.added.extend(cookies)

    async def add_init_script(self, script):
        self.scripts.append(script)


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


def test_restore_seeds_localstorage():
    state = {"cookies": [{"name": "a", "value": "b", "domain": ".x.com", "path": "/"}],
             "origins": [{"origin": "https://x.com", "localStorage": [{"name": "k", "value": "v"}]}]}
    vault.put_secret("session-id-ls", json.dumps({"at": time.time(), "state": state}))
    b = FakeBrowser()
    n = asyncio.run(session.restore("id-ls", b))
    assert n == 1
    assert any("https://x.com" in s and "localStorage.setItem" in s for s in b.context.scripts), \
        "restore must reseed localStorage, not only cookies"
