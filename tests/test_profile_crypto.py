"""Profile-at-rest encryption + vault rekey (round 4, priority 2). No live browser."""
import os
from pathlib import Path

import pytest

from aa.browser import profile_crypto
from aa.jsonio import Denied


def _fake_profile(home, identity="alice", profile="main"):
    d = home.PROFILE_DIR / identity / profile
    d.mkdir(parents=True, exist_ok=True)
    (d / "Cookies").write_bytes(b"fake-cookie-db-bytes")
    (d / "Login Data").write_bytes(b"fake-login-db-bytes")
    ls = d / "Local Storage" / "leveldb"
    ls.mkdir(parents=True, exist_ok=True)
    (ls / "000003.log").write_bytes(b"fake-leveldb-bytes")
    (d / "History").write_text("not sensitive, stays put")
    return d


def test_seal_unseal_roundtrip(home, vault):
    d = _fake_profile(home)
    out = profile_crypto.seal_profile("alice")
    assert sorted(out["sealed"]) == ["Cookies", "Local Storage", "Login Data"]
    assert not (d / "Cookies").exists()
    assert not (d / "Login Data").exists()
    assert not (d / "Local Storage").exists()
    assert (d / "History").exists()  # out of scope stays plaintext (documented)
    assert vault.exists("profiles", "alice__main__Cookies")
    out2 = profile_crypto.unseal_profile("alice")
    assert sorted(out2["restored"]) == ["Cookies", "Local Storage", "Login Data"]
    assert (d / "Cookies").read_bytes() == b"fake-cookie-db-bytes"
    assert (d / "Login Data").read_bytes() == b"fake-login-db-bytes"
    assert (d / "Local Storage" / "leveldb" / "000003.log").read_bytes() == b"fake-leveldb-bytes"
    assert not vault.exists("profiles", "alice__main__Cookies")  # blob dropped after restore


def test_seal_twice_is_idempotent(home):
    _fake_profile(home)
    profile_crypto.seal_profile("alice")
    assert profile_crypto.seal_profile("alice")["sealed"] == []
    assert profile_crypto.unseal_profile("alice")["restored"]


def test_seal_refuses_live_browser(home):
    d = _fake_profile(home)
    # SingletonLock -> own (live) pid, same format Chromium writes.
    os.symlink(f"testhost-{os.getpid()}", d / "SingletonLock")
    with pytest.raises(Denied):
        profile_crypto.seal_profile("alice")
    assert (d / "Cookies").exists()  # nothing deleted


def test_seal_missing_profile_is_noop(home):
    assert profile_crypto.seal_profile("ghost")["sealed"] == []
    assert profile_crypto.unseal_profile("ghost")["restored"] == []
