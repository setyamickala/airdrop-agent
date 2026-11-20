"""Per-identity deterministic browser fingerprint (round 4, priority 1)."""
from __future__ import annotations

import uuid

from aa.browser.fingerprint import fingerprint_config, render_stealth_js


def test_same_identity_is_deterministic():
    a = fingerprint_config("alice")
    b = fingerprint_config("alice")
    assert a == b


def test_different_identities_differ():
    ids = [f"identity-{i}" for i in range(12)]
    cfgs = [fingerprint_config(i) for i in ids]
    # At least the UA / timezone / viewport / UUID must vary across identities.
    assert len({c["user_agent"] for c in cfgs}) > 1
    assert len({c["timezone_id"] for c in cfgs}) > 1
    assert len({(c["viewport"]["width"], c["viewport"]["height"]) for c in cfgs}) > 1
    assert len({c["eip6963_uuid"] for c in cfgs}) == len(ids)


def test_timezone_locale_consistent():
    for i in ("alice", "bob", "carol", "dave"):
        c = fingerprint_config(i)
        assert c["languages"][0] == c["locale"]
        # No identity keeps the old Asia/Jakarta + en-US mismatch.
        assert not (c["timezone_id"] == "Asia/Jakarta" and c["locale"] == "en-US")


def test_chrome_version_is_supported_not_131():
    for i in ("alice", "bob"):
        assert "Chrome/131.0.0.0" not in fingerprint_config(i)["user_agent"]
        assert "Chrome/" in fingerprint_config(i)["user_agent"]


def test_eip6963_uuid_is_uuid5_per_identity():
    a = fingerprint_config("alice")["eip6963_uuid"]
    assert uuid.UUID(a).version == 5
    assert a != fingerprint_config("bob")["eip6963_uuid"]
    assert a == fingerprint_config("alice")["eip6963_uuid"]


def test_rendered_stealth_js_has_real_plugins_and_values():
    cfg = fingerprint_config("alice")
    js = render_stealth_js(cfg)
    assert "__AA_" not in js  # no unfilled template tokens
    assert "[1, 2, 3, 4, 5]" not in js  # old numeric fake plugins are gone
    assert "Chrome PDF Plugin" in js
    assert cfg["locale"] in js
    assert str(cfg["hardware_concurrency"]) in js
    assert cfg["platform"] in js
