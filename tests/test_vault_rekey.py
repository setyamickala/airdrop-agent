"""Vault rekey (round 4, priority 2b): old password dies, new password works."""
import os

import pytest


def test_rekey_roundtrip(home, vault, monkeypatch):
    monkeypatch.setenv("VAULT_PASSWORD", "test-passphrase-not-secret")
    vault.put_secret("token:x", "abc123")
    vault.store_mnemonic("id-x", "test " * 23 + "test")
    pk = bytes.fromhex("11" * 32)
    vault.store_evm("k1", pk)
    out = vault.rekey("brand-new-password-123")
    assert out["rekeyed"]["blobs"] >= 2
    assert out["rekeyed"]["keystores"] == 1
    assert os.environ["VAULT_PASSWORD"] == "brand-new-password-123"
    assert vault.get_secret("token:x") == "abc123"
    assert vault.load_mnemonic("id-x") == "test " * 23 + "test"
    assert vault.load_evm("k1").address
    # Old password no longer opens anything.
    monkeypatch.setenv("VAULT_PASSWORD", "test-passphrase-not-secret")
    with pytest.raises(Exception):
        vault.get_secret("token:x")


def test_rekey_rejects_same_password(home, vault, monkeypatch):
    monkeypatch.setenv("VAULT_PASSWORD", "test-passphrase-not-secret")
    vault.put_secret("x", "y")
    with pytest.raises(SystemExit):
        vault.rekey("test-passphrase-not-secret")


def test_rekey_failure_rolls_back(home, vault, monkeypatch):
    monkeypatch.setenv("VAULT_PASSWORD", "test-passphrase-not-secret")
    vault.put_secret("x", "y")
    # Corrupt one blob so re-encryption fails midway: rollback must restore it.
    blob_path = home.VAULT_DIR / "secrets" / "x.enc"
    blob_path.write_text('{"v": 1, "salt": "00", "nonce": "00", "ct": "00"}')
    with pytest.raises(Exception):
        vault.rekey("another-new-password-456")
    # Rollback restored the (corrupt) blob; vault still answers to old password.
    assert os.environ["VAULT_PASSWORD"] == "test-passphrase-not-secret"
    with pytest.raises(Exception):
        vault.get_secret("x")  # still corrupt, but password did not change
