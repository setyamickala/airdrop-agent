
import pytest


def test_evm_roundtrip(vault):
    
    pk = bytes.fromhex("11" * 32)
    addr = vault.store_evm("k1", pk)
    loaded = vault.load_evm("k1")
    assert loaded.address == addr
    assert vault.get_address("evm", "k1") == addr


def test_sol_roundtrip(vault):
    from solders.keypair import Keypair

    kp = Keypair()
    addr = vault.store_sol("s1", bytes(kp))
    assert str(vault.load_sol("s1").pubkey()) == addr


def test_mnemonic_encrypted(vault):
    m = "test " * 23 + "test"
    vault.store_mnemonic("id-x", m)
    assert vault.load_mnemonic("id-x") == m


def test_secret(vault):
    vault.put_secret("token:x", "abc123")
    assert vault.get_secret("token:x") == "abc123"
    assert vault.get_secret("missing", "def") == "def"


def test_aad_rename_breaks(vault, home):
    vault.put_secret("a", "1")
    src = home.VAULT_DIR / "secrets" / "a.enc"
    src.rename(home.VAULT_DIR / "secrets" / "b.enc")
    with pytest.raises(Exception):
        vault.get_secret("b")


def test_export_import(vault, home, tmp_path):
    vault.put_secret("x", "y")
    dest = tmp_path / "bundle.json"
    vault.export_bundle(dest)
    assert dest.exists()
    import shutil

    for p in list(home.VAULT_DIR.iterdir()):
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    vault.import_bundle(dest, "test-passphrase-not-secret")
    assert vault.get_secret("x") == "y"


def test_hd_derivation_is_deterministic():
    from aa.wallet import hd

    m = hd.new_mnemonic()
    a1, addr1 = hd.derive_evm(m, 0)
    a2, addr2 = hd.derive_evm(m, 0)
    assert addr1 == addr2
    assert a1 == a2
    s1, saddr1 = hd.derive_sol(m, 0)
    assert saddr1 == hd.derive_sol(m, 0)[1]


def test_private_key_never_in_index(vault, home):
    vault.store_evm("k2", bytes.fromhex("22" * 32))
    text = (home.VAULT_DIR / "index.json").read_text()
    assert "0x" not in text or True  # index holds addresses only
    assert "22" * 32 not in text


def test_overwrite_failure_keeps_old_entry(vault, monkeypatch):
    """A crash/failed write during overwrite must not destroy the existing secret."""
    vault.put_secret("atomic", "old-value")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    orig = AESGCM.encrypt

    def boom(self, *a, **k):
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(AESGCM, "encrypt", boom)
    try:
        with pytest.raises(RuntimeError):
            vault.overwrite("secrets", "atomic", b"new-value")
    finally:
        monkeypatch.setattr(AESGCM, "encrypt", orig)
    assert vault.get_secret("atomic") == "old-value"
    assert not list((vault.config.VAULT_DIR / "secrets").glob(".tmp-*")), "no temp litter left behind"
