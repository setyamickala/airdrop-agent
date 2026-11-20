"""Encrypted vault for keys, seed phrases and session secrets.

* Keys/mnemonics/secrets are AES-256-GCM under a scrypt-derived key, one salt per
  blob, blob name as AAD (renaming a file breaks decryption loudly).
* EVM keys additionally keep a standard V3 keystore so MetaMask/Rabby can import
  a burner by hand.
* Only public addresses are ever returned by the CLI.
* `export`/`import` move the whole vault as one encrypted bundle.

Layout (0700):
  vault/index.json       public label -> addresses (no secrets)
  vault/evm/<id>.json    V3 keystore
  vault/hd/<id>.enc      encrypted mnemonic (HD root per identity)
  vault/sol/<id>.enc     encrypted Solana secret key
  vault/secrets/<n>.enc  encrypted platform secrets (cookies, tokens, passwords)
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from . import config
from .log import get_logger

log = get_logger("vault")
INDEX = config.VAULT_DIR / "index.json"
_CACHE: dict[bytes, bytes] = {}


def _password() -> str:
    pw = config.env("VAULT_PASSWORD")
    if not pw:
        pf = config.env("VAULT_PASSWORD_FILE")
        if pf and Path(pf).exists():
            pw = Path(pf).read_text().strip()
    if not pw or pw == "change-me-long-random-passphrase":
        raise SystemExit("VAULT_PASSWORD not set (generate one: aa init --random-vault-password)")
    return pw


def _derive(salt: bytes, password: str) -> bytes:
    key = (salt, password.encode())
    if key not in _CACHE:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        _CACHE[key] = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode())
    return _CACHE[key]


def _kdf(salt: bytes) -> bytes:
    return _derive(salt, _password())


def _encrypt_blob(data: bytes, aad: str, password: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_derive(salt, password)).encrypt(nonce, data, aad.encode())
    return {"v": 1, "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def _decrypt_blob(blob: dict, aad: str, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(_derive(bytes.fromhex(blob["salt"]), password)).decrypt(
        bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), aad.encode())


def _path(kind: str, name: str, ext: str = ".enc") -> Path:
    return config.VAULT_DIR / kind / f"{name}{ext}"


def put(kind: str, name: str, data: bytes) -> None:
    blob = _encrypt_blob(data, f"{kind}/{name}", _password())
    p = _path(kind, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(blob))


def drop(kind: str, name: str) -> bool:
    """Delete one vault blob (used after a sealed profile is restored)."""
    p = _path(kind, name)
    if not p.exists():
        return False
    p.unlink()
    return True


def overwrite(kind: str, name: str, data: bytes) -> None:
    p = _path(kind, name)
    if p.exists():
        p.unlink()
    put(kind, name, data)


def get(kind: str, name: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    p = _path(kind, name)
    if not p.exists():
        raise SystemExit(f"vault entry missing: {kind}/{name}")
    b = json.loads(p.read_text())
    return AESGCM(_kdf(bytes.fromhex(b["salt"]))).decrypt(bytes.fromhex(b["nonce"]),
                                                         bytes.fromhex(b["ct"]), f"{kind}/{name}".encode())


def exists(kind: str, name: str) -> bool:
    return _path(kind, name).exists()


def put_secret(name: str, value: str) -> None:
    overwrite("secrets", config.slug(name), value.encode())


def get_secret(name: str, default: str | None = None) -> str | None:
    n = config.slug(name)
    if not exists("secrets", n):
        return default
    return get("secrets", n).decode()


# ---------- public index ----------
def index() -> dict:
    return json.loads(INDEX.read_text()) if INDEX.exists() else {}


def save_index(idx: dict) -> None:
    config.secure_overwrite(INDEX, json.dumps(idx, indent=2))


def set_address(kind: str, key: str, address: str) -> None:
    idx = index()
    idx.setdefault(kind, {})[key] = address
    save_index(idx)


def get_address(kind: str, key: str) -> str:
    a = index().get(kind, {}).get(key)
    if not a:
        raise SystemExit(f"no {kind} wallet {key}")
    return a


def drop_address(kind: str, key: str) -> None:
    idx = index()
    idx.get(kind, {}).pop(key, None)
    save_index(idx)


# ---------- EVM ----------
def store_evm(key: str, private_key: bytes) -> str:
    from eth_account import Account

    ks = Account.encrypt(private_key, _password())
    p = _path("evm", key, ".json")
    config.secure_write(p, json.dumps(ks))
    acct = Account.from_key(private_key)
    set_address("evm", key, acct.address)
    return acct.address


def load_evm(key: str):
    from eth_account import Account

    ks = json.loads(_path("evm", key, ".json").read_text())
    return Account.from_key(Account.decrypt(ks, _password()))


# ---------- Solana ----------
def store_sol(key: str, secret: bytes) -> str:
    from solders.keypair import Keypair

    put("sol", key, secret)
    addr = str(Keypair.from_bytes(secret).pubkey())
    set_address("sol", key, addr)
    return addr


def load_sol(key: str):
    from solders.keypair import Keypair

    return Keypair.from_bytes(get("sol", key))


# ---------- mnemonic ----------
def store_mnemonic(key: str, mnemonic: str) -> None:
    put("hd", key, mnemonic.encode())


def load_mnemonic(key: str) -> str:
    return get("hd", key).decode()


def has_mnemonic(key: str) -> bool:
    return exists("hd", key)


# ---------- export / import ----------
def export_bundle(dest: Path, password: str | None = None) -> dict:
    """Seal the entire vault into one AES-GCM file (fresh password allowed)."""
    import hashlib
    import tarfile
    import tempfile

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    pw = (password or _password()).encode()
    salt, nonce = os.urandom(16), os.urandom(12)
    k = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(pw)
    with tempfile.TemporaryDirectory() as td:
        tar = Path(td) / "vault.tar"
        with tarfile.open(tar, "w") as t:
            t.add(config.VAULT_DIR, arcname="vault")
        ct = AESGCM(k).encrypt(nonce, tar.read_bytes(), b"vault-export")
    blob = {"v": 1, "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}
    config.secure_write(dest, json.dumps(blob))
    return {"file": str(dest), "sha256": hashlib.sha256(Path(dest).read_bytes()).hexdigest()}


def import_bundle(src: Path, password: str) -> dict:
    import tarfile

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    b = json.loads(Path(src).read_text())
    k = Scrypt(salt=bytes.fromhex(b["salt"]), length=32, n=2 ** 15, r=8, p=1).derive(password.encode())
    raw = AESGCM(k).decrypt(bytes.fromhex(b["nonce"]), bytes.fromhex(b["ct"]), b"vault-export")
    import io

    with tarfile.open(fileobj=io.BytesIO(raw)) as t:
        t.extractall(config.HOME, filter="data")
    entries = len([p for p in config.VAULT_DIR.rglob("*") if p.is_file()])
    return {"restored": str(config.VAULT_DIR), "entries": entries}


def count() -> dict:
    idx = index()
    return {k: len(v) for k, v in idx.items()}


def rekey(new_password: str, old_password: str | None = None) -> dict:
    """Re-encrypt every vault entry under a new password, atomically-ish.

    Steps: (1) export an encrypted backup bundle under the old password;
    (2) re-encrypt every ``.enc`` blob and every EVM V3 keystore in place;
    (3) only then point ``.env`` at the new password. On any failure the
    backup bundle is imported back (old password keeps working) and the
    error is re-raised. The backup file lives in a temp dir and is removed
    on success; ``index.json`` holds only public addresses and is untouched.
    """
    from eth_account import Account

    old_pw = old_password or _password()
    if not new_password or new_password == old_pw:
        raise SystemExit("rekey needs a new password different from the current one")
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="aa-rekey-"))
    backup = tmp / "vault-backup.json"
    try:
        export_bundle(backup, old_pw)
        rekeyed = {"blobs": 0, "keystores": 0}
        for p in sorted(config.VAULT_DIR.rglob("*.enc")):
            rel = p.relative_to(config.VAULT_DIR)
            kind, name = rel.parts[0], rel.stem
            blob = json.loads(p.read_text())
            plain = _decrypt_blob(blob, f"{kind}/{name}", old_pw)
            config.secure_overwrite(p, json.dumps(_encrypt_blob(plain, f"{kind}/{name}", new_password)))
            rekeyed["blobs"] += 1
        for p in sorted((config.VAULT_DIR / "evm").glob("*.json")):
            ks = json.loads(p.read_text())
            priv = Account.decrypt(ks, old_pw)
            config.secure_overwrite(p, json.dumps(Account.encrypt(priv, new_password)))
            rekeyed["keystores"] += 1
        # All entries re-encrypted: now switch the password on disk + in env.
        _write_env_password(new_password)
        os.environ["VAULT_PASSWORD"] = new_password
        _CACHE.clear()
        shutil.rmtree(tmp, ignore_errors=True)
        return {"rekeyed": rekeyed, "backup_removed": True}
    except Exception:
        try:
            import_bundle(backup, old_pw)
        except Exception:  # noqa: BLE001
            log.error("rekey failed AND backup restore failed — backup kept at %s", backup)
            raise
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _write_env_password(new_password: str) -> None:
    """Replace the VAULT_PASSWORD line in .env (0600), appending if absent."""
    lines, found = [], False
    if config.ENV_FILE.exists():
        lines = config.ENV_FILE.read_text().splitlines()
    out = []
    for line in lines:
        if line.strip().startswith("VAULT_PASSWORD="):
            out.append(f"VAULT_PASSWORD={new_password}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"VAULT_PASSWORD={new_password}")
    config.secure_overwrite(config.ENV_FILE, "\n".join(out) + "\n")


def gen_password(n: int = 32) -> str:
    return secrets.token_urlsafe(n)
