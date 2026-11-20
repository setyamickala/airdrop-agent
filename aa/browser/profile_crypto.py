"""Encrypt Chromium profile files at rest (round 4, priority 2a).

While the browser runs, Chromium needs its profile on disk in plaintext
(SQLite ``Cookies``, ``Login Data``, ``Local Storage``). The moment the
browser closes, this module seals those files into the vault (AES-256-GCM,
same key as the rest of the vault) and deletes the plaintext originals; the
next launch unseals them just before Playwright starts.

Limits, stated plainly:
* Only the files/directories in SENSITIVE_FILES / SENSITIVE_DIRS are sealed.
  History, cache, service-worker storage and the rest of the profile stay
  plaintext on disk — full-directory encryption was judged too risky
  (locked files, profile size) for this round.
* Sealing refuses while the browser is actually running (live SingletonLock);
  it never deletes a profile that is in use.
* The profile is plaintext *while the browser runs* — this protects a
  stolen/lost disk or a backup, not a live attacker on the machine.
"""
from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

from .. import config, vault
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("profile_crypto")

# Files whose contents are session secrets. Directories are tarred as one blob.
SENSITIVE_FILES = ("Cookies", "Login Data", "Web Data")
SENSITIVE_DIRS = ("Local Storage", "Session Storage")
KIND = "profiles"


def profile_dir(identity_id: str, profile: str = "main") -> Path:
    return config.PROFILE_DIR / identity_id / profile


def _entry(identity_id: str, profile: str, rel: str) -> str:
    return f"{identity_id}__{profile}__{rel.replace('/', '__')}"


def _browser_running(d: Path) -> bool:
    """True if Chromium's SingletonLock points at a live process."""
    lock = d / "SingletonLock"
    # NB: Chromium's lock is a symlink to a *nonexistent* target
    # ("hostname-pid"), so exists() (which follows the link) is False for a
    # live lock — check is_symlink() too.
    if not (lock.exists() or lock.is_symlink()):
        return False
    pid = 0
    try:
        pid = int(str(os.readlink(lock)).rsplit("-", 1)[-1])
    except Exception:  # noqa: BLE001
        return True  # unreadable lock: assume running, refuse to delete
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _tar_bytes(d: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.add(d, arcname=d.name)
    return buf.getvalue()


def _untar_bytes(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        t.extractall(dest, filter="data")


def seal_profile(identity_id: str, profile: str = "main") -> dict:
    """Encrypt sensitive profile files into the vault, delete originals."""
    d = profile_dir(identity_id, profile)
    if not d.exists():
        return {"sealed": [], "note": "no profile dir"}
    if _browser_running(d):
        raise Denied(f"profile {identity_id}/{profile} is in use — refusing to seal")
    sealed: list[str] = []
    for name in SENSITIVE_FILES:
        p = d / name
        if p.is_file():
            vault.overwrite(KIND, _entry(identity_id, profile, name), p.read_bytes())
            p.unlink()
            sealed.append(name)
    for name in SENSITIVE_DIRS:
        p = d / name
        if p.is_dir():
            vault.overwrite(KIND, _entry(identity_id, profile, name), _tar_bytes(p))
            import shutil

            shutil.rmtree(p)
            sealed.append(name)
    if sealed:
        log.info("sealed profile %s/%s: %s", identity_id, profile, ", ".join(sealed))
    return {"sealed": sealed}


def unseal_profile(identity_id: str, profile: str = "main") -> dict:
    """Restore sealed profile files from the vault, drop the vault blobs."""
    d = profile_dir(identity_id, profile)
    restored: list[str] = []
    for name in list(SENSITIVE_FILES) + list(SENSITIVE_DIRS):
        entry = _entry(identity_id, profile, name)
        if not vault.exists(KIND, entry):
            continue
        data = vault.get(KIND, entry)
        target = d / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if name in SENSITIVE_DIRS:
            _untar_bytes(data, d)
        else:
            target.write_bytes(data)
            os.chmod(target, 0o600)
        vault.drop(KIND, entry)
        restored.append(name)
    if restored:
        log.info("unsealed profile %s/%s: %s", identity_id, profile, ", ".join(restored))
    return {"restored": restored}


def enabled() -> bool:
    """Opt-out only: AA_PROFILE_ENCRYPT=0 disables sealing/unsealing."""
    return config.env_bool("AA_PROFILE_ENCRYPT", True)
