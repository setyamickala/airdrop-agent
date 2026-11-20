"""Install browser wallet extensions from the Chrome Web Store into a local dir.

Playwright can only load unpacked extensions, so we fetch the CRX, strip the CRX
header, extract the zip and hand the directory to the browser launcher. Pinned
versions are not used — the store always serves current, and manifests are patched
just enough to load unpacked (update_url removed, no MV2 fallback needed).

Usage: aa ext install rabby --identity <id>   -> ~/.airdrop-agent/extensions/<id>/rabby
"""
from __future__ import annotations

import io
import json
import shutil
import struct
import zipfile

import requests

from .. import config
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("ext")

STORE = {
    "rabby": ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
    "metamask": ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    "phantom": ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    "keplr": ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
}
CRX_URL = ("https://clients2.google.com/service/update2/crx?response=redirect"
           "&prodversion=131.0&acceptformat=crx2,crx3&x=id%3D{id}%26uc")


def available() -> dict:
    return {k: v[1] for k, v in STORE.items()}


def _strip_crx(blob: bytes) -> bytes:
    if blob[:4] != b"Cr24":
        raise Denied("download is not a CRX (store may have redirected)")
    ver = struct.unpack("<I", blob[4:8])[0]
    if ver == 3:
        (hlen,) = struct.unpack("<I", blob[8:12])
        return blob[12 + hlen:]
    if ver == 2:
        (pklen, siglen) = struct.unpack("<II", blob[8:16])
        return blob[16 + pklen + siglen:]
    raise Denied(f"unsupported CRX version {ver}")


def install(identity_id: str, name: str, force: bool = False) -> dict:
    if name not in STORE:
        raise Denied(f"unknown extension '{name}' (choices: {', '.join(STORE)})")
    ext_id, label = STORE[name]
    dest = config.EXT_DIR / identity_id / name
    if dest.exists() and not force:
        return {"extension": name, "path": str(dest), "cached": True}
    r = requests.get(CRX_URL.format(id=ext_id), timeout=120, allow_redirects=True)
    r.raise_for_status()
    zbytes = _strip_crx(r.content)
    tmp = dest.with_suffix(".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        z.extractall(tmp)
    if not (tmp / "manifest.json").exists():
        raise Denied("extension archive has no manifest.json")
    manifest = json.loads((tmp / "manifest.json").read_text())
    manifest.pop("update_url", None)
    (tmp / "manifest.json").write_text(json.dumps(manifest))
    for junk in ("_metadata", "META-INF"):
        shutil.rmtree(tmp / junk, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    tmp.rename(dest)
    db_note(identity_id, name, label, manifest.get("version", "?"))
    return {"extension": name, "label": label, "path": str(dest), "version": manifest.get("version"),
            "mv": manifest.get("manifest_version")}


def db_note(identity_id: str, name: str, label: str, version: str) -> None:
    from .. import db

    db.event("ext", f"installed {label} {version}", identity_id)


def paths(identity_id: str) -> list[str]:
    base = config.EXT_DIR / identity_id
    if not base.exists():
        return []
    return [str(p) for p in base.iterdir() if (p / "manifest.json").exists()]


def remove(identity_id: str, name: str) -> dict:
    d = config.EXT_DIR / identity_id / name
    shutil.rmtree(d, ignore_errors=True)
    return {"removed": not d.exists(), "path": str(d)}
