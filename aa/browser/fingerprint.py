"""Deterministic per-identity browser fingerprint.

Every identity gets a stable, distinct fingerprint derived only from its
``identity_id`` (SHA-256 picks, UUIDv5 for the EIP-6963 UUID), so one identity
looks the same on every run but different identities do not look alike.
Nothing is stored: the same input always yields the same config, which is
what makes this testable without launching a live browser.

Deliberate limits (do not over-claim): this varies the *declared* values
(UA, locale/timezone, viewport, hardwareConcurrency/deviceMemory, the
EIP-6963 UUID) and ships a small, honest stealth shim. It does NOT spoof
canvas/WebGL/audio/font fingerprints — those are not implemented here.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

# Chrome versions that were still supported when this was written (late 2026).
CHROME_VERSIONS = ("140.0.0.0", "141.0.0.0", "142.0.0.0", "143.0.0.0", "144.0.0.0")

# (UA platform fragment, navigator.platform) — kept consistent with each other.
PLATFORMS = (
    ("Macintosh; Intel Mac OS X 10_15_7", "MacIntel"),
    ("Windows NT 10.0; Win64; x64", "Win32"),
    ("X11; Linux x86_64", "Linux x86_64"),
)

# (timezone_id, locale) — always a matching pair, never e.g. Asia/Jakarta
# with en-US the way the old single global config did.
LOCALES = (
    ("Asia/Jakarta", "id-ID"),
    ("Asia/Singapore", "en-SG"),
    ("Asia/Tokyo", "ja-JP"),
    ("Europe/Berlin", "de-DE"),
    ("America/New_York", "en-US"),
    ("America/Los_Angeles", "en-US"),
    ("Europe/London", "en-GB"),
    ("Asia/Seoul", "ko-KR"),
)

VIEWPORTS = ((1920, 1080), (1366, 768), (1536, 864), (1440, 900), (1280, 720), (1600, 900))
HARDWARE_CONCURRENCY = (4, 8, 12, 16)
DEVICE_MEMORY = (4, 8, 16)


def _pick(identity_id: str, salt: str, n: int) -> int:
    digest = hashlib.sha256(f"aa-fingerprint:{salt}:{identity_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % n


def _languages(locale: str) -> list[str]:
    base = locale.split("-")[0]
    langs = [locale]
    if base != locale:
        langs.append(base)
    if "en" not in langs:
        langs.append("en")
    return langs


def fingerprint_config(identity_id: str) -> dict:
    """Deterministic fingerprint config for one identity."""
    identity_id = str(identity_id or "main")
    version = CHROME_VERSIONS[_pick(identity_id, "chrome", len(CHROME_VERSIONS))]
    plat, nav_platform = PLATFORMS[_pick(identity_id, "platform", len(PLATFORMS))]
    tz, locale = LOCALES[_pick(identity_id, "locale", len(LOCALES))]
    vw, vh = VIEWPORTS[_pick(identity_id, "viewport", len(VIEWPORTS))]
    cores = HARDWARE_CONCURRENCY[_pick(identity_id, "cores", len(HARDWARE_CONCURRENCY))]
    mem = DEVICE_MEMORY[_pick(identity_id, "memory", len(DEVICE_MEMORY))]
    return {
        "identity_id": identity_id,
        "user_agent": (f"Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) "
                       f"Chrome/{version} Safari/537.36"),
        "platform": nav_platform,
        "timezone_id": tz,
        "locale": locale,
        "languages": _languages(locale),
        "viewport": {"width": vw, "height": vh},
        "hardware_concurrency": cores,
        "device_memory": mem,
        # UUIDv5: stable per identity, distinct across identities, no state.
        "eip6963_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"airdrop-agent:{identity_id}")),
    }


def render_stealth_js(cfg: dict) -> str:
    """Fill the stealth.js template with one identity's fingerprint values."""
    template = (Path(__file__).parent / "stealth.js").read_text(encoding="utf-8")
    return (template
            .replace("__AA_LANGUAGES_JSON__", json.dumps(cfg["languages"]))
            .replace("__AA_HARDWARE_CONCURRENCY__", str(cfg["hardware_concurrency"]))
            .replace("__AA_DEVICE_MEMORY__", str(cfg["device_memory"]))
            .replace("__AA_PLATFORM__", json.dumps(cfg["platform"])))
