"""Paths, env loading and YAML config for airdrop-agent.

Every other module imports this. The home directory defaults to ~/.airdrop-agent
and can be moved with AIRDROP_HOME (filesystem sandbox friendly).
"""
from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

import yaml

PKG_ROOT = Path(__file__).resolve().parents[1]
HOME = Path(os.environ.get("AIRDROP_HOME", Path.home() / ".airdrop-agent")).expanduser()
VAULT_DIR = HOME / "vault"
DATA_DIR = HOME / "data"
SESSION_DIR = HOME / "sessions"
PROFILE_DIR = HOME / "browser"
PROOF_DIR = HOME / "proofs"
LOG_DIR = HOME / "logs"
QUEST_DIR = HOME / "quests"
EXT_DIR = HOME / "extensions"
KILL_FILE = HOME / "KILL"
ENV_FILE = HOME / ".env"
CONFIG_DIR = PKG_ROOT / "config"

DEFAULTS = {
    "policy.yaml": "policy.yaml",
    "quests.yaml": "quests.yaml",
    "radar_sources.yaml": "radar_sources.yaml",
    "personas.yaml": "personas.yaml",
    "discord_servers.yaml": "discord_servers.yaml",
    "faucets.yaml": "faucets.yaml",
    "providers.yaml": "providers.yaml",
    "autopilot.yaml": "autopilot.yaml",
}

for _d in (HOME, VAULT_DIR, DATA_DIR, SESSION_DIR, PROFILE_DIR, PROOF_DIR, LOG_DIR, QUEST_DIR, EXT_DIR):
    _d.mkdir(parents=True, exist_ok=True)
for _d in (HOME, VAULT_DIR, DATA_DIR, SESSION_DIR, PROFILE_DIR, PROOF_DIR, LOG_DIR, QUEST_DIR, EXT_DIR):
    try:
        os.chmod(_d, 0o700)
    except OSError:
        pass


def load_env(path: Path | None = None) -> None:
    """Parse KEY=VALUE lines into os.environ without clobbering real env vars."""
    f = Path(path or ENV_FILE)
    if not f.exists():
        return
    for raw in f.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_required(name: str) -> str:
    v = env(name)
    if not v:
        raise SystemExit(f"missing env {name} (set it in {ENV_FILE})")
    return v


def env_bool(name: str, default: bool = False) -> bool:
    v = env(name)
    return default if not v else v.lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name) or default)
    except ValueError:
        return default


def cfg_path(name: str) -> Path:
    """Config lives in the data home; falls back to the shipped template."""
    p = HOME / name
    if not p.exists():
        tpl = CONFIG_DIR / name
        if tpl.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tpl, p)
    return p


def load_yaml(name: str) -> dict:
    p = cfg_path(name) if not Path(name).is_absolute() else Path(name)
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise SystemExit(f"invalid YAML in {p}: {e}")


def save_yaml(name: str, data: dict) -> None:
    p = HOME / name
    p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def policy() -> dict:
    return load_yaml(os.environ.get("POLICY_FILE", "policy.yaml"))


def providers() -> dict:
    return load_yaml("providers.yaml")


def autopilot_cfg() -> dict:
    return load_yaml("autopilot.yaml")


def personas() -> dict:
    return load_yaml("personas.yaml")


def secure_write(path: Path, data: str) -> None:
    """Write 0600, refusing to silently clobber (O_EXCL) unless overwrite=True."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def secure_overwrite(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    os.chmod(path, 0o600)


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


_SLUG = re.compile(r"[^a-z0-9_-]+")


def slug(text: str, fallback: str = "x") -> str:
    s = _SLUG.sub("-", text.strip().lower()).strip("-")
    return (s or fallback)[:40]


def mask(secret: str, keep: int = 4) -> str:
    if not secret:
        return ""
    return "*" * max(0, len(secret) - keep) + secret[-keep:]
