"""Redaction + logging.

Anything printed for the model passes through `redact()`. Patterns are structural
(private keys, tokens, cookies) plus literal values of sensitive env vars, so a new
secret in .env is masked even if we forgot a pattern.
"""
from __future__ import annotations

import logging
import os
import re
import sys

from . import config

SENSITIVE_ENV = re.compile(r"(PASS|PASSWORD|SECRET|TOKEN|KEY|SEED|MNEMONIC|SESSION|COOKIE|PRIVATE)", re.I)

# Never-mask list for values that are useful in logs
KEEP_ENV = {"VAULT_PASSWORD_FILE", "TG_API_ID", "IMAP_PORT", "IMAP_HOST"}

_literals: list[str] = []
_seen: tuple[str, ...] = ()


def register(secret: str | None) -> None:
    if secret and len(secret) >= 8 and secret not in _literals:
        _literals.append(secret)


def refresh_literals() -> None:
    """Pick up secrets added to the environment after import (tests, long-running daemons)."""
    global _seen
    vals = tuple(v for k, v in os.environ.items()
                 if SENSITIVE_ENV.search(k) and k not in KEEP_ENV and v and len(v) >= 8)
    if vals == _seen:
        return
    _seen = vals
    for v in vals:
        register(v)


refresh_literals()

# mnemonic: 12/24 lowercase words separated by spaces
MNEMONIC = re.compile(r"\b(?:[a-z]{3,8} ){11,23}[a-z]{3,8}\b")

PATTERNS = [
    (re.compile(r"\b(0x)?[0-9a-fA-F]{64}\b"), lambda m: (m.group(1) or "") + "0x…" + m.group(0)[-6:]),
    (re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{30,}\b"), lambda m: "bot…" + m.group(0)[-6:]),
    (re.compile(r"\b(MFK|Mf)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{20,}\b"),
     lambda m: "discord…" + m.group(0)[-6:]),
    (re.compile(r"\b[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,}\b"), lambda m: "token…" + m.group(0)[-6:]),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"), lambda m: "proxy…" + m.group(0)[-5:]),
    # 12/24-word mnemonic (regex was defined but never wired into redact()).
    # NOTE: this is structural — any 12+ run of 3-8 letter lowercase words
    # matches, so a long lowercase sentence can be over-redacted. That is
    # the safe direction for a secret; see looks_like_mnemonic() for the
    # strict full-string check.
    (MNEMONIC, lambda m: "mnemonic…redacted"),
    # Solana private key in base58: 64 bytes -> ~87-88 chars. Raw 32-44 char
    # base58 *addresses* are public and deliberately NOT redacted here —
    # a pattern that short would also eat ordinary ids/tokens.
    (re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{87,88}\b"), lambda m: "sol-key…" + m.group(0)[-6:]),
]


def redact(text: str) -> str:
    if not text:
        return text
    refresh_literals()
    out = str(text)
    for secret in sorted(_literals, key=len, reverse=True):
        out = out.replace(secret, secret[:3] + "…" + secret[-3:] if len(secret) > 12 else "***")
    for rx, fn in PATTERNS:
        out = rx.sub(fn, out)
    return out


def looks_like_mnemonic(text: str) -> bool:
    return bool(MNEMONIC.fullmatch(text.strip()))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(f"aa.{name}")
    if log.handlers:
        return log
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    sh.addFilter(RedactingFilter())
    log.addHandler(sh)
    try:
        fh = logging.FileHandler(config.LOG_DIR / "agent.log")
        fh.setFormatter(fmt)
        fh.addFilter(RedactingFilter())
        log.addHandler(fh)
    except OSError:
        pass
    log.propagate = False
    return log
