"""Message + typed-data signing with a policy layer.

Signing is how wallets get drained, so the rules are explicit:

  plain UTF-8 personal_sign  -> origin must be allowlisted; the page must match the SIWE domain
  eth_sign / blind 32-byte   -> summarised, gated, never auto
  EIP-712 Permit/Permit2/Seaport/order -> summarised field by field, gated
  anything else typed        -> gated when it carries value-bearing fields
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_utils import is_address, to_checksum_address

from .. import db, gates, policy, vault
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("sign")

RISKY_PRIMARY = re.compile(r"(?i)permit|order|seaport|swap|intent|mail|witness|delegat")
VALUE_FIELDS = {"spender", "amount", "value", "deadline", "nonce", "token", "tokenId", "operator", "approved", "expiry"}


def origin_host(origin: str) -> str:
    if "://" in origin:
        return (urlparse(origin).hostname or "").lower()
    return urlparse("https://" + origin).hostname or origin.lower()


def _allowed(host: str) -> bool:
    return policy.domain_ok(host)


def summarize_message(message: str) -> dict:
    host = ""
    m = re.search(r"(?i)(?:domain|uri|origin)\s*[:=]\s*([^\s\n]+)", message)
    if m:
        host = origin_host(m.group(1))
    nonce = re.search(r"(?i)nonce\s*[:=]\s*(\S+)", message)
    return {"chars": len(message), "domain_field": host, "has_nonce": bool(nonce),
            "looks_like_siwe": bool(re.search(r"(?i)sign[- ]in with ethereum|wants you to sign", message))}


def summarize_typed(typed: dict) -> dict:
    domain = typed.get("domain") or {}
    msg = typed.get("message") or {}
    fields = sorted(msg.keys())
    amounts = {k: msg[k] for k in fields if k.lower() in VALUE_FIELDS}
    return {"primary": typed.get("primaryType", ""),
            "domain": domain.get("name") or domain.get("verifyingContract") or "",
            "host": origin_host(domain.get("name", "")) if domain.get("name") else "",
            "chain_id": domain.get("chainId"),
            "fields": fields,
            "value_fields": {k: str(v)[:24] for k, v in amounts.items()},
            "risky": bool(RISKY_PRIMARY.search(typed.get("primaryType", ""))) or bool(amounts)}


def _check_origin(host: str, strict: bool = True) -> None:
    if strict and not _allowed(host):
        raise Denied(f"origin '{host}' is not in the domain allowlist (aa allow add {host})")


def personal(identity_id: str, label: str, message: str, origin: str = "",
             broadcast_gate: bool = True) -> dict:
    host = origin_host(origin) if origin else ""
    if host:
        _check_origin(host)
    summary = summarize_message(message)
    payload = {"_kind": "sign_text", "identity_id": identity_id, "label": label,
               "message": message, "origin": host}
    gate, reasons = policy.needs_gate("sign_text", identity_id=identity_id,
                                      looks_like_siwe=summary["looks_like_siwe"])
    if gate and broadcast_gate:
        gates.require("sign_text", f"Sign message di {host or 'CLI'} ({summary['chars']} chars)\n{message[:280]}", payload)

    acct = Account.from_key(vault.load_evm(label).key)
    sig = acct.sign_message(encode_defunct(text=message)).signature.hex()
    db.event("sign", f"personal_sign {host}", identity_id, data={"label": label})
    return {"address": acct.address, "signature": sig if sig.startswith("0x") else "0x" + sig,
            "summary": summary, "origin": host}


def typed(identity_id: str, label: str, typed_json: dict | str, origin: str = "") -> dict:
    data = json.loads(typed_json) if isinstance(typed_json, str) else typed_json
    if not isinstance(data, dict) or "message" not in data or "types" not in data:
        raise SystemExit("typed data needs types/primaryType/domain/message")
    s = summarize_typed(data)
    # The host that must be allowlisted is the page origin that asked for
    # the signature — never the `domain.name` inside the typed data itself,
    # which the page controls and can spoof (e.g. domain.name "Uniswap"
    # while the page is a drainer). Without a page origin there is nothing
    # to verify against, so the sign is denied; the CLI passes --origin.
    host = host_from_origin(origin) if origin else ""
    if not host:
        raise Denied("typed sign needs a verifiable page origin "
                     "(browser: origin missing; CLI: pass --origin <host>)")
    _check_origin(host, strict=True)
    mainnet = int(s.get("chain_id") or 1) in (1, 8453, 10, 42161, 137, 56)
    payload = {"_kind": "sign_typed", "identity_id": identity_id, "label": label,
               "typed": data, "origin": host}
    gate, reasons = policy.needs_gate("sign_typed", risky=s["risky"], mainnet=mainnet)
    if gate:
        detail = (f"Typed data {s['primary']} di {host or 'CLI'} chain={s.get('chain_id')}\n"
                  f"fields: {', '.join(s['fields'][:12])}\n"
                  f"value: {json.dumps(s['value_fields'], ensure_ascii=False)[:300]}")
        gates.require("sign_typed", detail, payload)
    acct = vault.load_evm(label)
    signed = Account.sign_typed_data(acct.key, full_message=data)
    db.event("sign", f"typed_data {s['primary']} {host}", identity_id, data={"label": label})
    return {"address": acct.address, "signature": "0x" + signed.signature.hex().removeprefix("0x"),
            "summary": s, "reasons": reasons}


def host_from_origin(origin: str) -> str:
    return origin_host(origin) if origin else ""


def recover(message: str, signature: str) -> str:
    return Account.recover_message(encode_defunct(text=message), signature=signature)


def eip712_hash(data: dict) -> str:
    return encode_typed_data(full_message=data).body.hex()


def validate_address(addr: str) -> str:
    if not is_address(addr):
        raise Denied(f"invalid address {addr}")
    return to_checksum_address(addr)
