"""Solana wallets: generate, import, balance, simulate-then-send transfers.

Same rails as EVM: simulate first, caps before signing, receipt stored as proof.
Raw JSON-RPC so no extra SDK dependency; signatures happen locally in-process.
"""
from __future__ import annotations

import base64
import time

import requests
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from .. import db, gates, guard, vault
from ..jsonio import Denied
from ..log import get_logger
from . import hd

log = get_logger("wallet.sol")
LAMPORTS = 1_000_000_000
MEMO_PROGRAM = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


def rpc(cfg: dict, method: str, params: list):
    r = requests.post(cfg["rpc"], json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(f"solana {method}: {body['error'].get('message')}")
    return body.get("result")


def create(identity_id: str, count: int = 1, prefix: str = "sol") -> list[dict]:
    out = []
    for _ in range(count):
        kp = Keypair()
        label = f"{identity_id}-{prefix}-{str(kp.pubkey())[:6].lower()}"
        vault.store_sol(label, bytes(kp))
        db.add_wallet(identity_id, "sol", str(kp.pubkey()), label)
        out.append({"label": label, "address": str(kp.pubkey())})
        del kp
    db.event("wallet", f"created {count} sol wallet(s)", identity_id)
    return out


def derive(identity_id: str, count: int = 1) -> list[dict]:
    return hd.provision(identity_id, "sol", count, prefix="s")


def import_key(identity_id: str, secret: str, label: str | None = None) -> dict:
    raw = secret.strip()
    try:
        if raw.startswith("["):
            import json

            data = bytes(json.loads(raw))
            kp = Keypair.from_seed(data) if len(data) == 32 else Keypair.from_bytes(data)
        elif raw.startswith("0x"):
            data = bytes.fromhex(raw[2:])
            kp = Keypair.from_seed(data) if len(data) == 32 else Keypair.from_bytes(data)
        else:
            kp = Keypair.from_base58_string(raw)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"cannot parse solana secret: {e}")
    label = label or f"{identity_id}-imp-{str(kp.pubkey())[:6].lower()}"
    vault.store_sol(label, bytes(kp))
    db.add_wallet(identity_id, "sol", str(kp.pubkey()), label, kind="imported")
    return {"label": label, "address": str(kp.pubkey())}


def resolve(identity_id: str, ref: str) -> dict:
    ws = db.wallets(identity_id, "sol")
    if not ws:
        raise Denied(f"identity {identity_id} has no Solana wallet (aa wallet new --chain sol ...)")
    if ref in ("first", "default", ""):
        return ws[0]
    for w in ws:
        if w["label"] == ref or w["address"] == ref:
            return w
    raise SystemExit(f"sol wallet not found: {ref}")


def balance(cfg: dict, address: str) -> dict:
    res = rpc(cfg, "getBalance", [address, {"commitment": "confirmed"}])
    lamports = int((res or {}).get("value", 0))
    return {"address": address, "lamports": lamports, "sol": lamports / LAMPORTS}


def _unsigned_transfer(cfg: dict, from_addr: str, to_addr: str, lamports: int, memo: str | None):
    blockhash = rpc(cfg, "getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"]
    ix = transfer(TransferParams(from_pubkey=Pubkey.from_string(from_addr),
                                 to_pubkey=Pubkey.from_string(to_addr), lamports=lamports))
    ixns = [ix]
    if memo:
        from solders.instruction import Instruction

        ixns.append(Instruction(MEMO_PROGRAM, memo.encode(), []))
    msg = Message.new_with_blockhash(ixns, Pubkey.from_string(from_addr), Hash.from_string(blockhash))
    return Transaction.new_unsigned(msg), blockhash


def send(cfg: dict, key: str, to_addr: str, lamports: int, *, memo: str | None = None,
         broadcast: bool = False, identity_id: str = "") -> dict:
    from .. import policy as pol

    # The gate lives HERE, in the library send() — not in the CLI — so every
    # caller (CLI, MCP, guards) gates exactly once. The CLI used to gate with
    # the identical payload before calling send(), which double-gated: the
    # single-use approval was consumed by the CLI and demanded again here.
    guard.check_kill()
    if pol.blocked(to_addr):
        raise Denied(f"address blocklisted: {to_addr}")
    kp = vault.load_sol(key)
    from_addr = str(kp.pubkey())
    tx, blockhash = _unsigned_transfer(cfg, from_addr, to_addr, lamports, memo)
    sim = rpc(cfg, "simulateTransaction", [base64.b64encode(bytes(tx)).decode(),
                                          {"sigVerify": False, "replaceRecentBlockhash": True,
                                           "commitment": "confirmed"}])
    if (sim or {}).get("value", {}).get("err"):
        raise Denied(f"simulation failed: {sim['value']['err']}")
    units = int((sim or {}).get("value", {}).get("unitsConsumed") or 0)
    pol.check_value(_chain_name(cfg), _wallet_of(identity_id, from_addr) if identity_id else key,
                    lamports, 5000, 1)
    payload = {"_kind": "tx", "chain": _chain_name(cfg), "identity": identity_id, "label": key,
               "to": to_addr, "value": str(lamports), "data": "solana"}
    want_gate, reasons = pol.needs_gate("tx", mainnet=not cfg.get("testnet"), contract_ok=True)
    if want_gate:
        if not gates.consume(payload):
            gates.require("tx", f"SOL send {lamports / LAMPORTS} → {to_addr} dari {key} "
                                f"({'; '.join(reasons)})", payload)
    elif not gates.consume(payload):
        db.event("tx", f"auto: SOL send {lamports / LAMPORTS} → {to_addr}", identity_id)
    if not broadcast:
        return {"simulated": True, "from": from_addr, "to": to_addr, "lamports": lamports,
                "units": units, "blockhash": blockhash}
    tx.sign([kp], Hash.from_string(blockhash))
    sig = rpc(cfg, "sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                      {"encoding": "base64", "skipPreflight": False, "maxRetries": 3}])
    for _ in range(30):
        st = rpc(cfg, "getSignatureStatuses", [[sig], {"searchTransactionHistory": False}])
        v = ((st or {}).get("value") or [None])[0]
        if v and v.get("confirmationStatus") in ("confirmed", "finalized"):
            db.add_spend(_chain_name(cfg), key, lamports)
            return {"signature": sig, "confirmed": True, "slot": v.get("slot"), "status": v.get("confirmationStatus")}
        time.sleep(1.2)
    return {"signature": sig, "confirmed": False, "note": "sent but not confirmed in 36s"}


def _wallet_of(identity_id: str, address: str) -> str:
    r = db.one("SELECT label FROM wallets WHERE identity_id=? AND chain='sol' AND address=?", (identity_id, address))
    return r["label"] if r else address


def _chain_name(cfg: dict) -> str:
    return cfg.get("name", "solana")
