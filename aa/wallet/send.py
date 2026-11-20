"""EVM transaction pipeline: decode -> policy -> simulate -> gate -> sign -> broadcast -> proof.

There is no other broadcast path in the codebase. Anything that moves value (CLI,
quest runner, browser wallet provider, testnet campaigns) funnels through `send()`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address

from .. import chains, config, db, gates, guard, policy, vault
from ..jsonio import Denied
from ..log import get_logger

log = get_logger("send")

SEL = {
    "0xa9059cbb": ("transfer", ["address", "uint256"]),
    "0x095ea7b3": ("approve", ["address", "uint256"]),
    "0x39509351": ("increaseAllowance", ["address", "uint256"]),
    "0x23b872dd": ("transferFrom", ["address", "address", "uint256"]),
    "0xa22cb465": ("setApprovalForAll", ["address", "bool"]),
    "0x42842e0e": ("safeTransferFrom", ["address", "address", "uint256"]),
    "0x87517c45": ("permit2Approve", ["address", "address", "uint160", "uint48"]),
    "0x2e7ba6ef": ("claim", ["uint256", "uint256", "bytes32[]", "uint256"]),
    "0x379607f5": ("claim", ["uint256"]),
}
ZERO = "0x0000000000000000000000000000000000000000"


def decode(calldata: str) -> dict:
    if not calldata or calldata in ("0x", "0x0"):
        return {"kind": "native"}
    sel = calldata[:10]
    if sel not in SEL:
        return {"kind": "call", "selector": sel}
    name, types = SEL[sel]
    try:
        vals = abi_decode(types, bytes.fromhex(calldata[10:]))
    except Exception:  # noqa: BLE001
        return {"kind": name, "selector": sel, "undecodable": True}
    d = {"kind": name, "selector": sel}
    if name in ("approve", "increaseAllowance", "transfer", "permit2Approve"):
        d["target"] = vals[0]
        d["amount"] = str(int(vals[-1]) if name != "permit2Approve" else int(vals[-2]))
    if name == "transferFrom":
        d["from"], d["target"], d["amount"] = vals[0], vals[1], str(int(vals[2]))
    if name == "setApprovalForAll":
        d["operator"], d["approved"] = vals[0], bool(vals[1])
    if name == "safeTransferFrom":
        d["from"], d["target"], d["token_id"] = vals[0], vals[1], str(vals[2])
    return d


def _human(dec: dict, value_wei: int, chain: str) -> str:
    d = 10 ** policy.decimals(chain)
    if dec["kind"] == "native":
        return f"native transfer {value_wei/d:.6f} on {chain}"
    if dec["kind"] == "call" and not value_wei:
        return "contract call"
    if dec["kind"] in ("approve", "increaseAllowance", "permit2Approve"):
        amt = dec.get("amount", "0")
        bits = 160 if dec["kind"] == "permit2Approve" else 256
        tag = "UNLIMITED" if policy.unlimited_approval(amt, bits=bits) else f"{int(amt)/d:.4f}"
        return f"{dec['kind']} {tag} to spender {dec.get('target')}"
    if dec["kind"] == "setApprovalForAll":
        return f"setApprovalForAll operator {dec.get('operator')} -> {dec.get('approved')}"
    return f"contract call {dec.get('selector')} (value {value_wei/d:.6f})"


def _check_unlimited(dec: dict) -> None:
    """Hard block for unlimited approvals, in every mode (K6).

    Runs after decode() and before simulation, so no gas is spent and no gate
    is created for a transaction that must never run. A finite approval, or
    revoking setApprovalForAll (approved=False), passes through.
    """
    kind = dec.get("kind")
    if kind in ("approve", "increaseAllowance", "permit2Approve"):
        bits = 160 if kind == "permit2Approve" else 256
        if policy.unlimited_approval(dec.get("amount"), bits=bits):
            raise Denied(f"unlimited approval blocked ({kind}) — use a finite amount")
    elif kind == "setApprovalForAll" and dec.get("approved"):
        raise Denied("unlimited approval blocked (setApprovalForAll) — use a finite approval instead")


def send(chain: str, identity_id: str, label: str, to: str | None, *, value_wei: int = 0, calldata: str = "0x",
         broadcast: bool = False, task: str = "", via: str = "cli", contract_creation: bool = False) -> dict:
    guard.check_kill()
    w3, cfg = chains.w3(chain)
    if to:
        to = to_checksum_address(to)
        if policy.blocked(to):
            raise Denied(f"address is blocklisted: {to}")
    elif not contract_creation:
        raise Denied("send needs a recipient")
    acct = vault.load_evm(label)
    owner = acct.address
    dec = decode(calldata)
    _check_unlimited(dec)
    summary = _human(dec, value_wei, chain)
    contract_ok = policy.allowlisted_contract(chain, to or "") or dec["kind"] == "native" or contract_creation

    # simulate before spending a gate/code
    gas = 0
    sim_tx = {"from": owner, "value": value_wei, "data": calldata if calldata != "0x" else b""}
    if to:
        sim_tx["to"] = to
    try:
        gas = int(w3.eth.estimate_gas(sim_tx))
    except Exception as e:  # noqa: BLE001 — revert / no code
        raise Denied(f"simulation reverted: {str(e)[:200]}")
    base = w3.eth.get_block("latest").get("baseFeePerGas") or w3.eth.gas_price
    try:
        prio = w3.eth.max_priority_fee
    except Exception:  # noqa: BLE001
        prio = w3.to_wei(1, "gwei")
    max_fee = min(int(base * 2 + prio), int(base + w3.to_wei(5, "gwei")))
    policy.check_value(chain, label, value_wei, max_fee, gas)

    payload = {"_kind": "tx", "chain": chain, "identity": identity_id, "label": label, "to": to,
               "value": str(value_wei), "data": calldata, "task": task}
    want_gate, reasons = policy.needs_gate("tx", mainnet=not cfg["testnet"], contract_ok=contract_ok)
    if want_gate:
        body = (f"TX {summary}\nfrom {label} {owner}\nto {to}\ngas~{gas} fee~{gas*max_fee/1e18:.8f}\n"
                f"alasan: {'; '.join(reasons)}")
        if not gates.consume(payload):
            gates.require("tx", body, payload)
    elif not gates.consume(payload):
        db.event("tx", f"auto: {summary}", identity_id)

    tx = {"chainId": int(cfg["chain_id"]), "from": owner, "value": value_wei,
          "data": calldata if calldata != "0x" else b"", "nonce": w3.eth.get_transaction_count(owner),
          "gas": gas, "maxFeePerGas": max_fee, "maxPriorityFeePerGas": int(prio), "type": 2}
    if to:
        tx["to"] = to
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction
    if not broadcast:
        return {"simulated": True, "summary": summary, "to": to, "value": str(value_wei), "gas": gas,
                "fee_native": gas * max_fee / 1e18, "raw_len": len(raw), "reasons": reasons,
                "explorer": chains.explorer(chain, "pending")}

    h = w3.eth.send_raw_transaction(raw)
    txhash = h.hex() if isinstance(h, str) else h.hex()
    if not txhash.startswith("0x"):
        txhash = "0x" + txhash
    # Record the broadcast hash BEFORE waiting for the receipt, so the hash
    # survives a receipt timeout (and the runner can park on it instead of
    # re-broadcasting a transaction that may already be mined).
    p = config.PROOF_DIR / f"tx_{chain}_{txhash[2:10]}.json"
    p.write_text(json.dumps({"tx": txhash, "chain": chain, "from": owner, "to": to,
                             "value": str(value_wei), "summary": summary, "status": "broadcast",
                             "receipt": "pending", "via": via, "ts": db.now(),
                             "explorer": chains.explorer(chain, txhash)}, indent=2))
    db.event("tx", txhash, identity_id, data={"chain": chain, "label": label, "ok": None,
                                              "broadcast": True})
    try:
        receipt = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    except Exception:  # noqa: BLE001 — timeout / RPC drop after broadcast
        raise Denied(f"tx broadcast but receipt not confirmed within timeout: {txhash}")
    ok = int(receipt.get("status", 0)) == 1
    db.add_spend(chain, label, value_wei + gas * (receipt.get("effectiveGasPrice") or max_fee))
    proof = {"tx": txhash, "chain": chain, "from": owner, "to": to, "value": str(value_wei),
             "summary": summary, "gas_used": receipt.get("gasUsed"), "status": ok,
             "block": receipt.get("blockNumber"), "via": via, "ts": db.now(),
             "explorer": chains.explorer(chain, txhash)}
    p.write_text(json.dumps(proof, indent=2))
    db.event("tx", txhash, identity_id, data={"chain": chain, "label": label, "ok": ok})
    if not ok:
        raise Denied(f"tx mined but reverted: {txhash}")
    return {"tx": txhash, "confirmed": True, "block": receipt.get("blockNumber"), "gas_used": receipt.get("gasUsed"),
            "explorer": chains.explorer(chain, txhash), "summary": summary, "proof": str(p)}


def approve(chain: str, identity_id: str, label: str, token: str, spender: str,
            amount: int | None = None, broadcast: bool = False) -> dict:
    """ERC20 approve builder. `amount` is required and must be finite — an
    unlimited approval is hard-blocked, so amount=None is denied here, before
    any RPC call is made."""
    if amount is None:
        raise Denied("approve amount is required; unlimited approval is blocked — "
                     "pass an explicit finite --amount")
    from eth_abi import encode as abi_encode

    data = "0x095ea7b3" + abi_encode(["address", "uint256"], [to_checksum_address(spender), amount]).hex()
    return send(chain, identity_id, label, token, calldata=data, broadcast=broadcast, via="approve")


def transfer_token(chain: str, identity_id: str, label: str, token: str, to: str, amount: int,
                   broadcast: bool = False) -> dict:
    from eth_abi import encode as abi_encode

    data = "0xa9059cbb" + abi_encode(["address", "uint256"], [to_checksum_address(to), amount]).hex()
    return send(chain, identity_id, label, token, calldata=data, broadcast=broadcast, via="transfer_token")


def wait_balance(address: str, chain: str, min_wei: int, timeout: int = 600) -> dict:
    w3, _ = chains.w3(chain)
    end = time.time() + timeout
    while time.time() < end:
        b = w3.eth.get_balance(to_checksum_address(address))
        if b >= min_wei:
            return {"address": address, "wei": b, "funded": True}
        time.sleep(15)
    return {"address": address, "wei": 0, "funded": False}


def proof_dir() -> Path:
    return config.PROOF_DIR
