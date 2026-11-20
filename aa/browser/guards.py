"""Wallet bridge between the injected page provider and the Python guards.

Every request hits policy first. The page never gets a signature the operator did not
approve (or that the active mode did not authorise within caps).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from urllib.parse import urlparse

from .. import chains, db, gates, policy, scam_check, vault
from ..jsonio import Denied, Gate
from ..log import get_logger
from ..wallet import send as sender
from ..wallet import sign as signer
from ..wallet.sol_tx import decode_transaction

log = get_logger("bridge")


class WalletBridge:
    def __init__(self, browser):
        self.b = browser
        self.identity_id = browser.identity_id
        self.chain = browser.chain
        self._label = None
        self._events: list[dict] = []

    @property
    def label(self) -> str:
        if self._label:
            return self._label
        ws = db.wallets(self.identity_id, "evm")
        if not ws:
            raise Denied("identity has no EVM wallet")
        self._label = ws[0]["label"]
        return self._label

    @label.setter
    def label(self, v: str) -> None:
        self._label = v

    @property
    def address(self) -> str:
        return vault.get_address("evm", self.label)

    @property
    def sol_address(self) -> str:
        ws = db.wallets(self.identity_id, "sol")
        return ws[0]["address"] if ws else ""

    def _origin(self, source) -> str:
        """`source` comes from Playwright: a mapping whose "frame" is a Frame object."""
        try:
            frame = source.get("frame") if hasattr(source, "get") else getattr(source, "frame", None)
            url = getattr(frame, "url", None) or (frame.get("url") if hasattr(frame, "get") else "")
            return (urlparse(url or "").hostname or "").lower()
        except Exception:  # noqa: BLE001
            return ""

    def _log(self, **kw) -> None:
        kw["ts"] = db.now()
        self._events = (self._events + [kw])[-40:]

    async def events(self) -> list[dict]:
        return self._events

    async def _check_page_text(self, method: str) -> None:
        """Best-effort drainer scan of the visible page before a connect/sign.

        Runs in the async wrapper (the sync _evm_sync/_sol_sync cannot await
        the page). A `bad` page is denied outright; `warn` is logged and left
        to the gate. If the page text is unavailable (no page yet, navigation
        in flight) the check is skipped silently — the origin scam_check in
        _guard still applies.
        """
        try:
            text = await asyncio.wait_for(self.b.page.inner_text("body"), timeout=3)
        except Exception:  # noqa: BLE001
            return
        v = scam_check.check_page_text((text or "")[:20000])
        if v["verdict"] == "bad":
            raise Denied(f"page text looks like a drainer ({'; '.join(v['reasons'])})")
        if v["verdict"] == "warn":
            log.warning("drainer-ish page text before %s: %s", method, "; ".join(v["reasons"]))
            db.event("scam", f"warn page text before {method}: {'; '.join(v['reasons'])}",
                     self.identity_id, level="warn")

    # ---------- EVM ----------
    async def evm(self, source: dict, method: str, params_json: str) -> str:
        params = json.loads(params_json or "[]")
        origin = self._origin(source)
        try:
            if method in ("eth_requestAccounts", "wallet_requestPermissions", "personal_sign",
                          "eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData",
                          "eth_sendTransaction"):
                await self._check_page_text(method)
            res = await asyncio.to_thread(self._evm_sync, origin, method, params)
        except Gate as e:
            res = {"error": {"code": 4001, "message": f"approval needed: {e}"}}
        except Denied as e:
            res = {"error": {"code": 4100, "message": str(e)}}
        except Exception as e:  # noqa: BLE001
            log.exception("bridge error %s", method)
            res = {"error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
        self._log(method=method, origin=origin, result="ok" if "error" not in res else res["error"]["message"])
        return json.dumps(res, default=str)

    def _guard(self, origin: str) -> dict:
        if not origin:
            raise Denied("no page origin")
        v = scam_check.check_url("https://" + origin)
        if v["verdict"] == "bad":
            raise Denied(f"origin {origin} looks like a drainer ({'; '.join(v['reasons'])})")
        return v

    def _require_connected(self, origin: str) -> None:
        """Deny wallet-leaking reads until the origin has connected.

        There is no per-origin "connect gate consumed" state to query — a
        consumed connect gate allowlists the domain in _needs_connect_gate,
        so the domain allowlist is the record of it. An origin that has
        never connected (or was never allowlisted) gets Denied here, after
        the drainer check in _guard.
        """
        self._guard(origin)
        if not policy.domain_ok(origin):
            raise Denied(f"origin '{origin}' has not connected "
                         f"(no connect gate consumed) — connect first")

    def _needs_connect_gate(self, origin: str, verdict: dict) -> bool:
        if policy.domain_ok(origin) and verdict["verdict"] == "ok":
            return False
        if verdict["verdict"] == "ok" and policy.mode() == "turbo" and policy.cfg().get("auto_allowlist_domains", True):
            policy.allow_domain(origin)
            db.event("policy", f"auto-allowlisted {origin}", self.identity_id)
            return False
        payload = {"_kind": "connect", "identity_id": self.identity_id, "origin": origin}
        if gates.consume(payload):
            policy.allow_domain(origin)
            return False
        return True

    def _evm_sync(self, origin: str, method: str, params: list) -> dict:
        if method == "eth_accounts":
            self._require_connected(origin)
            return {"result": [self.address]}
        if method in ("eth_chainId", "net_version"):
            cid = int(chains.cfg(self.chain)["chain_id"])
            return {"result": hex(cid) if method == "eth_chainId" else str(cid)}
        if method == "wallet_getPermissions":
            return {"result": [{"parentCapability": "eth_accounts"}]}
        if method in ("wallet_requestPermissions", "eth_requestAccounts"):
            v = self._guard(origin)
            if self._needs_connect_gate(origin, v):
                gates.require("connect", f"Connect wallet {self.address} ke {origin} "
                                         f"(scam_check={v['verdict']}: {'; '.join(v['reasons']) or 'clean'})",
                              {"_kind": "connect", "identity_id": self.identity_id, "origin": origin})
            return {"result": [self.address]}
        if method == "wallet_switchEthereumChain":
            want = int(params[0]["chainId"], 16) if params else 0
            for name in chains.all_chains():
                if int(policy.chain(name)["chain_id"]) == want:
                    self.chain = name
                    self.b.chain = name
                    return {"result": None, "chainId": hex(want)}
            raise Denied(f"chain {want} not in policy.yaml")
        if method == "wallet_watchAsset":
            return {"result": True}
        if method == "personal_sign":
            msg = params[0]
            text = _decode_hex(msg)
            out = signer.personal(self.identity_id, self.label, text, origin, broadcast_gate=True)
            self._log(kind="sign_text", origin=origin)
            return {"result": out["signature"]}
        if method in ("eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData"):
            typed = params[1] if len(params) > 1 else params[0]
            out = signer.typed(self.identity_id, self.label, typed, origin)
            self._log(kind="sign_typed", origin=origin)
            return {"result": out["signature"]}
        if method == "eth_sendTransaction":
            tx = params[0]
            to = tx.get("to")
            if not to:
                raise Denied("contract creation from the page is not supported yet")
            value = int(tx.get("value", "0x0"), 16)
            data = tx.get("data") or tx.get("input") or "0x"
            out = sender.send(self.chain, self.identity_id, self.label, to,
                              value_wei=value, calldata=data, broadcast=True, via="browser")
            return {"result": out["tx"], "proof": out.get("proof")}
        if method == "eth_estimateGas":
            self._require_connected(origin)
            w3, _ = chains.w3(self.chain)
            tx = params[0]
            gas = w3.eth.estimate_gas({"from": tx.get("from", self.address), "to": tx.get("to"),
                                       "value": int(tx.get("value", "0x0"), 16),
                                       "data": tx.get("data", "0x")})
            return {"result": hex(gas)}
        if method in ("eth_gasPrice", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount",
                      "eth_getTransactionReceipt", "eth_call"):
            w3, _ = chains.w3(self.chain)
            if method == "eth_call":
                self._require_connected(origin)
                p = params[0]
                r = w3.eth.call({"to": p.get("to"), "data": p.get("data", "0x")},
                                p.get("block_identifier", "latest"))
                return {"result": r.hex()}
            if method == "eth_gasPrice":
                return {"result": hex(w3.eth.gas_price)}
            if method == "eth_blockNumber":
                return {"result": hex(w3.eth.block_number)}
            if method == "eth_getBalance":
                return {"result": hex(w3.eth.get_balance(params[0]))}
            if method == "eth_getTransactionCount":
                return {"result": hex(w3.eth.get_transaction_count(params[0]))}
            if method == "eth_getTransactionReceipt":
                r = w3.eth.get_transaction_receipt(params[0])
                return {"result": dict(r) if r else None}
            return {"result": None}
        raise Denied(f"unsupported method {method}")

    # ---------- Solana ----------
    async def solana(self, source: dict, method: str, params_json: str) -> str:
        params = json.loads(params_json or "[]")
        origin = self._origin(source)
        try:
            if method in ("connect", "wallet_requestPermissions", "eth_requestAccounts",
                          "signMessage", "signTransaction", "signAndSendTransaction"):
                await self._check_page_text(method)
            res = await asyncio.to_thread(self._sol_sync, origin, method, params)
        except Gate as e:
            res = {"error": {"code": 4001, "message": f"approval needed: {e}"}}
        except Denied as e:
            res = {"error": {"code": 4100, "message": str(e)}}
        except Exception as e:  # noqa: BLE001
            log.exception("sol bridge error %s", method)
            res = {"error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
        self._log(method=f"sol:{method}", origin=origin)
        return json.dumps(res, default=str)

    def _sol_addr(self) -> str:
        ws = db.wallets(self.identity_id, "sol")
        if not ws:
            raise Denied("identity has no Solana wallet")
        return ws[0]["address"]

    def _sol_sync(self, origin: str, method: str, params: list) -> dict:
        from solders.transaction import Transaction

        v = self._guard(origin)
        if method in ("connect", "wallet_requestPermissions", "eth_requestAccounts"):
            if self._needs_connect_gate(origin, v):
                gates.require("connect", f"Connect Solana wallet {self._sol_addr()} ke {origin} "
                                         f"(scam_check={v['verdict']})",
                              {"_kind": "connect", "identity_id": self.identity_id, "origin": origin,
                               "chain_family": "sol"})
            return {"result": {"publicKey": self._sol_addr()}}
        if method in ("disconnect",):
            return {"result": None}
        if method == "signMessage":
            raw = params[0]
            data = bytes(raw) if isinstance(raw, list) else base64.b64decode(raw)
            # Previously this signed with no gate at all, so any page that
            # passed scam_check could get an arbitrary message signed
            # (including Sign-In With Solana). Mirror EVM personal_sign:
            # origin must be allowlisted, sign-in messages always gate.
            if not policy.domain_ok(origin):
                raise Denied(f"origin '{origin}' is not in the domain allowlist (aa allow add {origin})")
            text = data.decode("utf-8", "replace")
            lowered = text.lower()
            looks_like_siwe = ("sign-in with" in lowered or "sign in with" in lowered
                               or "wants you to sign" in lowered)
            gate, _reasons = policy.needs_gate("sign_text", looks_like_siwe=looks_like_siwe)
            ws = db.wallets(self.identity_id, "sol")
            if not ws:
                raise Denied("identity has no Solana wallet")
            if gate:
                payload = {"_kind": "sign_text", "identity_id": self.identity_id,
                           "label": ws[0]["label"],
                           "message": text[:2000], "origin": origin,
                           "message_sha256": hashlib.sha256(data).hexdigest(),
                           "chain_family": "sol"}
                gates.require("sign_text",
                              f"Sign Solana message di {origin} ({len(text)} chars)\n{text[:280]}",
                              payload)
            kp = vault.load_sol(ws[0]["label"])
            sig = kp.sign_message(data)
            return {"result": {"signature": list(bytes(sig)), "publicKey": self._sol_addr()}}
        if method in ("signTransaction", "signAndSendTransaction"):
            cfg = chains.sol("solana-devnet" if "solana-devnet" in chains.all_chains() else
                             [c for c in chains.all_chains() if policy.chain(c).get("kind") == "solana"][0])
            raw = params[0]
            tx_bytes = base64.b64decode(raw) if isinstance(raw, str) else bytes(raw)
            ws = db.wallets(self.identity_id, "sol")
            if not ws:
                raise Denied("identity has no Solana wallet")
            kp = vault.load_sol(ws[0]["label"])
            from ..wallet import sol as solw

            sim = solw.rpc(cfg, "simulateTransaction", [base64.b64encode(tx_bytes).decode(),
                                                       {"sigVerify": False, "replaceRecentBlockhash": True}])
            if (sim or {}).get("value", {}).get("err"):
                raise Denied(f"solana simulation failed: {sim['value']['err']}")
            # K1: decode the instructions to measure what actually leaves our
            # wallet. The simulated pre-balance is the account balance, not
            # the amount sent, so it must never be used as the value.
            decoded = decode_transaction(tx_bytes, ws[0]["address"])
            if any(a.get("unlimited") for a in decoded["token_approvals"]):
                raise Denied("unlimited SPL token approval blocked -- refusing to sign")
            # Exact SOL out, plus the conservative ATA rent estimate (the ATA
            # instruction carries no amount; see aa/wallet/sol_tx.py).
            value_lamports = decoded["total_lamports_out"]
            policy.check_value(cfg["name"], ws[0]["label"], value_lamports, 5000, 1)
            first_to = (decoded["transfers"][0]["to"] if decoded["transfers"]
                        else decoded["token_transfers"][0]["destination"]
                        if decoded["token_transfers"] else "solana-tx")
            summary_bits = []
            if decoded["transfers"]:
                summary_bits.append("SOL: " + ", ".join(
                    f"{t['lamports'] / 1_000_000_000:g} ke {t['to']}"
                    for t in decoded["transfers"]))
            if decoded["token_transfers"]:
                summary_bits.append("token: " + ", ".join(
                    f"{t['amount']} {t['mint'] or 'unknown-mint'} ke {t['destination']}"
                    for t in decoded["token_transfers"]))
            if decoded["ata_creates"]:
                summary_bits.append(
                    f"buat {len(decoded['ata_creates'])} ATA "
                    f"(rent ~{decoded['ata_rent_estimate_lamports'] / 1_000_000_000:g} SOL)")
            if decoded["token_approvals"]:
                summary_bits.append("approve: " + ", ".join(
                    f"{a['amount']} {a['mint'] or 'unknown-mint'} ke {a['delegate']}"
                    for a in decoded["token_approvals"]))
            summary = (f"Solana tx di {origin} "
                       f"({'signAndSend' if method == 'signAndSendTransaction' else 'sign'}): "
                       + ("; ".join(summary_bits) or "tanpa transfer nilai"))
            payload = {"_kind": "tx", "chain": cfg["name"], "identity": self.identity_id,
                       "label": ws[0]["label"], "to": first_to, "value": str(value_lamports),
                       "sol_lamports": value_lamports,
                       "token_transfers": decoded["token_transfers"],
                       "token_approvals": decoded["token_approvals"],
                       "tx_hash": decoded["tx_hash"],
                       "data": base64.b64encode(tx_bytes).decode()[:4000]}
            if not gates.consume(payload):
                gates.require("tx", summary, payload)
            # Legacy transactions sign in place; versioned (v0) bytes are
            # rejected by Transaction.from_bytes, so re-sign by rebuilding
            # the VersionedTransaction with our keypair (solders 0.29).
            try:
                tx = Transaction.from_bytes(tx_bytes)
            except Exception:  # noqa: BLE001 -- v0 bytes fall through to versioned signing
                from solders.transaction import VersionedTransaction

                vtx = VersionedTransaction.from_bytes(tx_bytes)
                signed = base64.b64encode(bytes(VersionedTransaction(vtx.message, [kp]))).decode()
            else:
                tx.sign([kp], tx.message.recent_blockhash)
                signed = base64.b64encode(bytes(tx)).decode()
            if method == "signTransaction":
                return {"result": signed}
            sig = solw.rpc(cfg, "sendTransaction", [signed, {"encoding": "base64", "skipPreflight": False}])
            # Daily spend records the real SOL out + ATA rent estimate + the
            # estimated network fee (0 when we are not the fee payer).
            db.add_spend(cfg["name"], ws[0]["label"],
                         value_lamports + decoded["estimated_fee_lamports"])
            db.event("tx", f"sol {sig}", self.identity_id, data={"chain": cfg["name"]})
            return {"result": sig}
        raise Denied(f"unsupported solana method {method}")


_SNAKE = {
    "eth_gasPrice": "gas_price", "eth_blockNumber": "block_number", "eth_getBalance": "get_balance",
    "eth_getTransactionCount": "get_transaction_count", "eth_getTransactionReceipt": "get_transaction_receipt",
}


def _decode_hex(msg) -> str:
    if isinstance(msg, str) and msg.startswith("0x"):
        try:
            return bytes.fromhex(msg[2:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return msg
    return str(msg)
