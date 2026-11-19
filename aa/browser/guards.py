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

    # ---------- EVM ----------
    async def evm(self, source: dict, method: str, params_json: str) -> str:
        params = json.loads(params_json or "[]")
        origin = self._origin(source)
        try:
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

    def _sol_chain(self) -> dict:
        """Respect the session chain when it is Solana; else first configured Solana chain."""
        try:
            if policy.chain(self.chain).get("kind") == "solana":
                return chains.sol(self.chain)
        except SystemExit:
            pass
        for name in chains.all_chains():
            if policy.chain(name).get("kind") == "solana":
                return chains.sol(name)
        raise Denied("no solana chain configured in policy.yaml")

    def _sol_sync(self, origin: str, method: str, params: list) -> dict:
        from solders.transaction import Transaction, VersionedTransaction

        from ..wallet import sol as solw

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
            ws = db.wallets(self.identity_id, "sol")
            if not ws:
                raise Denied("identity has no Solana wallet")
            gate, _reasons = policy.needs_gate("sign_text")
            if gate or not policy.domain_ok(origin):
                gates.require("sign_text", f"Solana signMessage di {origin} ({len(data)} bytes)",
                              {"_kind": "sign_text", "identity_id": self.identity_id,
                               "label": ws[0]["label"], "origin": origin,
                               "message": base64.b64encode(data).decode()})
            kp = vault.load_sol(ws[0]["label"])
            sig = kp.sign_message(data)
            return {"result": {"signature": list(bytes(sig)), "publicKey": self._sol_addr()}}
        if method in ("signTransaction", "signAndSendTransaction"):
            cfg = self._sol_chain()
            raw = params[0]
            tx_bytes = base64.b64decode(raw) if isinstance(raw, str) else bytes(raw)
            ws = db.wallets(self.identity_id, "sol")
            if not ws:
                raise Denied("identity has no Solana wallet")
            label = ws[0]["label"]
            kp = vault.load_sol(label)
            versioned = False
            try:
                tx = Transaction.from_bytes(tx_bytes)
                msg = tx.message
            except Exception:  # noqa: BLE001 — not legacy; try versioned (v0)
                try:
                    vtx = VersionedTransaction.from_bytes(tx_bytes)
                    msg = vtx.message
                    versioned = True
                except Exception as e:  # noqa: BLE001
                    raise Denied(f"cannot parse solana transaction: {str(e)[:120]}")
            n_req = int(msg.header.num_required_signatures)
            keys = [str(k) for k in msg.account_keys]
            if n_req != 1 or not keys or keys[0] != str(kp.pubkey()):
                raise Denied("transaction must require exactly this wallet as the sole signer")
            pre = int((solw.rpc(cfg, "getBalance", [keys[0], {"commitment": "confirmed"}]) or {}).get("value", 0))
            sim = solw.rpc(cfg, "simulateTransaction", [base64.b64encode(tx_bytes).decode(),
                                                        {"sigVerify": False, "replaceRecentBlockhash": True}])
            sval = (sim or {}).get("value") or {}
            if sval.get("err"):
                raise Denied(f"solana simulation failed: {sval['err']}")
            accounts = sval.get("accounts") or []
            post = int(accounts[0].get("lamports", pre)) if accounts else pre
            # Cap the native OUTFLOW (payer balance delta incl. fees), never the whole balance.
            value_est = max(pre - post, 5000)
            policy.check_value(cfg["name"], label, value_est, 5000, 1)
            payload = {"_kind": "tx", "chain": cfg["name"], "identity": self.identity_id,
                       "label": label, "to": "solana-tx", "value": str(value_est),
                       "data": base64.b64encode(tx_bytes).decode(),
                       "data_sha256": hashlib.sha256(tx_bytes).hexdigest()}
            mainnet = not policy.chain(cfg["name"]).get("testnet", False)
            want_gate, reasons = policy.needs_gate("tx", mainnet=mainnet, contract_ok=True)
            if want_gate:
                if not gates.consume(payload):
                    gates.require("tx", f"Solana {method} di {cfg['name']} (~{value_est} lamports)\n"
                                        f"alasan: {'; '.join(reasons)}", payload)
            elif not gates.consume(payload):
                db.event("tx", f"auto sol {method} on {cfg['name']}", self.identity_id)
            if versioned:
                signed_tx = VersionedTransaction(msg, [kp])
            else:
                tx.sign([kp], msg.recent_blockhash)
                signed_tx = tx
            signed = base64.b64encode(bytes(signed_tx)).decode()
            if method == "signTransaction":
                return {"result": signed}
            sig = solw.rpc(cfg, "sendTransaction", [signed, {"encoding": "base64", "skipPreflight": False}])
            db.add_spend(cfg["name"], label, value_est)
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
