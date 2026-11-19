"""Solana wallet bridge regression tests (fake RPC, real vault/solders/policy)."""
import base64
import types

import pytest
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

from aa import db, gates, policy, vault
from aa.browser.guards import WalletBridge
from aa.jsonio import Gate
from aa.wallet import sol as solw

MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


@pytest.fixture
def sol_wallet(ident):
    return db.wallets(ident, "sol")[0]


@pytest.fixture
def bridge(ident):
    return WalletBridge(types.SimpleNamespace(identity_id=ident, chain="solana-devnet"))


@pytest.fixture
def fake_rpc(monkeypatch):
    state = {"pre": 10 ** 9, "post": 10 ** 9 - 1_000_000, "calls": []}

    def rpc(cfg, method, params):
        state["calls"].append((cfg["name"], method))
        if method == "getBalance":
            return {"value": state["pre"]}
        if method == "simulateTransaction":
            return {"value": {"err": None, "accounts": [{"lamports": state["post"]}]}}
        if method == "sendTransaction":
            return "sig-test"
        raise AssertionError(f"unexpected rpc {method}")

    monkeypatch.setattr(solw, "rpc", rpc)
    return state


def _transfer_tx(kp, lamports=1_000_000):
    ix = transfer(TransferParams(from_pubkey=kp.pubkey(), to_pubkey=Keypair().pubkey(), lamports=lamports))
    msg = Message.new_with_blockhash([ix], kp.pubkey(), Hash.default())
    return Transaction.new_unsigned(msg)


def test_mainnet_session_chain_gated(ident, sol_wallet, bridge, fake_rpc, monkeypatch):
    bridge.chain = "solana"
    captured = {}

    def fake_require(kind, summary, payload):
        captured.update(payload)
        raise Gate("capture")

    monkeypatch.setattr(gates, "require", fake_require)
    kp = vault.load_sol(sol_wallet["label"])
    b64 = base64.b64encode(bytes(_transfer_tx(kp))).decode()
    with pytest.raises(Gate):
        bridge._sol_sync("app.galxe.com", "signTransaction", [b64])
    assert captured.get("chain") == "solana", "session chain must not be overridden by devnet"
    assert ("solana", "simulateTransaction") in fake_rpc["calls"]


def test_devnet_auto_and_cap_uses_delta(ident, sol_wallet, bridge, fake_rpc, monkeypatch):
    fake_rpc["pre"] = 100 * 10 ** 9                 # 100 SOL balance — far above the per-tx cap
    fake_rpc["post"] = fake_rpc["pre"] - 1_000_000  # 0.001 SOL outflow — inside the cap
    seen = {}
    orig = policy.check_value

    def spy(chain, wallet, value, gas_price=0, gas=0):
        seen["value"] = value
        return orig(chain, wallet, value, gas_price, gas)

    monkeypatch.setattr(policy, "check_value", spy)
    kp = vault.load_sol(sol_wallet["label"])
    b64 = base64.b64encode(bytes(_transfer_tx(kp))).decode()
    out = bridge._sol_sync("app.galxe.com", "signTransaction", [b64])
    assert seen["value"] == 1_000_000, "cap must check the tx delta, not the whole balance"
    signed = Transaction.from_bytes(base64.b64decode(out["result"]))
    assert signed.signatures[0] != Signature.default()


def test_signmessage_unknown_origin_gates(ident, sol_wallet, bridge):
    with pytest.raises(Gate):
        bridge._sol_sync("unknown.example", "signMessage", [list(b"hello")])


def test_signmessage_allowlisted_auto(ident, sol_wallet, bridge):
    out = bridge._sol_sync("app.galxe.com", "signMessage", [list(b"hello")])
    assert out["result"]["signature"]


def test_gate_payload_distinguishes_large_txs(ident, sol_wallet, bridge, fake_rpc, monkeypatch):
    bridge.chain = "solana"
    payloads = []

    def fake_require(kind, summary, payload):
        payloads.append(payload)
        raise Gate("capture")

    monkeypatch.setattr(gates, "require", fake_require)
    kp = vault.load_sol(sol_wallet["label"])

    def big_tx(tag):
        memo = Instruction(MEMO, b"A" * 3100 + tag + b"Z" * 100, [])
        msg = Message.new_with_blockhash([memo], kp.pubkey(), Hash.default())
        return base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()

    for tag in (b"X", b"Y"):
        with pytest.raises(Gate):
            bridge._sol_sync("app.galxe.com", "signTransaction", [big_tx(tag)])
    assert len(payloads) == 2
    assert len(payloads[0]["data"]) > 4000
    assert payloads[0]["data"] != payloads[1]["data"], \
        "gate payload must cover the WHOLE tx — truncation lets one approval cover another tx"


def test_versioned_transaction_supported(ident, sol_wallet, bridge, fake_rpc):
    kp = vault.load_sol(sol_wallet["label"])
    ix = transfer(TransferParams(from_pubkey=kp.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1000))
    msg = MessageV0.try_compile(kp.pubkey(), [ix], [], Hash.default())
    vtx = VersionedTransaction.populate(msg, [Signature.default()])
    out = bridge._sol_sync("app.galxe.com", "signTransaction", [base64.b64encode(bytes(vtx)).decode()])
    signed = VersionedTransaction.from_bytes(base64.b64decode(out["result"]))
    assert signed.signatures[0] != Signature.default()
