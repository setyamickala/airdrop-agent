"""Regression tests for the guarded EVM send pipeline (fake RPC, real vault/policy)."""
import pytest
from eth_abi import encode as abi_encode
from web3 import Web3

from aa import chains, db, policy
from aa.jsonio import Denied, Gate
from aa.wallet import send as sender


@pytest.fixture
def wallet(ident):
    return db.wallets(ident, "evm")[0]["label"]


@pytest.fixture
def fake_w3(home, ident, monkeypatch):
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:9"))  # never actually called
    calls = {}
    monkeypatch.setattr(w3.eth, "estimate_gas", lambda tx: 21000)
    monkeypatch.setattr(w3.eth, "get_block", lambda tag: {"baseFeePerGas": 10 ** 9})
    monkeypatch.setattr(type(w3.eth), "max_priority_fee", property(lambda self: 10 ** 9))

    def gtc(owner, block_identifier="latest"):
        calls["nonce_tag"] = block_identifier
        return 0

    monkeypatch.setattr(w3.eth, "get_transaction_count", gtc)
    monkeypatch.setattr(chains, "w3", lambda name: (w3, policy.chain(name)))
    return calls


def test_nonce_uses_pending(home, ident, wallet, fake_w3):
    out = sender.send("sepolia", ident, wallet, "0x" + "11" * 20, value_wei=10 ** 15)
    assert out["simulated"]
    assert fake_w3["nonce_tag"] == "pending", "nonce must include in-flight txs"


def test_unlimited_approve_gates(home, ident, wallet, fake_w3, monkeypatch):
    monkeypatch.setattr(policy, "allowlisted_contract", lambda c, a: True)
    data = "0x095ea7b3" + abi_encode(["address", "uint256"], ["0x" + "22" * 20, 2 ** 256 - 1]).hex()
    with pytest.raises(Gate):
        sender.send("sepolia", ident, wallet, "0x" + "33" * 20, calldata=data)


def test_unlimited_approve_gates_in_turbo(home, ident, wallet, fake_w3, monkeypatch):
    policy.set_mode("turbo")
    monkeypatch.setattr(policy, "allowlisted_contract", lambda c, a: True)
    data = "0x095ea7b3" + abi_encode(["address", "uint256"], ["0x" + "22" * 20, 2 ** 256 - 1]).hex()
    with pytest.raises(Gate):
        sender.send("sepolia", ident, wallet, "0x" + "33" * 20, calldata=data)
    policy.set_mode("balanced")


def test_bounded_approve_auto_on_testnet(home, ident, wallet, fake_w3, monkeypatch):
    monkeypatch.setattr(policy, "allowlisted_contract", lambda c, a: True)
    data = "0x095ea7b3" + abi_encode(["address", "uint256"], ["0x" + "22" * 20, 10 ** 18]).hex()
    out = sender.send("sepolia", ident, wallet, "0x" + "33" * 20, calldata=data)
    assert out["simulated"]


def test_invalid_recipient_denied(home, ident, wallet, fake_w3):
    with pytest.raises(Denied):
        sender.send("sepolia", ident, wallet, "0xdeadbeef", value_wei=1)
