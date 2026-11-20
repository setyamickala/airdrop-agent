"""Gate moved into sol.send() (round 4, priority 3a): one gate, consumed once.

RPC + keypair are mocked; no network, no real signing broadcast.
"""
import re

import pytest
from solders.keypair import Keypair

from aa.jsonio import Gate

BLOCKHASH = "11111111111111111111111111111111"


@pytest.fixture(autouse=True)
def capture_code(monkeypatch):
    from aa import gates, notify

    seen = []
    orig_send = notify.send

    def _capture(text, **kw):
        m = re.search(r"aa gate approve \d+ ([A-Z0-9]{6})", text)
        if m:
            seen.append(m.group(1))
        return orig_send(text, **kw)

    monkeypatch.setattr(gates.notify, "send", _capture)
    return seen


@pytest.fixture
def fake_sol(monkeypatch):
    from aa import vault
    from aa.wallet import sol

    kp = Keypair()
    calls = {"send": 0}
    monkeypatch.setattr(vault, "load_sol", lambda key: kp)

    def _rpc(cfg, method, params):
        if method == "getLatestBlockhash":
            return {"value": {"blockhash": BLOCKHASH}}
        if method == "simulateTransaction":
            return {"value": {"err": None, "unitsConsumed": 1000}}
        if method == "sendTransaction":
            calls["send"] += 1
            return "5" * 88  # fake signature
        if method == "getSignatureStatuses":
            return {"value": [{"confirmationStatus": "confirmed", "slot": 1}]}
        raise AssertionError(f"unexpected rpc {method}")

    monkeypatch.setattr(sol, "rpc", _rpc)
    return kp, calls


def test_sol_send_gates_once_inside_send(home, ident, capture_code, fake_sol):
    from aa import chains, db, gates
    from aa.wallet import sol

    kp, calls = fake_sol
    cfg = chains.sol("solana")  # mainnet -> needs_gate("tx") is True in balanced
    to = str(Keypair().pubkey())
    with pytest.raises(Gate):
        sol.send(cfg, "label-1", to, 1_000_000, broadcast=True, identity_id=ident)
    assert len(gates.list_gates("pending")) == 1  # exactly one gate created
    gid = gates.list_gates("pending")[0]["id"]
    gates.approve(gid, capture_code[-1])
    out = sol.send(cfg, "label-1", to, 1_000_000, broadcast=True, identity_id=ident)
    assert out["confirmed"] is True
    assert calls["send"] == 1  # broadcast exactly once
    # The single-use approval is spent: a third send needs a fresh gate.
    with pytest.raises(Gate):
        sol.send(cfg, "label-1", to, 1_000_000, broadcast=True, identity_id=ident)
    assert len(gates.list_gates("pending")) == 1
