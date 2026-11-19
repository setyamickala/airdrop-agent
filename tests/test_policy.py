
import pytest


def test_redacts_private_key_and_token():
    from aa.log import redact

    pk = "0x" + "a1" * 32
    out = redact(f"key {pk} token MFKabc.def.ghi")
    assert "a1a1a1a1" not in out
    assert "…" in out


def test_redacts_env_literals(monkeypatch):
    monkeypatch.setenv("SOME_API_KEY", "super-secret-value-123")
    from aa.log import redact

    assert "super-secret-value-123" not in redact("x super-secret-value-123 y")


def test_mask():
    from aa import config

    assert config.mask("abcdefghij", 3) == "*******hij"


def test_slug():
    from aa import config

    assert config.slug("My Project!!") == "my-project"


def test_policy_cap_units_and_mode(home):
    from aa import policy

    assert policy.cap_for("sepolia", "tx") == int(0.05 * 1e18)
    policy.set_mode("turbo")
    assert policy.cap_for("sepolia", "tx") == int(0.1 * 1e18)


def test_unlimited_approval():
    from aa import policy

    assert policy.unlimited_approval(2 ** 256 - 1)
    assert policy.unlimited_approval(2 ** 256 - 2)
    assert not policy.unlimited_approval(100)


def test_unlimited_approval_denied_in_approve(monkeypatch):
    """H3: approve() must DENY unlimited amounts, not default to max uint256."""
    from aa.jsonio import Denied
    from aa.wallet import send as sender

    calls = []
    monkeypatch.setattr(sender, "send", lambda *a, **k: calls.append((a, k)) or {"sent": True})
    with pytest.raises(Denied):
        sender.approve("sepolia", "id-1", "first", "0x" + "11" * 20, "0x" + "22" * 20, None)
    with pytest.raises(Denied):
        sender.approve("sepolia", "id-1", "first", "0x" + "11" * 20, "0x" + "22" * 20, 2 ** 256 - 1)
    with pytest.raises(Denied):
        sender.approve("sepolia", "id-1", "first", "0x" + "11" * 20, "0x" + "22" * 20, 2 ** 256 - 2)
    assert calls == [], "denied approvals must never reach send()"
    # A finite amount still goes through.
    assert sender.approve("sepolia", "id-1", "first", "0x" + "11" * 20, "0x" + "22" * 20, 100) == {"sent": True}
    assert len(calls) == 1


def test_unlimited_approval_denied_in_send(home):
    """H3: send() must DENY an unlimited-approval calldata before any RPC."""
    from eth_abi import encode as abi_encode

    from aa.jsonio import Denied
    from aa.wallet import send as sender

    token, spender = "0x" + "11" * 20, "0x" + "22" * 20
    unlimited = "0x095ea7b3" + abi_encode(["address", "uint256"], [spender, 2 ** 256 - 1]).hex()
    with pytest.raises(Denied):
        sender.send("sepolia", "id-1", "first", token, calldata=unlimited)
    finite = "0x095ea7b3" + abi_encode(["address", "uint256"], [spender, 100]).hex()
    # Finite is NOT denied by the unlimited check — it proceeds and fails
    # later (no wallet/RPC in this test), proving the check is the gate.
    with pytest.raises(Exception, match="(?i)identity|wallet|vault|connection|rpc|estimate|denied"):
        sender.send("sepolia", "id-1", "first", token, calldata=finite)


def test_value_cap_denied(home):
    from aa import policy
    from aa.jsonio import Denied

    with pytest.raises(Denied):
        policy.check_value("sepolia", "w1", int(1 * 1e18))


def test_needs_gate_matrix(home):
    from aa import policy

    policy.set_mode("turbo")
    ok, _ = policy.needs_gate("tx", mainnet=False, contract_ok=True)
    assert not ok
    ok, _ = policy.needs_gate("tx", mainnet=True, contract_ok=True)
    assert ok
    policy.set_mode("safe")
    ok, _ = policy.needs_gate("connect", safe_origin=True)
    assert ok


def test_domain_allowlist(home):
    from aa import policy

    assert policy.domain_ok("app.galxe.com")
    assert not policy.domain_ok("evil.xyz")
    policy.allow_domain("evil.xyz")
    assert policy.domain_ok("evil.xyz")
