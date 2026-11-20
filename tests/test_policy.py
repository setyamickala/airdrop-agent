
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


def test_redacts_mnemonic_and_solana_key():
    from aa.log import redact

    words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    out = redact(f"seed words {words} end")
    assert "abandon" not in out
    assert "mnemonic…redacted" in out
    sol_key = "5" * 88
    out2 = redact(f"sol key {sol_key} end")
    assert sol_key not in out2
    assert "sol-key…" in out2
    # A short ordinary log line is untouched, and a public Solana address
    # (32-44 char base58) is not redacted.
    assert redact("quest done for galxe") == "quest done for galxe"
    assert "DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK" in redact(
        "sol account DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK funded")


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
    assert not policy.unlimited_approval(100)


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
