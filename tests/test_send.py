"""K6: unlimited approvals are hard-blocked in every mode — in send() after
decode() and before simulation, in approve() (amount is required), and in
the CLI (the --unlimited flag is denied, not silently honoured)."""
import pytest

from aa.jsonio import Denied

TOKEN = "0x0000000000000000000000000000000000000001"
SPENDER = "0x0000000000000000000000000000000000000002"


def test_approve_amount_none_raises():
    from aa.wallet import send as sender

    with pytest.raises(Denied, match="approve amount is required"):
        sender.approve("sepolia", "id", "label", TOKEN, SPENDER, amount=None)


def test_check_unlimited_blocks_approve():
    from aa.wallet.send import _check_unlimited

    with pytest.raises(Denied, match="unlimited approval blocked"):
        _check_unlimited({"kind": "approve", "amount": str(2 ** 256 - 1)})
    with pytest.raises(Denied, match="unlimited approval blocked"):
        _check_unlimited({"kind": "increaseAllowance", "amount": str(2 ** 256 - 1)})


def test_check_unlimited_blocks_permit2_uint160_max():
    from aa.wallet.send import _check_unlimited

    # Permit2 amounts are uint160: 2**160-1 is unlimited there, even though it
    # is far below the uint256 max.
    with pytest.raises(Denied, match="unlimited approval blocked"):
        _check_unlimited({"kind": "permit2Approve", "amount": str(2 ** 160 - 1)})


def test_check_unlimited_blocks_set_approval_for_all():
    from aa.wallet.send import _check_unlimited

    with pytest.raises(Denied, match="unlimited approval blocked"):
        _check_unlimited({"kind": "setApprovalForAll", "operator": SPENDER, "approved": True})


def test_check_unlimited_allows_finite_and_revoke():
    from aa.wallet.send import _check_unlimited

    assert _check_unlimited({"kind": "approve", "amount": "100"}) is None
    assert _check_unlimited({"kind": "permit2Approve", "amount": "100"}) is None
    assert _check_unlimited({"kind": "setApprovalForAll", "operator": SPENDER,
                             "approved": False}) is None
    assert _check_unlimited({"kind": "native"}) is None


def test_unlimited_approval_bits160():
    from aa import policy

    assert policy.unlimited_approval(2 ** 160 - 1, bits=160)
    assert not policy.unlimited_approval(2 ** 160 - 2, bits=160)
    # Same value is finite under the uint256 default.
    assert not policy.unlimited_approval(2 ** 160 - 1)
    assert policy.unlimited_approval(2 ** 256 - 1)
    assert not policy.unlimited_approval(100)
