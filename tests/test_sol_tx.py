"""Unit tests for aa/wallet/sol_tx.py (K1). No live RPC, no real keys:
all transactions are built locally with solders.
"""
import hashlib
import struct

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

from aa.jsonio import Denied
from aa.wallet.sol_tx import (
    ATA_RENT_LAMPORTS_ESTIMATE,
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    TOKEN_PROGRAM,
    decode_transaction,
)

LAMPORTS = 1_000_000_000


def _legacy_bytes(ixns, payer):
    msg = Message.new_with_blockhash(ixns, payer.pubkey(), Hash.default())
    tx = Transaction.new_unsigned(msg)
    tx.sign([payer], Hash.default())
    return bytes(tx)


def _token_ix(discriminator, amount, accounts, decimals=None):
    data = bytes([discriminator]) + struct.pack("<Q", amount)
    if decimals is not None:
        data += bytes([decimals])
    return Instruction(Pubkey.from_string(TOKEN_PROGRAM), data, accounts)


def _meta(pubkey, signer=False, writable=False):
    return AccountMeta(pubkey, signer, writable)


def test_sol_transfer_decodes_amount_and_recipient():
    payer, dest = Keypair(), Keypair()
    raw = _legacy_bytes(
        [transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=dest.pubkey(),
                                 lamports=1_234_567))],
        payer)
    d = decode_transaction(raw, str(payer.pubkey()))
    assert d["sol_lamports_out"] == 1_234_567
    assert d["transfers"] == [{"from": str(payer.pubkey()), "to": str(dest.pubkey()),
                               "lamports": 1_234_567}]
    assert d["token_transfers"] == [] and d["token_approvals"] == []
    assert d["fee_payer"] == str(payer.pubkey())
    assert d["tx_hash"] == hashlib.sha256(raw).hexdigest()
    assert d["instructions"][0]["kind"] == "system_transfer"
    assert d["estimated_fee_lamports"] == 5_000


def test_transfer_checked_decodes_mint_and_amount():
    payer, mint = Keypair(), Keypair()
    src, dst = Keypair().pubkey(), Keypair().pubkey()
    ix = _token_ix(12, 777_000, [_meta(src, writable=True), _meta(mint.pubkey()),
                                 _meta(dst, writable=True),
                                 _meta(payer.pubkey(), signer=True)], decimals=6)
    d = decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))
    assert d["sol_lamports_out"] == 0
    assert d["token_transfers"] == [{"mint": str(mint.pubkey()), "amount": 777_000,
                                     "source": str(src), "destination": str(dst),
                                     "authority": str(payer.pubkey()), "decimals": 6}]
    assert d["instructions"][0]["kind"] == "token_transfer_checked"


def test_plain_token_transfer_mint_unknown():
    payer = Keypair()
    src, dst = Keypair().pubkey(), Keypair().pubkey()
    ix = _token_ix(3, 42, [_meta(src, writable=True), _meta(dst, writable=True),
                           _meta(payer.pubkey(), signer=True)])
    d = decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))
    assert d["token_transfers"][0]["mint"] is None
    assert d["token_transfers"][0]["amount"] == 42
    assert d["token_transfers"][0]["destination"] == str(dst)
    assert d["instructions"][0]["kind"] == "token_transfer"


def test_unknown_program_denied():
    payer = Keypair()
    weird = Pubkey.from_string(str(Keypair().pubkey()))
    ix = Instruction(weird, b"\x00", [])
    with pytest.raises(Denied, match=str(weird)):
        decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))


def test_unknown_system_and_token_instructions_denied():
    payer = Keypair()
    sys_ix = Instruction(Pubkey.from_string("11111111111111111111111111111111"),
                         struct.pack("<I", 99), [])
    with pytest.raises(Denied, match="System instruction 99"):
        decode_transaction(_legacy_bytes([sys_ix], payer), str(payer.pubkey()))
    tok_ix = _token_ix(99, 1, [_meta(Keypair().pubkey())])
    with pytest.raises(Denied, match="SPL Token instruction 99"):
        decode_transaction(_legacy_bytes([tok_ix], payer), str(payer.pubkey()))


def test_unlimited_approve_flagged():
    payer = Keypair()
    src, delegate = Keypair().pubkey(), Keypair().pubkey()
    ix = _token_ix(4, 2 ** 64 - 1, [_meta(src, writable=True),
                                    _meta(delegate, writable=True),
                                    _meta(payer.pubkey(), signer=True)])
    d = decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))
    assert len(d["token_approvals"]) == 1
    assert d["token_approvals"][0]["unlimited"] is True
    assert d["token_approvals"][0]["delegate"] == str(delegate)
    # A finite approval is not flagged.
    ix2 = _token_ix(4, 100, [_meta(src, writable=True), _meta(delegate, writable=True),
                             _meta(payer.pubkey(), signer=True)])
    d2 = decode_transaction(_legacy_bytes([ix2], payer), str(payer.pubkey()))
    assert d2["token_approvals"][0]["unlimited"] is False


def test_transfer_from_someone_else_counts_zero():
    sender, dest, stranger = Keypair(), Keypair(), Keypair()
    raw = _legacy_bytes(
        [transfer(TransferParams(from_pubkey=sender.pubkey(), to_pubkey=dest.pubkey(),
                                 lamports=5_000_000))],
        sender)
    d = decode_transaction(raw, str(stranger.pubkey()))
    assert d["sol_lamports_out"] == 0
    assert d["transfers"][0]["lamports"] == 5_000_000  # still listed, not ours
    assert d["estimated_fee_lamports"] == 0  # we are not the fee payer


def test_ata_create_rent_estimated_not_in_sol_out():
    payer, owner, mint = Keypair(), Keypair(), Keypair()
    ata = Keypair().pubkey()
    ix = Instruction(Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM), b"",
                     [_meta(payer.pubkey(), signer=True, writable=True),
                      _meta(ata, writable=True), _meta(owner.pubkey()),
                      _meta(mint.pubkey()),
                      _meta(Pubkey.from_string("11111111111111111111111111111111")),
                      _meta(Pubkey.from_string(TOKEN_PROGRAM))])
    d = decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))
    assert d["sol_lamports_out"] == 0
    assert d["ata_rent_estimate_lamports"] == ATA_RENT_LAMPORTS_ESTIMATE
    assert d["total_lamports_out"] == ATA_RENT_LAMPORTS_ESTIMATE
    assert len(d["ata_creates"]) == 1
    assert d["instructions"][0]["lamports"] is None
    assert d["instructions"][0]["ata_create"] is True


def test_versioned_transaction_decodes():
    payer, dest = Keypair(), Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=dest.pubkey(),
                                 lamports=9_999))
    m0 = MessageV0.try_compile(payer.pubkey(), [ix], [], Hash.default())
    raw = bytes(VersionedTransaction(m0, [payer]))
    d = decode_transaction(raw, str(payer.pubkey()))
    assert d["sol_lamports_out"] == 9_999
    assert d["transfers"][0]["to"] == str(dest.pubkey())


def test_compute_budget_and_memo_allowed_no_value():
    payer = Keypair()
    from solders.compute_budget import set_compute_unit_limit

    memo = Instruction(Pubkey.from_string(MEMO_PROGRAM), b"hello", [])
    raw = _legacy_bytes([set_compute_unit_limit(200_000), memo], payer)
    d = decode_transaction(raw, str(payer.pubkey()))
    assert d["sol_lamports_out"] == 0
    assert [i["kind"] for i in d["instructions"]] == ["compute_budget", "memo"]


def test_close_account_records_destination():
    payer = Keypair()
    acct, dst = Keypair().pubkey(), Keypair().pubkey()
    ix = Instruction(Pubkey.from_string(TOKEN_PROGRAM), bytes([9]),
                     [_meta(acct, writable=True), _meta(dst, writable=True),
                      _meta(payer.pubkey(), signer=True)])
    d = decode_transaction(_legacy_bytes([ix], payer), str(payer.pubkey()))
    assert d["instructions"][0]["kind"] == "token_close_account"
    assert d["instructions"][0]["destination"] == str(dst)
    assert d["sol_lamports_out"] == 0
