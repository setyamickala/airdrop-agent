"""Pure decoding of Solana transactions for the browser guard (K1).

No vault, no RPC, no keys: given raw transaction bytes and our wallet
address, work out exactly what value leaves our wallet. Anything this
module cannot understand is denied -- a signature must never be issued
for an instruction whose effect is unknown.

Verified against solders 0.29.0 in the test venv:
- ``Transaction.from_bytes`` parses legacy transactions only; it raises
  ``ValueError`` on versioned (v0) bytes.
- ``VersionedTransaction.from_bytes`` parses both legacy and v0 bytes
  (legacy bytes come back as a ``Message``/legacy message).
- A compiled instruction exposes ``program_id_index`` (int),
  ``accounts`` (bytes of account indices) and ``data`` (bytes).
- ``message.account_keys`` is the list of static account pubkeys;
  the fee payer is ``account_keys[0]`` (there is no ``fee_payer``
  attribute on the message in this version).
- A versioned transaction is signed by constructing a new
  ``VersionedTransaction(message, [keypair])``; there is no ``.sign``.

ATA rent decision (documented choice): an Associated Token Account
create instruction carries no lamport amount in its data -- the funder
pays the rent-exempt minimum for a 165-byte token account, currently
2,039,280 lamports. ``decode_transaction`` therefore records the ATA
create with ``lamports: None`` and ``ata_create: True`` and does NOT
fold the rent into ``sol_lamports_out`` (whose amount is exact). It
exposes ``ata_rent_estimate_lamports`` (2,039,280 per ATA create funded
by our wallet) and ``total_lamports_out`` (exact SOL out + that
estimate) so the caller can apply caps/gates conservatively on the
total. If the network rent-exempt minimum ever changes, the estimate
(and only the estimate) needs updating.

Fees: the network fee (5,000 lamports per signature by default) is NOT
part of ``sol_lamports_out``. ``estimated_fee_lamports`` reports it
separately (0 when our wallet is not the fee payer); callers that
record daily spend should add it, callers that cap the transfer value
should not.
"""
from __future__ import annotations

import hashlib
import struct

from ..jsonio import Denied

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

# Rent-exempt minimum for a 165-byte SPL token account (i.e. an ATA).
# See module docstring: this is an estimate, charged by the network when
# an ATA is created; the instruction data itself carries no amount.
ATA_RENT_LAMPORTS_ESTIMATE = 2_039_280
# Default network fee per signature (lamports).
FEE_PER_SIGNATURE = 5_000
# Unlimited SPL approval: amount == u64 max.
UNLIMITED_AMOUNT = 2 ** 64 - 1


def _u32(data: bytes, off: int, what: str) -> int:
    if len(data) < off + 4:
        raise Denied(f"truncated Solana instruction data for {what}")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int, what: str) -> int:
    if len(data) < off + 8:
        raise Denied(f"truncated Solana instruction data for {what}")
    return struct.unpack_from("<Q", data, off)[0]


def _u8(data: bytes, off: int, what: str) -> int:
    if len(data) < off + 1:
        raise Denied(f"truncated Solana instruction data for {what}")
    return data[off]


def _acct(keys: list[str], idxs: list[int], pos: int, what: str) -> str:
    if pos >= len(idxs):
        raise Denied(f"Solana instruction {what} is missing account {pos}")
    idx = idxs[pos]
    if idx >= len(keys):
        raise Denied(f"Solana instruction {what} references unknown account index {idx}")
    return keys[idx]


def _parse_message(tx_bytes: bytes):
    """Return (message, num_signatures) for legacy or versioned bytes."""
    if not tx_bytes:
        raise Denied("empty Solana transaction")
    try:
        from solders.transaction import Transaction

        tx = Transaction.from_bytes(tx_bytes)
        return tx.message, len(tx.signatures)
    except Exception:  # noqa: BLE001 -- legacy parse fails on v0 bytes; retry versioned
        pass
    try:
        from solders.transaction import VersionedTransaction

        vtx = VersionedTransaction.from_bytes(tx_bytes)
        return vtx.message, len(vtx.signatures)
    except Exception as e:  # noqa: BLE001
        raise Denied(f"cannot parse Solana transaction bytes: {e}") from e


def _decode_system(data: bytes, keys: list[str], idxs: list[int], out: dict) -> dict:
    disc = _u32(data, 0, "System instruction")
    if disc == 2:  # Transfer
        lamports = _u64(data, 4, "System Transfer")
        src = _acct(keys, idxs, 0, "System Transfer")
        dst = _acct(keys, idxs, 1, "System Transfer")
        return {"program": SYSTEM_PROGRAM, "kind": "system_transfer",
                "from": src, "to": dst, "lamports": lamports}
    if disc == 0:  # CreateAccount
        lamports = _u64(data, 4, "System CreateAccount")
        payer = _acct(keys, idxs, 0, "System CreateAccount")
        new = _acct(keys, idxs, 1, "System CreateAccount")
        return {"program": SYSTEM_PROGRAM, "kind": "system_create_account",
                "from": payer, "to": new, "lamports": lamports}
    if disc == 11:  # TransferWithSeed: u32, u64 lamports, u32 seed_len, seed, owner(32)
        lamports = _u64(data, 4, "System TransferWithSeed")
        seed_len = _u32(data, 12, "System TransferWithSeed")
        if len(data) < 16 + seed_len + 32:
            raise Denied("truncated System TransferWithSeed instruction")
        src = _acct(keys, idxs, 0, "System TransferWithSeed")
        dst = _acct(keys, idxs, 2, "System TransferWithSeed")
        return {"program": SYSTEM_PROGRAM, "kind": "system_transfer_with_seed",
                "from": src, "to": dst, "lamports": lamports}
    if disc == 3:  # CreateAccountWithSeed: u32, base(32), u32 seed_len, seed,
        # u64 lamports, u64 space, owner(32)
        seed_len = _u32(data, 36, "System CreateAccountWithSeed")
        lamports_off = 40 + seed_len
        lamports = _u64(data, lamports_off, "System CreateAccountWithSeed")
        if len(data) < lamports_off + 8 + 8 + 32:
            raise Denied("truncated System CreateAccountWithSeed instruction")
        payer = _acct(keys, idxs, 0, "System CreateAccountWithSeed")
        new = _acct(keys, idxs, 1, "System CreateAccountWithSeed")
        return {"program": SYSTEM_PROGRAM, "kind": "system_create_account_with_seed",
                "from": payer, "to": new, "lamports": lamports}
    # Allocate / Assign / nonce / lookup-table instructions move no value
    # and change no ownership we track, but guessing at them is worse than
    # refusing: deny anything not decoded above.
    raise Denied(f"unknown System instruction {disc} -- refusing to sign")


def _decode_token(data: bytes, keys: list[str], idxs: list[int], out: dict) -> dict:
    disc = _u8(data, 0, "SPL Token instruction")
    if disc == 3:  # Transfer: u8, u64 amount; [source, destination, authority]
        amount = _u64(data, 1, "SPL Token Transfer")
        src = _acct(keys, idxs, 0, "SPL Token Transfer")
        dst = _acct(keys, idxs, 1, "SPL Token Transfer")
        auth = _acct(keys, idxs, 2, "SPL Token Transfer")
        out["token_transfers"].append({"mint": None, "amount": amount,
                                       "source": src, "destination": dst,
                                       "authority": auth, "decimals": None})
        return {"program": TOKEN_PROGRAM, "kind": "token_transfer",
                "mint": None, "amount": amount, "source": src,
                "destination": dst, "authority": auth}
    if disc == 12:  # TransferChecked: u8, u64 amount, u8 decimals;
        # [source, mint, destination, authority]
        amount = _u64(data, 1, "SPL Token TransferChecked")
        decimals = _u8(data, 9, "SPL Token TransferChecked")
        src = _acct(keys, idxs, 0, "SPL Token TransferChecked")
        mint = _acct(keys, idxs, 1, "SPL Token TransferChecked")
        dst = _acct(keys, idxs, 2, "SPL Token TransferChecked")
        auth = _acct(keys, idxs, 3, "SPL Token TransferChecked")
        out["token_transfers"].append({"mint": mint, "amount": amount,
                                       "source": src, "destination": dst,
                                       "authority": auth, "decimals": decimals})
        return {"program": TOKEN_PROGRAM, "kind": "token_transfer_checked",
                "mint": mint, "amount": amount, "source": src,
                "destination": dst, "authority": auth, "decimals": decimals}
    if disc in (4, 13):  # Approve / ApproveChecked
        checked = disc == 13
        amount = _u64(data, 1, "SPL Token Approve")
        decimals = _u8(data, 9, "SPL Token ApproveChecked") if checked else None
        if checked:
            src = _acct(keys, idxs, 0, "SPL Token ApproveChecked")
            mint = _acct(keys, idxs, 1, "SPL Token ApproveChecked")
            delegate = _acct(keys, idxs, 2, "SPL Token ApproveChecked")
            owner = _acct(keys, idxs, 3, "SPL Token ApproveChecked")
        else:
            src = _acct(keys, idxs, 0, "SPL Token Approve")
            mint = None
            delegate = _acct(keys, idxs, 1, "SPL Token Approve")
            owner = _acct(keys, idxs, 2, "SPL Token Approve")
        unlimited = amount >= UNLIMITED_AMOUNT
        out["token_approvals"].append({"mint": mint, "amount": amount,
                                       "source": src, "delegate": delegate,
                                       "owner": owner, "unlimited": unlimited,
                                       "decimals": decimals})
        return {"program": TOKEN_PROGRAM,
                "kind": "token_approve_checked" if checked else "token_approve",
                "mint": mint, "amount": amount, "source": src,
                "delegate": delegate, "owner": owner,
                "unlimited": unlimited, "decimals": decimals}
    if disc == 9:  # CloseAccount: [account, destination, authority]
        acct = _acct(keys, idxs, 0, "SPL Token CloseAccount")
        dst = _acct(keys, idxs, 1, "SPL Token CloseAccount")
        auth = _acct(keys, idxs, 2, "SPL Token CloseAccount")
        return {"program": TOKEN_PROGRAM, "kind": "token_close_account",
                "account": acct, "destination": dst, "authority": auth}
    # MintTo / Burn / SetAuthority / Freeze / Thaw / SyncNative / etc. all
    # change token supply or control: deny rather than guess.
    raise Denied(f"unknown SPL Token instruction {disc} -- refusing to sign")


def _decode_ata(data: bytes, keys: list[str], idxs: list[int], out: dict, our: str) -> dict:
    # Create: empty data. CreateIdempotent: single 0x01 byte. Both make the
    # funder pay the rent-exempt minimum for the new token account.
    if len(data) not in (0, 1) or (data and data[0] != 1):
        raise Denied("unknown Associated Token instruction -- refusing to sign")
    funder = _acct(keys, idxs, 0, "Associated Token create")
    ata = _acct(keys, idxs, 1, "Associated Token create")
    owner = _acct(keys, idxs, 2, "Associated Token create")
    mint = _acct(keys, idxs, 3, "Associated Token create")
    entry = {"funder": funder, "ata": ata, "owner": owner, "mint": mint}
    out["ata_creates"].append(entry)
    if funder == our:
        out["ata_rent_estimate_lamports"] += ATA_RENT_LAMPORTS_ESTIMATE
    return {"program": ASSOCIATED_TOKEN_PROGRAM, "kind": "ata_create",
            "funder": funder, "ata": ata, "owner": owner, "mint": mint,
            "lamports": None, "ata_create": True}


def decode_transaction(tx_bytes: bytes, our_address: str) -> dict:
    """Decode a Solana transaction and measure what leaves our wallet.

    ``tx_bytes`` may be a legacy ``Transaction`` or a versioned
    ``VersionedTransaction``. Returns a dict with at least ``tx_hash``,
    ``fee_payer``, ``sol_lamports_out``, ``transfers``,
    ``token_transfers``, ``token_approvals``, ``instructions``, plus
    ``ata_creates``, ``ata_rent_estimate_lamports``,
    ``total_lamports_out`` and ``estimated_fee_lamports`` (see the
    module docstring for the ATA-rent and fee decisions).

    Raises :class:`aa.jsonio.Denied` for any program or instruction this
    module does not understand, for malformed data, and for versioned
    transactions using address lookup tables (their accounts cannot be
    resolved from the bytes alone).
    """
    our = (our_address or "").strip()
    message, num_signatures = _parse_message(tx_bytes)
    keys = [str(k) for k in message.account_keys]
    if not keys:
        raise Denied("Solana transaction has no accounts")
    lookups = getattr(message, "address_table_lookups", None)
    if lookups:
        raise Denied("versioned Solana transaction uses address lookup tables, "
                     "which cannot be resolved from the transaction bytes alone "
                     "-- refusing to sign")
    fee_payer = keys[0]
    out: dict = {
        "tx_hash": hashlib.sha256(tx_bytes).hexdigest(),
        "fee_payer": fee_payer,
        "sol_lamports_out": 0,
        "transfers": [],
        "token_transfers": [],
        "token_approvals": [],
        "ata_creates": [],
        "ata_rent_estimate_lamports": 0,
        "estimated_fee_lamports": FEE_PER_SIGNATURE * num_signatures if fee_payer == our else 0,
        "instructions": [],
    }
    for ins in message.instructions:
        if ins.program_id_index >= len(keys):
            raise Denied(f"Solana instruction references unknown program index "
                         f"{ins.program_id_index} -- refusing to sign")
        program = keys[ins.program_id_index]
        data = bytes(ins.data)
        idxs = list(bytes(ins.accounts))
        if program == SYSTEM_PROGRAM:
            entry = _decode_system(data, keys, idxs, out)
        elif program == TOKEN_PROGRAM:
            entry = _decode_token(data, keys, idxs, out)
        elif program == ASSOCIATED_TOKEN_PROGRAM:
            entry = _decode_ata(data, keys, idxs, out, our)
        elif program == COMPUTE_BUDGET_PROGRAM:
            if not data:
                raise Denied("empty Compute Budget instruction -- refusing to sign")
            entry = {"program": program, "kind": "compute_budget",
                     "discriminator": data[0]}
        elif program == MEMO_PROGRAM:
            entry = {"program": program, "kind": "memo"}
        else:
            raise Denied(f"unknown Solana program {program} -- refusing to sign")
        out["instructions"].append(entry)
        # Only lamports whose source is our wallet count as SOL out.
        # Token amounts are not SOL; ATA rent is estimated separately.
        if entry.get("kind") in ("system_transfer", "system_transfer_with_seed",
                                 "system_create_account",
                                 "system_create_account_with_seed"):
            if entry.get("from") == our:
                lamports = int(entry["lamports"])
                out["sol_lamports_out"] += lamports
                out["transfers"].append({"from": entry["from"], "to": entry["to"],
                                         "lamports": lamports})
            elif entry.get("kind") in ("system_transfer", "system_transfer_with_seed"):
                out["transfers"].append({"from": entry["from"], "to": entry["to"],
                                         "lamports": int(entry["lamports"])})
    out["total_lamports_out"] = (out["sol_lamports_out"]
                                 + out["ata_rent_estimate_lamports"])
    return out
