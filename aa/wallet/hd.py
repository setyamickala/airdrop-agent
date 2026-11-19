"""HD wallet engine — one mnemonic per identity, unlimited derived burners.

Derivation paths follow BIP-44 conventions so any wallet app can restore the seed:
  EVM     m/44'/60'/0'/0/{index}
  Solana  m/44'/501'/{index}'/0'
Indexes are allocated per identity+chain and never reused.
"""
from __future__ import annotations

from mnemonic import Mnemonic

try:
    from solders.keypair import Keypair
except ImportError:  # optional extra — pip install -e ".[solana]" (or ./install.sh --full)
    Keypair = None

from .. import db, vault
from ..jsonio import Denied

MN = Mnemonic("english")


def _require_solders() -> None:
    if Keypair is None:
        raise Denied("Solana support needs the solders extra — install it with: "
                     "pip install -e \".[solana]\" (or ./install.sh --full)")


def new_mnemonic(words: int = 24) -> str:
    return MN.generate(strength=256 if words >= 24 else 128)


def valid(mnemonic: str) -> bool:
    return MN.check(mnemonic.strip())


def _seed(mnemonic: str) -> bytes:
    return MN.to_seed(mnemonic.strip())


def derive_evm(mnemonic: str, index: int) -> tuple[bytes, str]:
    from eth_account import Account

    Account.enable_unaudited_hdwallet_features()
    acct = Account.from_mnemonic(mnemonic.strip(), account_path=f"m/44'/60'/0'/0/{index}")
    return bytes(acct.key), acct.address


def derive_sol(mnemonic: str, index: int) -> tuple[bytes, str]:
    _require_solders()
    kp = Keypair.from_seed_and_derivation_path(_seed(mnemonic), f"m/44'/501'/{index}'/0'")
    return bytes(kp), str(kp.pubkey())


def next_index(identity_id: str, chain: str) -> int:
    key = f"hd_index:{identity_id}:{chain}"
    idx = int(db.kv_get(key, 0))
    db.kv_set(key, idx + 1)
    return idx


def ensure(identity_id: str) -> str:
    if not vault.has_mnemonic(identity_id):
        m = new_mnemonic()
        vault.store_mnemonic(identity_id, m)
        db.event("wallet", "hd root created", identity_id)
        return m
    return vault.load_mnemonic(identity_id)


def restore(identity_id: str, mnemonic: str) -> dict:
    if not valid(mnemonic):
        raise SystemExit("mnemonic is invalid (checksum/word count)")
    if vault.has_mnemonic(identity_id):
        raise SystemExit("identity already has an HD root; use a new identity")
    vault.store_mnemonic(identity_id, mnemonic.strip())
    db.kv_set(f"hd_index:{identity_id}:evm", 0)
    db.kv_set(f"hd_index:{identity_id}:sol", 0)
    db.event("wallet", "hd root restored", identity_id)
    return {"identity": identity_id, "restored": True}


def provision(identity_id: str, chain: str, count: int, prefix: str = "w") -> list[dict]:
    """Derive `count` fresh wallets and store them. Returns public addresses only."""
    m = ensure(identity_id)
    out = []
    for _ in range(count):
        idx = next_index(identity_id, chain)
        # Labels are vault keys, so they must be global: an index alone collides
        # between identities (both start at e0).
        label = f"{identity_id}-{prefix}{idx}"
        if chain == "evm":
            pk, addr = derive_evm(m, idx)
            vault.store_evm(label, pk)
            db.add_wallet(identity_id, "evm", addr, label)
        elif chain == "sol":
            secret, addr = derive_sol(m, idx)
            vault.store_sol(label, secret)
            db.add_wallet(identity_id, "sol", addr, label)
        else:
            raise SystemExit(f"unknown chain family {chain}")
        out.append({"label": label, "address": addr, "index": idx, "chain": chain})
    return out
