"""Policy engine: modes, caps, allowlists and the one place that says yes/no.

Modes
  safe      every funding/sign/connect step needs an approval code
  balanced  testnet inside caps is automatic; mainnet + permits + unknown contracts gate
  turbo     everything inside caps is automatic (unlimited approvals and eth_sign/blind
            hash always gate; hard-blocked: KILL, blocklist, drainer verdicts)

A mode never overrides a hard block and never touches a wallet that is not in the
vault (the operator's main seed stays offline).
"""
from __future__ import annotations

import datetime as dt
import re

from . import config, db
from .jsonio import Denied
from .log import get_logger

log = get_logger("policy")
MODES = ("safe", "balanced", "turbo")
MAX_WEI = 2 ** 256 - 1


def mode() -> str:
    m = (db.kv_get("mode") or config.env("AA_MODE", "balanced")).strip().lower()
    return m if m in MODES else "balanced"


def set_mode(m: str) -> str:
    m = m.lower()
    if m not in MODES:
        raise SystemExit(f"mode must be one of {MODES}")
    db.kv_set("mode", m)
    db.event("policy", f"mode -> {m}")
    return m


def cfg() -> dict:
    return config.policy()


def limits() -> dict:
    return cfg().get("limits", {}) or {}


def chain(name: str) -> dict:
    c = (cfg().get("chains") or {}).get(name)
    if not c:
        raise SystemExit(f"chain '{name}' not configured in policy.yaml")
    return c


def testnets() -> list[str]:
    return [n for n, c in (cfg().get("chains") or {}).items() if c.get("testnet")]


def is_testnet(name: str) -> bool:
    return bool(chain(name).get("testnet"))


def decimals(name: str) -> int:
    return int(chain(name).get("native_decimals", 18))


def cap_for(name: str, kind: str) -> int:
    """Per-tx / daily / gas caps in base units, widened by the `turbo` block when relevant."""
    c = chain(name)
    if mode() == "turbo":
        over = (cfg().get("turbo") or {}).get("chains", {}).get(name) or {}
        c = {**c, **over}
    key = {"tx": "max_tx_native", "daily": "max_daily_native", "gas": "max_gas_native"}[kind]
    return int(float(c.get(key, 0)) * 10 ** decimals(name))


def check_value(name: str, wallet: str, value: int, gas_price: int = 0, gas: int = 0) -> None:
    d = 10 ** decimals(name)
    if value > cap_for(name, "tx"):
        raise Denied(f"value {value/d:.6f} > per-tx cap {cap_for(name,'tx')/d:.6f} on {name}")
    gas_cost = gas_price * max(gas, 1)
    if gas_price and gas_cost > cap_for(name, "gas"):
        raise Denied(f"gas {gas_cost/d:.8f} > gas cap {cap_for(name,'gas')/d:.8f}")
    spent = db.spent_today(name, wallet)
    if spent + value > cap_for(name, "daily"):
        raise Denied(f"daily cap reached on {name}: {spent/d:.6f}+{value/d:.6f} > {cap_for(name,'daily')/d:.6f}")


def allowlisted_contract(name: str, address: str) -> bool:
    if not address:
        return False
    al = (cfg().get("contracts_allowlist") or {}).get(name) or []
    return address.lower() in {a.lower() for a in al}


def blocked(address: str) -> bool:
    return address.lower() in {a.lower() for a in (cfg().get("blocklist") or [])}


def domain_ok(domain: str) -> bool:
    d = domain.lower().removeprefix("www.")
    allowed = [a.lower() for a in (cfg().get("domain_allowlist") or [])]
    auto = config.HOME / "allowlist_domains.txt"
    if auto.exists():
        allowed += [ln.strip().lower() for ln in auto.read_text().splitlines() if ln.strip()]
    return any(d == a or d.endswith("." + a) for a in allowed)


def allowed_domains() -> list[str]:
    auto = config.HOME / "allowlist_domains.txt"
    extra = [ln.strip().lower() for ln in auto.read_text().splitlines() if ln.strip()] if auto.exists() else []
    return sorted({*(a.lower() for a in (cfg().get("domain_allowlist") or [])), *extra})


def disallow_domain(domain: str) -> bool:
    d = domain.lower().removeprefix("www.")
    f = config.HOME / "allowlist_domains.txt"
    hit = False
    if f.exists():
        keep = [ln for ln in f.read_text().splitlines() if ln.strip() and ln.strip().lower() != d]
        hit = len(keep) != len(f.read_text().splitlines())
        f.write_text("\n".join(keep) + ("\n" if keep else ""))
    y = cfg()
    items = y.get("domain_allowlist") or []
    if d in [i.lower() for i in items]:
        y["domain_allowlist"] = [i for i in items if i.lower() != d]
        config.save_yaml("policy.yaml", y)
        hit = True
    return hit


def allow_domain(domain: str) -> None:
    d = domain.lower().removeprefix("www.")
    f = config.HOME / "allowlist_domains.txt"
    cur = set(f.read_text().split()) if f.exists() else set()
    if d not in cur:
        with open(f, "a") as fh:
            fh.write(d + "\n")


# ---------- the single decision entrypoint ----------
def needs_gate(action: str, **kw) -> tuple[bool, list[str]]:
    """Return (gate_required, reasons). Callers create the gate and stop on True."""
    m = mode()
    reasons: list[str] = []
    if m == "turbo":
        if action in ("connect", "sign_text", "quest", "follow", "chat", "checkin", "deploy"):
            if action == "deploy" and not is_testnet(kw.get("chain", "sepolia")):
                return True, ["deploy on mainnet"]
            return False, []
        if action == "sign_typed":
            if kw.get("risky") and (kw.get("mainnet") or not (cfg().get("turbo") or {}).get("allow_permits", False)):
                return True, ["risky typed data (permit/order)"]
            return False, []
        if action == "tx":
            if kw.get("unlimited"):
                return True, ["unlimited approval"]
            if kw.get("mainnet") and not (cfg().get("turbo") or {}).get("allow_mainnet", False):
                return True, ["mainnet tx"]
            if not kw.get("contract_ok", True):
                return True, ["contract not allowlisted"]
            return False, []
        return False, []

    if m == "safe":
        return True, ["safe mode"]
    # balanced
    if action == "tx":
        if kw.get("unlimited"):
            return True, ["unlimited approval"]
        if kw.get("mainnet"):
            return True, ["mainnet tx"]
        if not kw.get("contract_ok", True):
            return True, ["contract not allowlisted"]
        return False, []
    if action == "sign_typed":
        if kw.get("risky"):
            reasons.append("permit/order typed data")
        if kw.get("mainnet"):
            reasons.append("mainnet")
        return bool(reasons), reasons
    if action == "connect":
        return not kw.get("safe_origin", False), ["origin not allowlisted / scam_check not ok"]
    if action == "deploy":
        return bool(kw.get("mainnet")), ["deploy on mainnet"]
    return False, []


def action_budget(kind: str) -> int:
    """How many of an action per hour the mode allows (0 = unlimited)."""
    base = {"follow": 40, "chat": 60, "connect": 30, "tx": 20, "quest": 12}.get(kind, 60)
    mult = {"safe": 0.5, "balanced": 1, "turbo": 2}.get(mode(), 1)
    return int(base * mult)


def actions_last_hour(kind: str) -> int:
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat(timespec="seconds")
    return int(db.scalar("SELECT COUNT(*) FROM events WHERE kind=? AND ts>=?", (kind, since), 0) or 0)


def within_budget(kind: str) -> bool:
    b = action_budget(kind)
    return b == 0 or actions_last_hour(kind) < b


def note(kind: str, msg: str, identity_id: str | None = None, data: dict | None = None) -> None:
    db.event(kind, msg, identity_id, data=data)


UINT_RE = re.compile(r"^\d+$")


def unlimited_approval(amount: str | int | None) -> bool:
    if amount is None:
        return False
    try:
        return int(amount) >= MAX_WEI - 1
    except (TypeError, ValueError):
        return False
