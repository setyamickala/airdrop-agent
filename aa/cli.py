"""Command line surface. Every command returns the JSON envelope from `jsonio`.

The CLI is the only documented interface: shell, cron, MCP and any agent all call it,
so behaviour (and therefore policy) cannot drift between callers.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, chains, config, daily, db, gates, guard, log
from . import notify as notify_mod
from . import policy, vault
from .jsonio import Denied, run as envelope_run
from .wallet import evm as evmw
from .wallet import ext as extmod
from .wallet import hd, send as sender
from .wallet import sign as signer
from .wallet import sol as solw

lg = log.get_logger("cli")


def _units(chain: str, amount: float) -> int:
    return int(round(float(amount) * 10 ** policy.decimals(chain)))


def _asec(coro):
    return asyncio.run(coro)


# ---------------- init / doctor ----------------
def init(random_vault_password: bool = False, force: bool = False) -> tuple[dict, list[str]]:
    made = []
    for name in ("policy.yaml", "quests.yaml", "radar_sources.yaml", "personas.yaml",
                 "discord_servers.yaml", "faucets.yaml", "providers.yaml", "autopilot.yaml"):
        p = config.HOME / name
        if not p.exists():
            shutil.copy2(config.CONFIG_DIR / name, p)
            made.append(name)
    env = config.ENV_FILE
    if not env.exists():
        shutil.copy2(config.CONFIG_DIR / "env.example", env)
        os.chmod(env, 0o600)
    placeholder = "VAULT_PASSWORD=change-me" in env.read_text()
    if placeholder:
        pw = vault.gen_password(36)
        env.write_text(sub_line(env.read_text(), "VAULT_PASSWORD", pw))
        os.chmod(env, 0o600)
        made.append("VAULT_PASSWORD generated (stored in .env, back it up)")
    if not db.kv_get("mode"):
        policy.set_mode(config.env("AA_MODE", "balanced"))
    db.event("init", "initialised")
    return ({"home": str(config.HOME), "created": made, "mode": policy.mode()},
            ["edit ~/.airdrop-agent/.env (Telegram, RPC, email)", "aa doctor", "aa identity new mymain"])


def sub_line(text: str, key: str, value: str) -> str:  # type: ignore[name-defined]
    import re as _re

    if _re.search(rf"(?m)^{key}=.*$", text):
        return _re.sub(rf"(?m)^{key}=.*$", f"{key}={value}", text)
    return text + f"\n{key}={value}\n"


def doctor(offline: bool = False) -> tuple[dict, list[str]]:
    checks = {}

    def add(name, ok, detail=""):
        checks[name] = {"ok": bool(ok), "detail": detail}

    add("home_0700", oct(config.HOME.stat().st_mode)[-3:] == "700", str(config.HOME))
    add("env_0600", config.ENV_FILE.exists() and oct(config.ENV_FILE.stat().st_mode)[-3:] == "600")
    add("vault_password", bool(config.env("VAULT_PASSWORD") or config.env("VAULT_PASSWORD_FILE")))
    add("kill", not config.KILL_FILE.exists())
    add("policy", bool(policy.cfg().get("chains")), f"{len(policy.cfg().get('chains') or {})} chains")
    add("identities", bool(db.identities()), str(len(db.identities())))
    add("wallets", bool(db.rows("SELECT 1 FROM wallets LIMIT 1")))
    add("telegram_report", notify_mod.enabled())
    add("telegram_user", bool(config.env("TG_API_ID") and config.env("TG_API_HASH")))
    add("x_api", bool(config.env("X_BEARER_TOKEN")))
    add("discord", bool(config.env("DISCORD_USER_TOKEN") or db.rows("SELECT 1 FROM socials WHERE platform='discord'")))
    add("email", bool(config.env("IMAP_HOST") and config.env("IMAP_PASSWORD")))
    add("solana", _has("solders"))
    browsers = config.env("PLAYWRIGHT_BROWSERS_PATH") or config.env("AA_BROWSERS_PATH") or \
        str(Path.home() / "Library" / "Caches" / "ms-playwright" if sys.platform == "darwin"
            else Path.home() / ".cache" / "ms-playwright")
    add("browser", _has("playwright") and Path(browsers).exists(), browsers)
    add("forge", bool(shutil.which("forge")))
    add("captcha", bool(config.env("CAPTCHA_API_KEY")))
    if not offline:
        for c in chains.all_chains():
            try:
                cfg = chains.cfg(c)
                add(f"rpc_{c}", True, cfg["rpc"][:40])
            except Exception as e:  # noqa: BLE001
                add(f"rpc_{c}", False, str(e)[:80])
    bad = [k for k, v in checks.items() if not v["ok"]]
    return ({"checks": checks, "fail": bad, "version": __version__},
            ["fix: " + ", ".join(bad) if bad else "aa identity new mymain", "aa wallet new --identity mymain"])


def _has(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def status() -> tuple[dict, list[str]]:
    return ({"version": __version__, "guard": guard.status(), "identities": len(db.identities()),
             "wallets": len(db.rows("SELECT 1 FROM wallets")), "quests": len(db.rows("SELECT 1 FROM quests")),
             "gates": len(gates.list_gates()), "players": len(db.rows("SELECT 1 FROM socials")),
             "events_today": db.scalar("SELECT COUNT(*) FROM events WHERE ts>=?", (db.today(),), 0),
             "home": str(config.HOME)}, ["aa autopilot plan", "aa daily plan --identity <id>"])


# ---------------- identity ----------------
def identity_new(label: str, with_email: bool = False, wallet_count: int = 1,
                 persona: str = "casual-id", proxy: str = "") -> dict:
    label = config.slug(label)
    if db.one("SELECT 1 FROM identities WHERE label=?", (label,)):
        raise Denied(f"identity label exists: {label}")
    ident = db.create_identity(label, persona, proxy)
    hd.ensure(ident["id"])
    wallets = {"evm": hd.provision(ident["id"], "evm", max(1, wallet_count), prefix="e"),
               "sol": hd.provision(ident["id"], "sol", max(1, wallet_count), prefix="s")}
    out = {"identity": ident["id"], "label": label, "persona": persona,
           "evm": [w["address"] for w in wallets["evm"]], "sol": [w["address"] for w in wallets["sol"]]}
    if with_email:
        out["email"] = "run aa email add --identity " + ident["id"]
    out["next"] = f"aa wallet balance --identity {ident['id']}  ·  aa tg login --identity {ident['id']}"
    return out


def identity_list() -> tuple[dict, list[str]]:
    rows = db.identities(active_only=False)
    for r in rows:
        r["wallets"] = {"evm": len(db.wallets(r["id"], "evm")), "sol": len(db.wallets(r["id"], "sol"))}
        r["socials"] = [s["platform"] for s in db.rows("SELECT platform FROM socials WHERE identity_id=?", (r["id"],))]
        r["email"] = (db.email_of(r["id"]) or {}).get("address")
    return {"identities": rows}, ["aa identity show <id>"]


def identity_show(ident: str) -> tuple[dict, list[str]]:
    r = db.identity(ident)
    r["wallets"] = db.rows("SELECT label,chain,address,kind FROM wallets WHERE identity_id=?", (r["id"],))
    r["socials"] = db.rows("SELECT platform,handle,status FROM socials WHERE identity_id=?", (r["id"],))
    r["email"] = (db.email_of(r["id"]) or {}).get("address")
    r["events"] = db.rows("SELECT ts,kind,msg FROM events WHERE identity_id=? ORDER BY id DESC LIMIT 12", (r["id"],))
    return r, ["aa wallet balance --identity " + r["id"]]


def identity_clone(source: str, label: str, wallet_count: int = 0) -> tuple[dict, list[str]]:
    src = db.identity(source)
    label = config.slug(label)
    if db.one("SELECT 1 FROM identities WHERE label=?", (label,)):
        raise Denied(f"identity label exists: {label}")
    ident = db.create_identity(label, src.get("persona") or "casual-id", src.get("proxy") or "",
                               src.get("notes") or "")
    if wallet_count:
        hd.ensure(ident["id"])
        hd.provision(ident["id"], "evm", wallet_count, prefix="e")
        hd.provision(ident["id"], "sol", wallet_count, prefix="s")
    return ({"identity": ident["id"], "label": label, "cloned_from": src["id"],
             "persona": src.get("persona"), "proxy": src.get("proxy"), "wallets": wallet_count},
            ["aa wallet new --identity " + ident["id"] if not wallet_count else "aa session warm --identity " + ident["id"]])


def identity_rm(ident: str) -> tuple[dict, list[str]]:
    r = db.identity(ident)
    db.execute("UPDATE identities SET status='archived' WHERE id=?", (r["id"],))
    return {"archived": r["id"], "note": "keys stay in the vault"}, ["aa vault export"]


def identity_set(ident: str, field: str, value: str) -> tuple[dict, list[str]]:
    r = db.identity(ident)
    if field not in ("persona", "proxy", "notes", "status"):
        raise Denied("field must be persona/proxy/notes/status")
    db.execute(f"UPDATE identities SET {field}=? WHERE id=?", (value, r["id"]))
    return {"identity": r["id"], field: value}, []


# ---------------- wallet ----------------
def wallet_new(identity: str, chain: str = "both", count: int = 1, mode: str = "hd") -> tuple[dict, list[str]]:
    r = db.identity(identity)
    if count > 100:
        raise Denied("max 100 at once")
    chains_ = ["evm", "sol"] if chain == "both" else [chain]
    out = {}
    for c in chains_:
        if c not in ("evm", "sol"):
            raise Denied("chain must be evm, sol or both")
        out[c] = (hd.provision(r["id"], c, count, prefix="e" if c == "evm" else "s") if mode == "hd"
                  else (evmw.create(r["id"], count) if c == "evm" else solw.create(r["id"], count)))
    db.event("wallet", f"new {count} {chain} ({mode})", r["id"])
    return ({"identity": r["id"], "wallets": out},
            [f"aa wallet balance --identity {r['id']}", "aa testnet faucets --chain sepolia"])


def wallet_list(identity: str, chain: str = "") -> tuple[dict, list[str]]:
    r = db.identity(identity)
    ws = db.rows("SELECT w.label,w.chain,w.address,w.kind FROM wallets w WHERE identity_id=?"
                 + (" AND chain=?" if chain else "") + " ORDER BY w.chain,w.id",
                 (r["id"], chain) if chain else (r["id"],))
    return {"identity": r["id"], "wallets": ws}, ["aa wallet balance --identity " + r["id"]]


def wallet_balance(identity: str, chain: str | None = None) -> dict:
    r = db.identity(identity)
    out = []
    for c in chains.all_chains():
        if chain and c != chain:
            continue
        cfg = policy.chain(c)
        for w in db.wallets(r["id"], "evm" if cfg.get("kind", "evm") == "evm" else "sol"):
            try:
                if cfg.get("kind") == "solana":
                    b = solw.balance(chains.sol(c), w["address"])
                    out.append({"chain": c, "label": w["label"], "address": w["address"], "native": b["sol"]})
                else:
                    b = evmw.balance(cfg, w["address"])
                    out.append({"chain": c, "label": w["label"], "address": w["address"], "native": b["native"]})
            except Exception as e:  # noqa: BLE001
                out.append({"chain": c, "label": w["label"], "error": str(e)[:120]})
    return {"identity": r["id"], "balances": out, "funded": [b for b in out if b.get("native", 0) > 0]}


def do_send(chain: str, identity: str, label: str, to: str, amount: float = 0,
            broadcast: bool = False, data: str = "0x") -> dict:
    r = db.identity(identity)
    w = evmw.resolve(r["id"], label)
    return sender.send(chain, r["id"], w["label"], to, value_wei=_units(chain, amount),
                       calldata=data, broadcast=broadcast, via="cli")


def wallet_send(args) -> tuple[dict, list[str]]:
    out = do_send(args.chain, args.identity, args.label, args.to, args.amount, args.broadcast, args.data or "0x")
    return out, ["add --broadcast to execute" if not args.broadcast else "aa status"]


def wallet_sol_send(args) -> tuple[dict, list[str]]:
    r = db.identity(args.identity)
    w = solw.resolve(r["id"], args.label)
    cfg = chains.sol(args.chain)
    lamports = int(args.amount * 1e9)
    from . import guard as gd

    gd.check_kill()
    payload = {"_kind": "tx", "chain": args.chain, "identity": r["id"], "label": w["label"],
               "to": args.to, "value": str(lamports), "data": "solana"}
    if not gates.consume(payload):
        want, reasons = policy.needs_gate("tx", mainnet=not cfg.get("testnet"), contract_ok=True)
        if want:
            gates.require("tx", f"SOL send {args.amount} → {args.to} dari {w['label']}", payload)
    out = solw.send(cfg, w["label"], args.to, lamports, broadcast=args.broadcast, identity_id=r["id"])
    return out, []


def wallet_import(args) -> tuple[dict, list[str]]:
    r = db.identity(args.identity)
    if args.chain == "evm":
        out = evmw.import_key(r["id"], args.secret) if not args.mnemonic else \
            {"wallets": evmw.import_mnemonic(r["id"], args.secret, args.count)}
    else:
        out = solw.import_key(r["id"], args.secret)
    return {"imported": out}, ["aa wallet balance --identity " + r["id"]]


def wallet_approve(args) -> tuple[dict, list[str]]:
    if args.unlimited:
        # The flag is kept so old scripts fail with a clear error instead of
        # an argparse error; unlimited approvals are hard-blocked (see
        # wallet.send.approve), so this path always denies.
        raise Denied("unlimited approvals are hard-blocked — pass an explicit --amount")
    r = db.identity(args.identity)
    w = evmw.resolve(r["id"], args.label)
    out = sender.approve(args.chain, r["id"], w["label"], args.token, args.spender,
                         int(args.amount * 1e18), broadcast=args.broadcast)
    return out, []


# ---------------- sign ----------------
def do_sign(identity: str, label: str, message: str, origin: str = "") -> dict:
    r = db.identity(identity)
    w = evmw.resolve(r["id"], label)
    return signer.personal(r["id"], w["label"], message, origin)


def sign_message(args) -> tuple[dict, list[str]]:
    return do_sign(args.identity, args.label, args.message, args.origin or ""), []


def sign_typed(args) -> tuple[dict, list[str]]:
    r = db.identity(args.identity)
    w = evmw.resolve(r["id"], args.label)
    data = Path(args.file).read_text() if Path(args.file).exists() else args.json
    return signer.typed(r["id"], w["label"], data), []


# ---------------- email ----------------
def email_add(args) -> tuple[dict, list[str]]:
    r = db.identity(args.identity)
    from .email import imap

    out = imap.register(r["id"], args.address, args.password, args.host, args.port)
    return out, ["aa email otp --identity " + r["id"]]


def email_otp(args) -> tuple[dict, list[str]]:
    from .email import imap

    r = db.identity(args.identity) if args.identity else None
    out = imap.wait_otp(r["id"] if r else None, sender=args.sender or "", subject=args.subject or "",
                        timeout=args.timeout)
    return out, []


def email_link(args) -> tuple[dict, list[str]]:
    from .email import imap

    r = db.identity(args.identity) if args.identity else None
    return imap.wait_link(r["id"] if r else None, sender=args.sender or "", timeout=args.timeout), []


def email_auto(args) -> tuple[dict, list[str]]:
    """Watch the inbox and hand the code back to the caller in one shot."""
    return email_otp(args)


# ---------------- telegram ----------------
def tg_login(args) -> tuple[dict, list[str]]:
    from .social import telegram

    r = db.identity(args.identity)
    return _asec(telegram.login_send(r["id"], args.phone)), []


def tg_verify(args) -> tuple[dict, list[str]]:
    from .social import telegram

    r = db.identity(args.identity)
    return _asec(telegram.login_verify(r["id"], args.code, args.password or "")), []


def tg(args) -> tuple[dict, list[str]]:
    from .social import telegram

    r = db.identity(args.identity) if getattr(args, "identity", None) else None
    iid = r["id"] if r else (db.identities()[0]["id"] if db.identities() else "")
    cmd = args.tg_cmd
    if cmd == "me":
        return _asec(telegram.whoami(iid)), []
    if cmd == "join":
        return _asec(telegram.join(iid, args.target)), []
    if cmd == "follow":
        targets = [telegram.parse_target(t) for t in args.targets]
        return {"results": _asec(telegram.follow_many(iid, targets))}, []
    if cmd == "read":
        return _asec(telegram.read(iid, args.target, args.limit)), []
    if cmd == "send":
        return _asec(telegram.send(iid, args.target, args.text)), []
    if cmd == "react":
        return _asec(telegram.react(iid, args.target, args.emoji)), []
    if cmd == "start":
        return _asec(telegram.start_bot(iid, args.target, args.ref or "")), []
    if cmd == "miniapp":
        return _asec(telegram.miniapp_url(iid, args.target, args.url)), []
    if cmd == "dialogs":
        return _asec(telegram.dialogs(iid)), []
    if cmd == "click":
        return _asec(telegram.click_button(iid, args.target, args.text, args.msg_id)), []
    raise Denied("unknown tg command")


# ---------------- x ----------------
def x_cmd(args) -> tuple[dict, list[str]]:
    from .social import x

    if args.x_cmd == "login":
        return _asec(x.login(args.identity, args.user, args.password, totp_secret=args.totp or "")), []
    r = db.identity(args.identity)
    if args.x_cmd == "status":
        return _asec(x.status(r["id"])), []
    if args.x_cmd == "follow":
        return {"results": _asec(x.follow(r["id"], args.handles))}, []
    if args.x_cmd == "unfollow":
        return _asec(x.unfollow(r["id"], args.handles[0])), []
    if args.x_cmd == "post":
        return _asec(x.post(r["id"], args.text, reply_to=args.reply or "")), []
    if args.x_cmd == "like":
        return _asec(x.like(r["id"], args.url)), []
    if args.x_cmd == "repost":
        return _asec(x.repost(r["id"], args.url)), []
    if args.x_cmd == "search":
        return {"results": _asec(x.search(r["id"], args.query, args.limit))}, []
    if args.x_cmd == "timeline":
        return {"posts": x.timeline(args.handles[0], args.limit)}, []
    raise Denied("unknown x command")


# ---------------- discord ----------------
def dc(args) -> tuple[dict, list[str]]:
    from .social import discord

    if args.dc_cmd == "login":
        return _asec(discord.login(args.identity, args.email, args.password, args.totp or "")), []
    r = db.identity(args.identity)
    if args.dc_cmd == "status":
        return discord.status(r["id"]), []
    if args.dc_cmd == "servers":
        return {"servers": [{"id": g["id"], "name": g["name"]} for g in discord.guilds(r["id"])]}, []
    if args.dc_cmd == "channels":
        gid = discord.server_cfg(args.server)[1]["id"]
        return {"channels": discord.channels(r["id"], gid)}, []
    if args.dc_cmd == "follow":
        return discord.follow_channel(r["id"], args.channel), []
    if args.dc_cmd == "grind":
        return discord.grind(r["id"], args.server, minutes=args.minutes, max_messages=args.max,
                             persona=args.persona), []
    if args.dc_cmd == "progress":
        return {"progress": discord.progress(r["id"])}, []
    if args.dc_cmd == "read":
        return {"messages": discord.read(r["id"], args.channel, args.limit)}, []
    if args.dc_cmd == "send":
        return discord.send(r["id"], args.channel, args.text), []
    if args.dc_cmd == "react":
        return discord.react(r["id"], args.channel, args.message_id, args.emoji), []
    raise Denied("unknown discord command")


# ---------------- quests ----------------
def quest_cmd(args) -> tuple[dict, list[str]]:
    from .quest import dsl, runner

    if args.quest_cmd == "new":
        q = dsl.scaffold(args.name, args.url, args.platform, args.chain or "")
        p = dsl.write_file(q)
        dsl.save(q, status="pending", source="cli")
        return {"quest": q["id"], "file": str(p)}, [f"edit {p}", f"aa quest validate {q['id']}", f"aa quest run {q['id']}"]
    if args.quest_cmd == "import":
        out = dsl.import_file(Path(args.file))
        return out, [f"aa quest run {out['id']} --identity <id>"]
    if args.quest_cmd == "list":
        return {"quests": dsl.listing(args.status)}, []
    if args.quest_cmd == "show":
        q = dsl.load(args.quest)
        return {k: q[k] for k in q if not k.startswith("_")}, []
    if args.quest_cmd == "validate":
        q = dsl.load(args.quest)
        errs = dsl.validate(q)
        return {"valid": not errs, "errors": errs}, []
    if args.quest_cmd == "due":
        return {"due": [q["id"] for q in dsl.next_due(10)]}, []
    if args.quest_cmd == "remove":
        return dsl.remove(args.quest), []
    if args.quest_cmd == "probe":
        from .browser.engine import Browser

        rows = db.identities()
        iid = db.identity(args.identity)["id"] if args.identity else (rows[0]["id"] if rows else "")
        if not iid:
            raise Denied("no identity yet (aa identity new ...)")

        async def look():
            async with Browser(iid, headless=False) as b:
                out = await b.goto(args.url)
                await b.human_wait(2.5, 4.5)
                snap = await b.snapshot()
                shot = await b.screenshot("probe")
                return {"url": snap["url"], "title": snap["title"], "cf": out.get("cf"),
                        "fields": snap["fields"][:25], "text": snap["text"][:1200], "screenshot": shot}

        return _asec(look()), ["aa quest new <name> <url>"]
    if args.quest_cmd == "run":
        q = dsl.load(args.quest)
        iid = db.identity(args.identity)["id"] if args.identity else (db.identities()[0]["id"] if db.identities() else "")
        if not iid:
            raise Denied("no identity yet (aa identity new ...)")
        out = _asec(runner.run(q, iid, dry=args.dry, headless=not args.headful))
        return out, (["finish the manual step, then re-run"] if out.get("parked") else [])
    raise Denied("unknown quest command")



# ---------------- cloudflare ----------------
def cf_cmd(args) -> tuple[dict, list[str]]:
    from .browser import cf

    if args.cf_cmd == "status":
        return {"clearance": cf.status(args.identity or "")}, ["aa cf assist --url <url> --identity <id>"]
    if args.cf_cmd == "clear":
        return {"cleared": cf.forget(args.identity or "", args.host or "")}, []
    r = db.identity(args.identity)

    async def assist():
        from .browser.engine import Browser

        async with Browser(r["id"], headless=False) as b:
            await b.page.goto(args.url, wait_until="domcontentloaded")
            print("solve the challenge in the window; waiting…", file=sys.stderr)
            deadline = time.time() + int(config.env("CF_ASSIST_SECONDS", "300"))
            while time.time() < deadline:
                st = await cf.page_state(b.page)
                if st["clearance"] and not st["kind"]:
                    n = cf.remember(r["id"], urlparse(b.page.url).hostname or "", await b.page.context.cookies(),
                                    b.user_agent)
                    return {"host": b.page.url, "cookies": n, "last_check": st["kind"] or "clear"}
                await asyncio.sleep(2)
            shot = await b.screenshot("cf_assist_timeout")
            return {"host": b.page.url, "cookies": 0, "timeout": True, "screenshot": shot}

    return _asec(assist()), ["re-run the blocked command"]


# ---------------- session ----------------
def social_cmd(args) -> tuple[dict, list[str]]:
    from . import session
    from .email import gmail
    from .social import discord, telegram, x

    if args.s_cmd == "status":
        return {"identity": args.identity, "platforms": session.status(args.identity)}, []
    name = args.platform
    if name == "telegram":
        if args.s_cmd == "login":
            return _asec(telegram.login_send(args.identity, args.user)), []
    if args.s_cmd == "login":
        if name == "x":
            return _asec(x.login(args.identity, args.user, args.password, totp_secret=args.totp or "")), []
        if name == "discord":
            return _asec(discord.login(args.identity, args.user, args.password, args.totp or "")), []
        if name in ("gmail", "google"):
            return _asec(gmail.login(args.identity, args.user, args.password, args.totp or "")), []
        raise Denied(f"login not supported for {name}")
    if args.s_cmd == "check":
        return _asec(session.check(args.identity, name)), []
    if args.s_cmd == "warm":
        return _asec(session.warm(args.identity, name)), []
    raise Denied("unknown social command")


def session_cmd(args) -> tuple[dict, list[str]]:
    from . import session
    from .browser.engine import Browser

    if args.sn_cmd == "status":
        return {"identity": args.identity, "platforms": session.status(args.identity)}, []
    r = db.identity(args.identity)

    if args.sn_cmd == "check":
        async def each():
            return {"results": [await session.check(r["id"], p) for p in args.platforms]}

        return _asec(each()), []

    async def go():
        async with Browser(r["id"]) as b:
            if args.sn_cmd == "restore":
                n = await session.restore(r["id"], b)
                return {"restored": n}
            if args.sn_cmd == "save":
                return await session.save(r["id"], b)
            if args.sn_cmd == "warm":
                return {"results": await session.warm_all(r["id"])}
            raise Denied("unknown session command")

    return _asec(go()), []



# ---------------- testnet ----------------
def testnet(args) -> tuple[dict, list[str]]:
    from .testnet import campaign, deploy, faucets

    if args.t_cmd == "status":
        return {"toolchain": deploy.status(), "faucets": faucets.status()}, []
    if args.t_cmd == "faucets":
        return {"faucets": [f for f in faucets.for_chain(args.chain)]}, []
    if args.t_cmd == "claim":
        r = db.identity(args.identity)
        from .browser.engine import Browser

        async def go():
            async with Browser(r["id"], profile="faucet", chain=args.chain) as b:
                return await faucets.claim(b, r["id"], args.chain, args.name or "")

        return _asec(go()), []
    if args.t_cmd == "deploy":
        r = db.identity(args.identity)
        return deploy.run(args.chain, r["id"], args.kind), []
    if args.t_cmd == "campaign":
        r = db.identity(args.identity)
        return _asec(campaign.run(args.chain, r["id"], args.name, rounds=args.rounds)), []
    if args.t_cmd == "estimate":
        return campaign.estimate(args.chain, args.name), []
    raise Denied("unknown testnet command")


# ---------------- daily ----------------
async def do_daily(identity: str) -> dict:
    r = db.identity(identity)
    return await daily.run(r["id"], headless=config.env_bool("BROWSER_HEADLESS", True))


def daily_cmd(args) -> tuple[dict, list[str]]:
    if args.d_cmd == "status":
        return daily.status(), []
    if args.d_cmd == "plan":
        r = db.identity(args.identity)
        return daily.plan(r["id"]), []
    if args.d_cmd == "run":
        if args.all:
            return {"results": _asec(daily.run_all())}, []
        r = db.identity(args.identity)
        return _asec(do_daily(r["id"])), []
    raise Denied("unknown daily command")


# ---------------- radar ----------------
def radar_cmd(args) -> tuple[dict, list[str]]:
    from .radar import pipeline, sources

    if args.r_cmd == "scan":
        r = db.identity(args.identity)
        return _asec(pipeline.scan(r["id"], include_x=not args.no_x, include_tg=not args.no_tg,
                                   auto=True)), []
    if args.r_cmd == "latest":
        return {"items": pipeline.latest(args.limit, args.min_score)}, []
    if args.r_cmd == "kinds":
        return {"kinds": pipeline.by_kind()}, []
    if args.r_cmd == "clear":
        return pipeline.clear(args.status), []
    if args.r_cmd == "sources":
        return sources.listing(), []
    if args.r_cmd == "add":
        return sources.add(args.kind, args.target, args.trust), []
    if args.r_cmd == "rm":
        return sources.remove(args.kind, args.target), []
    raise Denied("unknown radar command")


# ---------------- autopilot ----------------
def autopilot_cmd(args) -> tuple[dict, list[str]]:
    from . import autopilot

    if args.a_cmd == "plan":
        return autopilot.plan(), []
    if args.a_cmd == "status":
        return autopilot.status(), []
    if args.a_cmd == "tick":
        return _asec(autopilot.tick(headless=not args.headful)), []
    if args.a_cmd == "run":
        return _asec(autopilot.run(args.minutes, headless=not args.headful)), []
    if args.a_cmd == "daemon":
        _asec(autopilot.daemon(headless=not args.headful))
        return {"stopped": True}, []
    raise Denied("unknown autopilot command")


# ---------------- browser / ext / vault ----------------
def ext(args) -> tuple[dict, list[str]]:
    if args.e_cmd == "list":
        return {"available": extmod.available(),
                "installed": {i["id"]: extmod.paths(i["id"]) for i in db.identities()}}, []
    r = db.identity(args.identity)
    if args.e_cmd == "install":
        return extmod.install(r["id"], args.name), ["export BROWSER_USE_EXTENSIONS=1"]
    if args.e_cmd == "remove":
        return extmod.remove(r["id"], args.name), []
    raise Denied("unknown ext command")


def browser(args) -> tuple[dict, list[str]]:
    from .browser.engine import Browser

    r = db.identity(args.identity)

    async def go():
        async with Browser(r["id"], profile=args.profile, headless=False if args.headful else None) as b:
            if args.url:
                await b.goto(args.url)
                await b.human_wait(1, 2)
            if args.login:
                print("browser open — log in manually, then Ctrl+C", file=sys.stderr)
                await asyncio.sleep(args.minutes * 60 if args.minutes else 1800)
            snap = await b.snapshot()
            shot = await b.screenshot("manual")
            return {"url": snap["url"], "title": snap["title"], "text": snap["text"][:1500],
                    "fields": snap["fields"][:20], "screenshot": shot}

    return _asec(go()), []


def vault_cmd(args) -> tuple[dict, list[str]]:
    if args.v_cmd == "export":
        dest = Path(args.file).expanduser()
        if dest.exists():
            raise Denied(f"{dest} exists")
        return vault.export_bundle(dest, args.password), ["store it offline, same password = full keys"]
    if args.v_cmd == "import":
        return vault.import_bundle(Path(args.file), args.password), []
    if args.v_cmd == "count":
        return {"entries": vault.count()}, []
    if args.v_cmd == "password":
        cur = config.env("VAULT_PASSWORD")
        if cur and not cur.startswith("change-me"):
            return {"password": "already set", "entries": vault.count(),
                    "hint": "rotation needs re-encryption; export first"}, []
        _set_vault_password()
        return {"generated": "stored in .env — back it up now"}, []
    raise Denied("unknown vault command")


def _set_vault_password() -> bool:
    pw = vault.gen_password(36)
    text = config.ENV_FILE.read_text()
    config.ENV_FILE.write_text(sub_line(text, "VAULT_PASSWORD", pw))
    os.chmod(config.ENV_FILE, 0o600)
    return True


# ---------------- parser ----------------
def build() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aa", description="airdrop-agent v4 — autonomous airdrop operator")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--version", action="store_true", help="print the version as JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name, **kw)
        sp.set_defaults(fn=envelope_run, target=fn)
        return sp

    s = add("init", init)
    s.add_argument("--random-vault-password", action="store_true")
    s.add_argument("--force", action="store_true")
    add("doctor", doctor).add_argument("--offline", action="store_true")
    add("status", status)
    add("version", lambda: ({"version": __version__}, []))
    s = add("mode", lambda m=None: ({"mode": policy.set_mode(m) if m else policy.mode()}, []))
    s.add_argument("m", choices=policy.MODES, nargs="?", default=None)
    add("kill", lambda reason="": (guard.kill(reason), []))
    add("unkill", lambda: (guard.unkill(), []))

    g = sub.add_parser("gate").add_subparsers(dest="g_cmd", required=True)
    g.add_parser("list").set_defaults(fn=envelope_run, target=lambda: ({"gates": gates.list_gates()}, []))
    gg = g.add_parser("approve")
    gg.add_argument("id", type=int)
    gg.add_argument("code")
    gg.set_defaults(fn=envelope_run, target=lambda id, code: (gates.approve(id, code), []))
    gr = g.add_parser("reject")
    gr.add_argument("id", type=int)
    gr.set_defaults(fn=envelope_run, target=lambda id: (gates.reject(id), []))
    g.add_parser("poll").set_defaults(fn=envelope_run, target=lambda: (gates.poll_telegram(), []))
    g.add_parser("expire").set_defaults(fn=envelope_run, target=lambda: ({"expired": gates.expire_old()}, []))

    a = sub.add_parser("allow").add_subparsers(dest="a_cmd", required=True)
    aa = a.add_parser("add")
    aa.add_argument("domain")
    aa.set_defaults(fn=envelope_run, target=lambda domain: (policy.allow_domain(domain) or {"allowed": domain}, []))
    a.add_parser("list").set_defaults(fn=envelope_run, target=lambda: ({"domains": policy.allowed_domains()}, []))
    ar = a.add_parser("rm")
    ar.add_argument("domain")
    ar.set_defaults(fn=envelope_run, target=lambda domain: ({"removed": policy.disallow_domain(domain), "domain": domain}, []))

    i = sub.add_parser("identity").add_subparsers(dest="i_cmd", required=True)
    n = i.add_parser("new")
    n.add_argument("label")
    n.add_argument("--with-email", action="store_true")
    n.add_argument("--wallets", type=int, default=1, dest="wallet_count")
    n.add_argument("--persona", default="casual-id")
    n.add_argument("--proxy", default="")
    n.set_defaults(fn=envelope_run, target=identity_new)
    ic = i.add_parser("clone")
    ic.add_argument("source")
    ic.add_argument("label")
    ic.add_argument("--wallets", type=int, default=0, dest="wallet_count")
    ic.set_defaults(fn=envelope_run, target=identity_clone)
    i.add_parser("list").set_defaults(fn=envelope_run, target=identity_list)
    sh = i.add_parser("show")
    sh.add_argument("identity")
    sh.set_defaults(fn=envelope_run, target=identity_show)
    rm = i.add_parser("rm")
    rm.add_argument("identity")
    rm.set_defaults(fn=envelope_run, target=identity_rm)
    st = i.add_parser("set")
    st.add_argument("identity")
    st.add_argument("field")
    st.add_argument("value")
    st.set_defaults(fn=envelope_run, target=identity_set)

    w = sub.add_parser("wallet").add_subparsers(dest="w_cmd", required=True)
    wn = w.add_parser("new")
    wn.add_argument("--identity", required=True)
    wn.add_argument("--chain", default="both", choices=["evm", "sol", "both"])
    wn.add_argument("--count", type=int, default=1)
    wn.add_argument("--mode", default="hd", choices=["hd", "random"])
    wn.set_defaults(fn=envelope_run, target=wallet_new)
    wl = w.add_parser("list")
    wl.add_argument("--identity", required=True)
    wl.add_argument("--chain", default="")
    wl.set_defaults(fn=envelope_run, target=wallet_list)
    wb = w.add_parser("balance")
    wb.add_argument("--identity", required=True)
    wb.add_argument("--chain", default=None)
    wb.set_defaults(fn=envelope_run, target=wallet_balance)
    ws = w.add_parser("send")
    ws.add_argument("--chain", required=True)
    ws.add_argument("--identity", required=True)
    ws.add_argument("--label", default="first")
    ws.add_argument("--to", required=True)
    ws.add_argument("--amount", type=float, required=True)
    ws.add_argument("--data", default="")
    ws.add_argument("--broadcast", action="store_true")
    ws.set_defaults(fn=envelope_run, target=wallet_send)
    wso = w.add_parser("sol-send")
    wso.add_argument("--chain", required=True)
    wso.add_argument("--identity", required=True)
    wso.add_argument("--label", default="first")
    wso.add_argument("--to", required=True)
    wso.add_argument("--amount", type=float, required=True)
    wso.add_argument("--broadcast", action="store_true")
    wso.set_defaults(fn=envelope_run, target=wallet_sol_send)
    wi = w.add_parser("import")
    wi.add_argument("--identity", required=True)
    wi.add_argument("--chain", default="evm", choices=["evm", "sol"])
    wi.add_argument("--secret", required=True)
    wi.add_argument("--mnemonic", action="store_true")
    wi.add_argument("--count", type=int, default=1)
    wi.set_defaults(fn=envelope_run, target=wallet_import)
    wa = w.add_parser("approve")
    wa.add_argument("--chain", required=True)
    wa.add_argument("--identity", required=True)
    wa.add_argument("--label", default="first")
    wa.add_argument("--token", required=True)
    wa.add_argument("--spender", required=True)
    wa.add_argument("--amount", type=float, default=0)
    wa.add_argument("--unlimited", action="store_true")
    wa.add_argument("--broadcast", action="store_true")
    wa.set_defaults(fn=envelope_run, target=wallet_approve)

    si = sub.add_parser("sign").add_subparsers(dest="s_cmd", required=True)
    sm = si.add_parser("message")
    sm.add_argument("--identity", required=True)
    sm.add_argument("--label", default="first")
    sm.add_argument("--message", required=True)
    sm.add_argument("--origin", default="")
    sm.set_defaults(fn=envelope_run, target=sign_message)
    stp = si.add_parser("typed")
    stp.add_argument("--identity", required=True)
    stp.add_argument("--label", default="first")
    stp.add_argument("--json", default="{}")
    stp.add_argument("--file", default="")
    stp.set_defaults(fn=envelope_run, target=sign_typed)

    e = sub.add_parser("email").add_subparsers(dest="e_cmd", required=True)
    ea = e.add_parser("add")
    ea.add_argument("--identity", required=True)
    ea.add_argument("--address", required=True)
    ea.add_argument("--password", required=True)
    ea.add_argument("--host", default="imap.gmail.com")
    ea.add_argument("--port", type=int, default=993)
    ea.set_defaults(fn=envelope_run, target=email_add)
    eo = e.add_parser("otp")
    eo.add_argument("--identity", default="")
    eo.add_argument("--sender", default="")
    eo.add_argument("--subject", default="")
    eo.add_argument("--timeout", type=int, default=180)
    eo.set_defaults(fn=envelope_run, target=email_otp)
    el = e.add_parser("link")
    el.add_argument("--identity", default="")
    el.add_argument("--sender", default="")
    el.add_argument("--timeout", type=int, default=180)
    el.set_defaults(fn=envelope_run, target=email_link)
    eg = e.add_parser("gmail-login")
    eg.add_argument("--identity", required=True)
    eg.add_argument("--address", required=True)
    eg.add_argument("--password", required=True)
    eg.add_argument("--totp", default="")
    eg.set_defaults(fn=envelope_run, target=lambda identity, address, password, totp="":
                    (_asec(__import__("aa.email.gmail", fromlist=["login"]).login(identity, address, password, totp)), []))
    es = e.add_parser("gmail-signup")
    es.add_argument("--identity", required=True)
    es.add_argument("--first", required=True)
    es.add_argument("--last", required=True)
    es.add_argument("--username", required=True)
    es.add_argument("--password", required=True)
    es.set_defaults(fn=envelope_run, target=lambda identity, first, last, username, password:
                    (_asec(__import__("aa.email.gmail", fromlist=["signup"]).signup(identity, first, last, username, password)), []))

    t = sub.add_parser("tg").add_subparsers(dest="tg_cmd", required=True)
    tl = t.add_parser("login")
    tl.add_argument("--identity", required=True)
    tl.add_argument("--phone", required=True)
    tl.set_defaults(fn=envelope_run, target=tg_login)
    tv = t.add_parser("verify")
    tv.add_argument("--identity", required=True)
    tv.add_argument("--code", required=True)
    tv.add_argument("--password", default="")
    tv.set_defaults(fn=envelope_run, target=tg_verify)

    def tgcmd(name, **kwargs):
        sp = t.add_parser(name)
        sp.add_argument("--identity", default="")
        sp.set_defaults(fn=envelope_run, target=tg, tg_cmd=name, **kwargs)

    tgcmd("me")
    tj = t.add_parser("join")
    tj.add_argument("target")
    tj.add_argument("--identity", default="")
    tj.set_defaults(fn=envelope_run, target=tg, tg_cmd="join")
    tf = t.add_parser("follow")
    tf.add_argument("targets", nargs="+")
    tf.add_argument("--identity", default="")
    tf.set_defaults(fn=envelope_run, target=tg, tg_cmd="follow")

    xp = sub.add_parser("x").add_subparsers(dest="x_cmd", required=True)
    xl = xp.add_parser("login")
    xl.add_argument("--identity", required=True)
    xl.add_argument("--user", required=True)
    xl.add_argument("--password", required=True)
    xl.add_argument("--totp", default="")
    xl.set_defaults(fn=envelope_run, target=x_cmd)
    xs = xp.add_parser("status")
    xs.add_argument("--identity", required=True)
    xs.set_defaults(fn=envelope_run, target=x_cmd)
    xf = xp.add_parser("follow")
    xf.add_argument("handles", nargs="+")
    xf.add_argument("--identity", required=True)
    xf.set_defaults(fn=envelope_run, target=x_cmd)
    xu = xp.add_parser("unfollow")
    xu.add_argument("handles", nargs="+")
    xu.add_argument("--identity", required=True)
    xu.set_defaults(fn=envelope_run, target=x_cmd)
    xt = xp.add_parser("post")
    xt.add_argument("text")
    xt.add_argument("--identity", required=True)
    xt.add_argument("--reply", default="")
    xt.set_defaults(fn=envelope_run, target=x_cmd)
    xk = xp.add_parser("like")
    xk.add_argument("url")
    xk.add_argument("--identity", required=True)
    xk.set_defaults(fn=envelope_run, target=x_cmd)
    xr = xp.add_parser("repost")
    xr.add_argument("url")
    xr.add_argument("--identity", required=True)
    xr.set_defaults(fn=envelope_run, target=x_cmd)
    xq = xp.add_parser("search")
    xq.add_argument("query")
    xq.add_argument("--identity", required=True)
    xq.add_argument("--limit", type=int, default=15)
    xq.set_defaults(fn=envelope_run, target=x_cmd)
    xtl = xp.add_parser("timeline")
    xtl.add_argument("handles", nargs="+")
    xtl.add_argument("--limit", type=int, default=10)
    xtl.set_defaults(fn=envelope_run, target=x_cmd)

    d = sub.add_parser("dc").add_subparsers(dest="dc_cmd", required=True)
    dl = d.add_parser("login")
    dl.add_argument("--identity", required=True)
    dl.add_argument("--email", required=True)
    dl.add_argument("--password", required=True)
    dl.add_argument("--totp", default="")
    dl.set_defaults(fn=envelope_run, target=dc)

    def dcmd(name, **kw):
        sp = d.add_parser(name)
        sp.add_argument("--identity", required=True)
        sp.set_defaults(fn=envelope_run, target=dc, dc_cmd=name, **kw)

    dcmd("status")
    dcmd("servers")
    dcmd("progress")
    dch = d.add_parser("channels")
    dch.add_argument("--identity", required=True)
    dch.add_argument("--server", required=True)
    dch.set_defaults(fn=envelope_run, target=dc, dc_cmd="channels")
    df = d.add_parser("follow")
    df.add_argument("--identity", required=True)
    df.add_argument("--channel", required=True)
    df.set_defaults(fn=envelope_run, target=dc, dc_cmd="follow")
    dg = d.add_parser("grind")
    dg.add_argument("--identity", required=True)
    dg.add_argument("--server", required=True)
    dg.add_argument("--minutes", type=int, default=30)
    dg.add_argument("--max", type=int, default=0)
    dg.add_argument("--persona", default="")
    dg.set_defaults(fn=envelope_run, target=dc, dc_cmd="grind")
    dr = d.add_parser("read")
    dr.add_argument("--identity", required=True)
    dr.add_argument("--channel", required=True)
    dr.add_argument("--limit", type=int, default=20)
    dr.set_defaults(fn=envelope_run, target=dc, dc_cmd="read")
    ds = d.add_parser("send")
    ds.add_argument("--identity", required=True)
    ds.add_argument("--channel", required=True)
    ds.add_argument("--text", required=True)
    ds.set_defaults(fn=envelope_run, target=dc, dc_cmd="send")
    drc = d.add_parser("react")
    drc.add_argument("--identity", required=True)
    drc.add_argument("--channel", required=True)
    drc.add_argument("--message-id", required=True)
    drc.add_argument("--emoji", default="👍")
    drc.set_defaults(fn=envelope_run, target=dc, dc_cmd="react")

    q = sub.add_parser("quest").add_subparsers(dest="quest_cmd", required=True)
    qn = q.add_parser("new")
    qn.add_argument("name")
    qn.add_argument("url")
    qn.add_argument("--platform", default="generic")
    qn.add_argument("--chain", default="")
    qn.set_defaults(fn=envelope_run, target=quest_cmd)
    qi = q.add_parser("import")
    qi.add_argument("file")
    qi.set_defaults(fn=envelope_run, target=quest_cmd)
    qli = q.add_parser("list")
    qli.add_argument("--status", default=None)
    qli.set_defaults(fn=envelope_run, target=quest_cmd)
    qs = q.add_parser("show")
    qs.add_argument("quest")
    qs.set_defaults(fn=envelope_run, target=quest_cmd)
    qv = q.add_parser("validate")
    qv.add_argument("quest")
    qv.set_defaults(fn=envelope_run, target=quest_cmd)
    qd = q.add_parser("due")
    qd.set_defaults(fn=envelope_run, target=quest_cmd)
    qrm = q.add_parser("remove")
    qrm.add_argument("quest")
    qrm.set_defaults(fn=envelope_run, target=quest_cmd)
    qpr = q.add_parser("probe")
    qpr.add_argument("url")
    qpr.add_argument("--identity", default="")
    qpr.set_defaults(fn=envelope_run, target=quest_cmd)
    qr = q.add_parser("run")
    qr.add_argument("quest")
    qr.add_argument("--identity", default="")
    qr.add_argument("--dry", action="store_true")
    qr.add_argument("--headful", action="store_true")
    qr.set_defaults(fn=envelope_run, target=quest_cmd)

    tn = sub.add_parser("testnet").add_subparsers(dest="t_cmd", required=True)
    tn.add_parser("status").set_defaults(fn=envelope_run, target=testnet)
    tf = tn.add_parser("faucets")
    tf.add_argument("--chain", required=True)
    tf.set_defaults(fn=envelope_run, target=testnet)
    tc = tn.add_parser("claim")
    tc.add_argument("--chain", required=True)
    tc.add_argument("--identity", required=True)
    tc.add_argument("--name", default="")
    tc.set_defaults(fn=envelope_run, target=testnet)
    td = tn.add_parser("deploy")
    td.add_argument("--chain", required=True)
    td.add_argument("--identity", required=True)
    td.add_argument("--kind", default="counter", choices=["counter", "erc20", "erc721"])
    td.set_defaults(fn=envelope_run, target=testnet)
    tcp = tn.add_parser("campaign")
    tcp.add_argument("--chain", required=True)
    tcp.add_argument("--identity", required=True)
    tcp.add_argument("--name", default="daily")
    tcp.add_argument("--rounds", type=int, default=1)
    tcp.set_defaults(fn=envelope_run, target=testnet)
    te = tn.add_parser("estimate")
    te.add_argument("--chain", required=True)
    te.add_argument("--name", default="daily")
    te.set_defaults(fn=envelope_run, target=testnet)

    dl2 = sub.add_parser("daily").add_subparsers(dest="d_cmd", required=True)
    dl2.add_parser("status").set_defaults(fn=envelope_run, target=daily_cmd)
    dp = dl2.add_parser("plan")
    dp.add_argument("--identity", required=True)
    dp.set_defaults(fn=envelope_run, target=daily_cmd)
    dr2 = dl2.add_parser("run")
    dr2.add_argument("--identity", default="")
    dr2.add_argument("--all", action="store_true")
    dr2.set_defaults(fn=envelope_run, target=daily_cmd)

    r = sub.add_parser("radar").add_subparsers(dest="r_cmd", required=True)
    rs = r.add_parser("scan")
    rs.add_argument("--identity", required=True)
    rs.add_argument("--no-x", action="store_true")
    rs.add_argument("--no-tg", action="store_true")
    rs.set_defaults(fn=envelope_run, target=radar_cmd)
    rl = r.add_parser("latest")
    rl.add_argument("--limit", type=int, default=20)
    rl.add_argument("--min-score", type=int, default=0)
    rl.set_defaults(fn=envelope_run, target=radar_cmd)
    r.add_parser("kinds").set_defaults(fn=envelope_run, target=radar_cmd)
    rc = r.add_parser("clear")
    rc.add_argument("--status", default="new")
    rc.set_defaults(fn=envelope_run, target=radar_cmd)
    r.add_parser("sources").set_defaults(fn=envelope_run, target=radar_cmd)
    ra = r.add_parser("add")
    ra.add_argument("kind", choices=["tg", "x", "query"])
    ra.add_argument("target")
    ra.add_argument("--trust", type=int, default=1)
    ra.set_defaults(fn=envelope_run, target=radar_cmd)
    rr = r.add_parser("rm")
    rr.add_argument("kind", choices=["tg", "x", "query"])
    rr.add_argument("target")
    rr.set_defaults(fn=envelope_run, target=radar_cmd)

    ap = sub.add_parser("autopilot").add_subparsers(dest="a_cmd", required=True)
    ap.add_parser("plan").set_defaults(fn=envelope_run, target=autopilot_cmd)
    ap.add_parser("status").set_defaults(fn=envelope_run, target=autopilot_cmd)
    apt = ap.add_parser("tick")
    apt.add_argument("--headful", action="store_true")
    apt.set_defaults(fn=envelope_run, target=autopilot_cmd)
    apr = ap.add_parser("run")
    apr.add_argument("--minutes", type=int, default=60)
    apr.add_argument("--headful", action="store_true")
    apr.set_defaults(fn=envelope_run, target=autopilot_cmd)
    apd = ap.add_parser("daemon")
    apd.add_argument("--headful", action="store_true")
    apd.set_defaults(fn=envelope_run, target=autopilot_cmd)


    cf = sub.add_parser("cf").add_subparsers(dest="cf_cmd", required=True)
    cfs = cf.add_parser("status")
    cfs.add_argument("--identity", default="")
    cfs.set_defaults(fn=envelope_run, target=cf_cmd)
    cfa = cf.add_parser("assist")
    cfa.add_argument("--url", required=True)
    cfa.add_argument("--identity", required=True)
    cfa.set_defaults(fn=envelope_run, target=cf_cmd)
    cfc = cf.add_parser("clear")
    cfc.add_argument("--identity", default="")
    cfc.add_argument("--host", default="")
    cfc.set_defaults(fn=envelope_run, target=cf_cmd)

    so = sub.add_parser("social").add_subparsers(dest="s_cmd", required=True)
    sol = so.add_parser("login")
    sol.add_argument("platform", choices=["x", "discord", "telegram", "gmail", "google"])
    sol.add_argument("--identity", required=True)
    sol.add_argument("--user", required=True)
    sol.add_argument("--password", default="")
    sol.add_argument("--totp", default="")
    sol.set_defaults(fn=envelope_run, target=social_cmd)
    for name in ("check", "warm"):
        sp = so.add_parser(name)
        sp.add_argument("platform", choices=["x", "discord", "gmail", "google", "telegram"])
        sp.add_argument("--identity", required=True)
        sp.set_defaults(fn=envelope_run, target=social_cmd)
    sos = so.add_parser("status")
    sos.add_argument("--identity", required=True)
    sos.set_defaults(fn=envelope_run, target=social_cmd)

    se = sub.add_parser("session").add_subparsers(dest="sn_cmd", required=True)
    for name in ("status", "save", "restore", "warm", "check"):
        sp = se.add_parser(name)
        sp.add_argument("--identity", required=True)
        if name == "check":
            sp.add_argument("--platforms", nargs="+", default=["x", "discord"])
        sp.set_defaults(fn=envelope_run, target=session_cmd)

    ex = sub.add_parser("ext").add_subparsers(dest="e2_cmd", required=True)
    ex.add_parser("list").set_defaults(fn=envelope_run, target=ext, e_cmd="list")
    for name in ("install", "remove"):
        sp = ex.add_parser(name)
        sp.add_argument("name")
        sp.add_argument("--identity", required=True)
        sp.set_defaults(fn=envelope_run, target=ext, e_cmd=name)

    br = sub.add_parser("browser")
    br.add_argument("--identity", required=True)
    br.add_argument("--url", default="")
    br.add_argument("--profile", default="manual")
    br.add_argument("--login", action="store_true")
    br.add_argument("--headful", action="store_true", default=True)
    br.add_argument("--minutes", type=int, default=0)
    br.set_defaults(fn=envelope_run, target=browser)

    v = sub.add_parser("vault").add_subparsers(dest="v_cmd", required=True)
    ve = v.add_parser("export")
    ve.add_argument("file")
    ve.add_argument("--password", default=None)
    ve.set_defaults(fn=envelope_run, target=vault_cmd)
    vi = v.add_parser("import")
    vi.add_argument("file")
    vi.add_argument("--password", required=True)
    vi.set_defaults(fn=envelope_run, target=vault_cmd)
    v.add_parser("count").set_defaults(fn=envelope_run, target=vault_cmd)
    v.add_parser("password").set_defaults(fn=envelope_run, target=vault_cmd)

    m = sub.add_parser("mcp")
    m.add_argument("action", choices=["serve"], nargs="?", default="serve")
    m.set_defaults(fn=lambda: (_mcp(), []), raw=True)

    ev = sub.add_parser("events")
    ev.add_argument("--limit", type=int, default=30)
    ev.add_argument("--kind", default="")
    ev.set_defaults(fn=envelope_run, target=lambda limit, kind: (
        {"events": db.rows("SELECT ts,level,kind,msg FROM events WHERE (?='' OR kind=?) ORDER BY id DESC LIMIT ?",
                           (kind, kind, limit))}, []))
    return p


def _mcp() -> dict:
    from .mcp import server

    server.serve()
    return {"mcp": "stopped"}


def main(argv: list[str] | None = None) -> int:
    parser = build()
    if argv == ["--version"] or (argv is None and "--version" in sys.argv):
        return envelope_run(lambda: ({"version": __version__}, []), argparse.Namespace())
    args = parser.parse_args(argv)
    if getattr(args, "raw", False):
        args.fn()
        return 0
    fn = getattr(args, "fn", None)
    target = getattr(args, "target", None)
    if not fn or not target:
        raise SystemExit("no command")
    return fn(target, args)


if __name__ == "__main__":
    sys.exit(main())
