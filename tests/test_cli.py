import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def aa(*args, env=None):
    e = dict(os.environ, PYTHONPATH=ROOT, **(env or {}))
    p = subprocess.run([sys.executable, os.path.join(ROOT, "aa.py"), *args],
                       capture_output=True, text=True, env=e, cwd=ROOT)
    return json.loads(p.stdout or "{}"), p.returncode, p.stderr


def test_version():
    out, rc, _ = aa("--version")
    assert rc == 0


def test_status(home):
    out, rc, _ = aa("status")
    assert rc == 0 and out["ok"]


def test_help_lists_commands():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "aa.py"), "--help"],
                       capture_output=True, text=True, cwd=ROOT)
    for cmd in ("identity", "wallet", "quest", "testnet", "autopilot", "mcp"):
        assert cmd in p.stdout


def test_init_creates_config_and_vault(home):
    out, rc, _ = aa("init", "--random-vault-password")
    assert rc == 0
    assert (home.HOME / "policy.yaml").exists()
    assert "VAULT_PASSWORD=" in (home.HOME / ".env").read_text()
    assert "change-me" not in (home.HOME / ".env").read_text()


def test_identity_then_wallets(home):
    aa("init")
    out, rc, err = aa("identity", "new", "demo", "--wallets", "2")
    assert rc == 0, err
    iid = out["data"]["identity"]
    out, rc, _ = aa("wallet", "list", "--identity", iid)
    assert rc == 0 and len(out["data"]["wallets"]) == 4


def test_unknown_identity(home):
    aa("init")
    out, rc, _ = aa("wallet", "list", "--identity", "nope")
    assert rc == 2 and not out["ok"]


def test_quest_new_and_validate(home):
    aa("init")
    out, rc, _ = aa("quest", "new", "Smoke", "https://example.com")
    assert rc == 0
    assert out["data"]["quest"] == "smoke"
    out, rc, _ = aa("quest", "validate", "smoke")
    assert rc == 0 and out["data"]["valid"]


def test_mcp_handshake(home):
    frames = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aa_status", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "nope"},
    ]
    e = dict(os.environ, PYTHONPATH=ROOT)
    p = subprocess.run([sys.executable, "-m", "aa.mcp.server"], input="\n".join(json.dumps(f) for f in frames),
                       capture_output=True, text=True, env=e, cwd=ROOT)
    out = [json.loads(line) for line in p.stdout.splitlines()]
    assert out[0]["result"]["serverInfo"]["name"] == "airdrop-agent"
    assert len(out[1]["result"]["tools"]) >= 10
    assert json.loads(out[2]["result"]["content"][0]["text"])["version"]
    assert out[3]["error"]["code"] == -32601


def test_kill_with_reason(home):
    """K7: `aa kill "reason"` — the documented form — must parse and record it."""
    aa("init")
    out, rc, _ = aa("kill", "insiden test")
    assert rc == 0, out
    assert out["data"]["kill"] is True
    assert "insiden test" in (home.KILL_FILE.read_text() if home.KILL_FILE.exists() else "")
    out, rc, _ = aa("unkill")
    assert rc == 0 and out["data"]["kill"] is False


def test_allowlist_roundtrip(home):
    aa("init")
    out, rc, _ = aa("allow", "add", "evil.test")
    assert rc == 0
    from aa import policy

    assert policy.domain_ok("evil.test")


# --- Round 4 docs-drift fixes: every corrected doc example must parse. ---
def _parse(argv):
    from aa.cli import build

    return build().parse_args(argv)


def test_docs_tg_read_react_start_parse():
    a = _parse(["tg", "read", "--identity", "main", "@channel", "--limit", "20"])
    assert (a.tg_cmd, a.target, a.limit) == ("read", "@channel", 20)
    a = _parse(["tg", "react", "--identity", "main", "https://t.me/c/1/2", "👍"])
    assert (a.tg_cmd, a.target, a.emoji) == ("react", "https://t.me/c/1/2", "👍")
    a = _parse(["tg", "start", "--identity", "main", "@bot", "--ref", "CODE"])
    assert (a.tg_cmd, a.target, a.ref) == ("start", "@bot", "CODE")


def test_docs_dc_flags_parse():
    a = _parse(["dc", "login", "--identity", "main", "--email", "you@mail", "--password", "x"])
    assert a.email == "you@mail"
    a = _parse(["dc", "follow", "--identity", "main", "--channel", "project"])
    assert a.channel == "project"
    a = _parse(["dc", "grind", "--identity", "main", "--server", "project",
                "--minutes", "30", "--max", "40"])
    assert a.max == 40


def test_docs_daily_status_takes_no_args():
    a = _parse(["daily", "status"])
    assert a.d_cmd == "status"
    assert not hasattr(a, "identity") or a.identity in (None, "")


def test_docs_corrected_wallet_and_vault_commands_parse():
    a = _parse(["sign", "message", "--identity", "main", "--label", "evm-1",
                "--message", "hello"])
    assert a.message == "hello"
    a = _parse(["vault", "export", "~/backup.aa"])
    assert a.v_cmd == "export"
    a = _parse(["vault", "rekey"])
    assert a.v_cmd == "rekey"
    a = _parse(["wallet", "sol-send", "--identity", "main", "--label", "s1",
                "--chain", "solana-devnet",
                "--to", "11111111111111111111111111111111", "--amount", "0.001"])
    assert a.to == "11111111111111111111111111111111"


def test_docs_removed_commands_do_not_parse():
    import pytest

    with pytest.raises(SystemExit):
        _parse(["wallet", "export", "--identity", "main"])
    with pytest.raises(SystemExit):
        _parse(["wallet", "sign", "--identity", "main"])
    with pytest.raises(SystemExit):
        _parse(["migrate"])
