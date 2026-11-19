# Changelog

## Unreleased — security & correctness audit

### Fixed
- Gates: `require()` respects the TTL (expired approvals can no longer be resurrected);
  `approve()` rejects expired gates; codes are stored hash-only (no plaintext column) and
  delivered to `~/.airdrop-agent/gates/<id>.code` when no Telegram bot is configured —
  never printed to stdout/logs.
- Policy/send: unlimited approvals and `setApprovalForAll(true)` gate in every mode, as
  documented; nonce uses the `pending` block tag; invalid recipients raise `Denied`.
- Solana bridge: respects the session chain (no silent devnet override); caps check the
  payer's native outflow (pre/post-simulation delta), not the whole balance; `signMessage`
  gates on non-allowlisted origins and in safe mode; gate payloads carry the full tx plus
  SHA-256 (no 4000-char truncation); versioned (v0) transactions supported; multi-signer
  transactions refused.
- Quest runner: `goto` stops on Cloudflare block or scam verdict `bad`; `checkin` failures
  record as fail unless the page shows "already done" evidence; login pre-flight detects
  `post`/`repost` and plain Telegram targets; `tx` amounts convert with Decimal (exact wei)
  and require a chain.
- CF clearance: collision-resistant vault keys (hash of the full host); legacy entries
  stay readable and migrate on save.
- Vault: `overwrite()` is atomic (encrypt → temp → replace); a failed write keeps the old secret.
- DB: day boundaries are UTC (matching event timestamps); connections are closed; schema
  initializes once per process; `add_spend` is atomic under BEGIN IMMEDIATE.
- Browser engine: native browser UA unless `BROWSER_UA` is set; page popups tracked as the
  active page; Windows stale-lock liveness uses OpenProcess, not `os.kill` (which terminates);
  screenshot proofs named with wall-clock epoch.
- Sessions: `restore` reseeds localStorage via origin-matched init scripts, not only cookies.

### Tests
- 37 new regression tests (gates, send pipeline, Solana bridge, runner integrity, CF keys,
  vault atomicity, DB concurrency/UTC, engine, session restore). Suite: 104 passing.


## 4.1.0 — 2026-11

Durability release. Tested against nineteen live quest, testnet and whitelist targets.

### Added
- Cloudflare layer: clearance cache bound to host + UA and sealed in the vault, native Turnstile
  interaction, provider tokens with `action`/`cdata`, FlareSolverr fallback, `aa cf assist/status/clear`.
- One browser profile per identity; `storage_state` mirrored encrypted, restored on start.
- `aa session status/check/warm/save/restore` and `aa social login/check/warm` dispatcher.
- Autopilot `warm` module; quest login pre-flight that parks with `needs_login`.
- `aa quest probe`, `{{url}}`/`{{email}}`/`{{wallet}}` templating, dict form of the `wallet` step.
- Nineteen quests for the tested targets; `docs/TARGETS.md` report, `docs/GUIDE.md`,
  `docs/INTRO.md`, `docs/CLOUDFLARE.md`, `docs/SESSIONS.md`.
- Tests for the detector, clearance cache and session mirror.

### Fixed
- `aa init` now always generates a real vault password instead of leaving a placeholder.
- Chromium stale `SingletonLock` is detected and cleared; launch retries three times.
- Quest soft steps catch any exception, not only `Denied`; `Gate` still aborts.
- Quest `click` no longer demands an exact match; `tx` uses per-chain decimals.
- Faucet claim picks the wallet kind of the chain, not always EVM.
- Autopilot no longer runs daily faucets twice per tick.


## 4.0.0 — 2026-11

Full rewrite. One package, one CLI, one policy engine; every v3 script kept as a shim.

### Added
- Modes `safe|balanced|turbo` with hard blocks that survive turbo.
- Payload-hash approval gates, single-use codes, TTL, Telegram owner commands.
- KILL switch, per-chain caps (native_decimals aware), daily spend ledger, rate windows.
- AES-256-GCM/scrypt vault with AAD binding and encrypted bundle export/import.
- HD wallets (EVM BIP44 + Solana ed25519), mass generation, imports, V3 keystore.
- EIP-1193 and Phantom providers injected into a stealth browser and routed to Python guards.
- SIWE-aware personal/typed signing, Permit/Permit2 detection, unlimited-approval block.
- Telegram (MTProto), X (browser + free syndication reads), Discord (token capture + humanized grind).
- IMAP inbox with OTP/link extraction and safe link filtering; Gmail login/signup assist.
- Quest DSL with validation, dry run, proofs, adapters for five platforms.
- Faucet catalog with cooldowns and label fallback; contract deploy; randomised campaigns.
- Radar: TG/X/web sources, dedupe, scam heuristics, explainable scoring, auto-queued draft quests.
- Daily streaks, autopilot ticker with budgets, systemd/launchd/cron templates.
- MCP stdio server (18 tools), SKILL.md, AGENTS.md router, Hermes/Muse/OpenClaw/Claude adapters.
- 59 offline tests + `aa doctor`.

### Changed
- `null` caps now mean deny; gas is capped pre-sign; simulation precedes every send.
- Domain allowlist is separate from contract allowlist; both editable at runtime.
- Solana lamport math now uses per-chain decimals (9), not 18.

### Security
- Redaction covers literal env secrets as well as structural patterns.
- Vault AAD makes renamed/moved blobs fail closed.
- `eth_sign` blind hashing always gates; drainer verdicts block auto-connect.
