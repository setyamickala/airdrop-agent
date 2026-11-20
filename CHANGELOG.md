# Changelog

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
- MCP stdio server (21 tools), SKILL.md, AGENTS.md router, Hermes/Muse/OpenClaw/Claude adapters.
- 59 offline tests + `aa doctor`.

### Changed
- `null` caps now mean deny; gas is capped pre-sign; simulation precedes every send.
- Domain allowlist is separate from contract allowlist; both editable at runtime.
- Solana lamport math now uses per-chain decimals (9), not 18.

### Security
- Redaction covers literal env secrets as well as structural patterns.
- Vault AAD makes renamed/moved blobs fail closed.
- `eth_sign` blind hashing always gates; drainer verdicts block auto-connect.
