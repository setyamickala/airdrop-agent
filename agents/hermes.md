# Hermes adapter

Hermes is shell-first, so it uses the binary directly. The H-routes map onto commands as follows.

| route | topic | command |
|---|---|---|
| H1 | swap/sell | `aa wallet send` / quest `tx` step (swap calldata) |
| H2 | bridge | quest `tx` step toward bridge contract |
| H3 | defi | `aa quest run` with a project quest |
| H4 | sniping | `aa radar scan` + `aa quest run` |
| H5 | monitoring | `aa radar latest`, `aa events` |
| H6 | NFT | `aa quest new ... --platform generic`, mint step |
| H7 | SIWE/typed | `aa sign typed --file payload.json` |
| H8 | browser | `aa browser --identity <id> --url <u>` |
| H9 | contract read/write | quest `tx` steps (`eval` was removed — arbitrary JS is no longer allowed) |
| H10 | deploy | `aa testnet deploy --kind erc20` |

## Env checklist

```
AIRDROP_HOME, VAULT_PASSWORD, AA_MODE
RPC_* (or keep public defaults), TG_API_ID/HASH, IMAP_*, X_BEARER_TOKEN
CAPTCHA_API_KEY (optional), GRIND_LLM_API_KEY (optional)
```

## Governor parity

Hermes' `governor.py` lives outside this repo. Do not skip it: keep `aa` caps in sync with the
governor (same max_tx/max_daily), or Hermes will approve what `aa` blocks. `aa` still runs its own
simulate → cap → gate chain regardless.

## Rules

- Call `aa doctor --offline` on session boot; full `aa doctor` before funded work.
- Never pass `--broadcast` until the dry summary is sane.
- Exit `10` is not an error: surface the gate id and wait.
- H-routes that only read (H5) never need a gate; keep them read-only.
