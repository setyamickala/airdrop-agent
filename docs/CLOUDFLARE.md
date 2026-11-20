# Cloudflare and Turnstile

Cloudflare is a session problem disguised as a captcha problem. A challenge solved a minute ago is
usually solved already; hammering it again is what gets an IP flagged. The layer therefore tries
reuse first, interaction second, a solver third (opt-in only), and you last.

## What runs when navigation sees a challenge

```
inject cached clearance (host + UA, TTL)
        │ miss
        ▼
28 s of human behaviour: mouse, scroll, focus, Turnstile click
        │ still challenged
        ▼
provider token (2captcha / anticaptcha) — ONLY when CF_ALLOW_SOLVER=1
        │ disabled, no key, or failure
        ▼
FlareSolverr request.get, cookies imported — ONLY when CF_ALLOW_FLARESOLVERR=1
        │ disabled or nothing configured
        ▼
screenshot + "blocked" + aa cf assist
```

With both opt-ins off (the default), `ensure()` goes straight from the natural
interaction to `blocked` + `aa cf assist`. Nothing is solved automatically.

`goto` never throws for a challenge; it returns `cf: "blocked"` plus a screenshot and a `next`
command. Quest steps that need the page record the block and park.

## Why cache instead of solve every time

`cf_clearance` is bound to the IP and user agent that earned it. Storing it with the UA lets the
next run skip the widget entirely. The cache is per identity and per host in the vault, defaults to
45 minutes (`CF_TTL_MINUTES`), and is dropped when the UA changes. Change proxy → clearance dies,
so keep one residential proxy per identity.

## Commands

```bash
aa cf status                         # cached hosts, age
aa cf assist --identity main --url https://app.example.com/points
aa cf clear --identity main --host app.example.com
```

`assist` opens one visible window on the identity's own profile. Click once, then wait: the cookie
is captured and reused immediately. `CF_ASSIST_SECONDS` (300) is the patience budget.

## Configuration

| key | default | meaning |
|---|---|---|
| `CF_ENABLED` | 1 | master switch |
| `CF_WAIT_SECONDS` | 28 | natural interaction budget |
| `CF_TTL_MINUTES` | 45 | clearance cache life |
| `CF_ASSIST_SECONDS` | 300 | assist window |
| `CF_ALLOW_SOLVER` | 0 (off) | opt-in: allow a captcha-provider token solve in `ensure()` |
| `CF_ALLOW_FLARESOLVERR` | 0 (off) | opt-in: allow FlareSolverr in `ensure()` |
| `CAPTCHA_PROVIDER` | — | `2captcha` or `anticaptcha` |
| `CAPTCHA_API_KEY` | — | provider key |
| `FLARESOLVERR_URL` | — | e.g. `http://127.0.0.1:8191` |

Setting `CAPTCHA_PROVIDER`/`CAPTCHA_API_KEY` or `FLARESOLVERR_URL` alone does
**not** enable solving — the matching `CF_ALLOW_*` flag must also be `1`.
The generic captcha path (`aa/browser/captcha.py`, used by quests for plain
reCAPTCHA/hCaptcha widgets) is separate and is not gated by these flags.

## Risk of enabling the solver / FlareSolverr

Solving a challenge with a third-party token or with FlareSolverr is, from the
target site's point of view, automating a bot check:

- **Account ban:** a solved challenge tied to an identity's session can get
  that account (and its points / wallet link) banned when the site later
  reviews the clearance.
- **Target ToS violation:** most quest/airdrop sites forbid automated or
  assisted challenge solving in their terms; a ban can also void rewards.
- **Fingerprint mismatch:** a token solved from a different IP than the
  browser session is a detectable mismatch that can burn the clearance and
  flag the IP. Since round 4, `_token_solve` passes the identity's proxy
  (`proxy` on the identity row / `BROWSER_PROXY`) to the solver, so the task
  is created with that proxy (anti-captcha `TurnstileTask`, 2captcha `proxy`
  param). With no proxy configured the task stays proxyless and this risk
  still applies.

Only enable these on testnet/throwaway identities, never on an account whose
rewards matter. Prefer `aa cf assist` (one manual click, same profile) and
clearance reuse.

Open item: FlareSolverr still runs without a per-request proxy — its `/v1`
call carries no proxy field, so the clearance it returns comes from the
FlareSolverr server's own IP. To keep it on the identity's IP, run the
FlareSolverr server itself behind that identity's proxy (server-side
configuration, not something this code can set per request).

Provider tokens cost roughly a cent. Turnstile needs `action` and `cdata` for a good score; the
layer reads `data-action` and `data-cdata` from the widget when present.

## Server / headless reality

Headless Chromium is the weakest signal. On a VPS:

1. `BROWSER_HEADLESS=1`
2. only if you accept the risks above: set `CF_ALLOW_SOLVER=1` with a provider
   key, and/or `CF_ALLOW_FLARESOLVERR=1` with `FLARESOLVERR_URL`
3. keep a residential proxy, one per identity
4. run `cf assist` once from a desktop session and copy the vault if you can

## What it does not do

- It does not rotate dozens of free proxies against one host; that burns clearance constantly.
- It does not solve interactive image grids without a provider.
- It cannot reuse clearance across a changed user agent or IP.
