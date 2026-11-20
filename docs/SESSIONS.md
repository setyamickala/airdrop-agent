# Sessions

Miners and check-in pages log you out when the browser forgets who you are. Two things caused it
before 4.1: a fresh profile per module, and no activity between runs. Both are fixed.

## One profile per identity

Every module (X, Discord, mail, faucets, quests, manual browser) now opens the same persistent
profile: `~/.airdrop-agent/browser/<identity>/main`. Cookies, localStorage and the service-worker
state all live there. A quest can land on a page you logged into yesterday and stay logged in.

`BROWSER_SEPARATE_PROFILES=1` restores the old isolation if you need it. `BROWSER_PROFILE` picks a
different named profile.

## Encrypted state mirror

On close, `storage_state` (cookies + origins) is sealed into the vault (`SESSION_AUTOSAVE`). On
start it is restored (`SESSION_RESTORE`), valid for `SESSION_STATE_DAYS` (default 14 days). A wiped profile comes
back without a re-login.

`session restore` exists for the case where the profile directory is gone but the vault is not.
`session save` forces a snapshot before a risky upgrade.

## Profile files sealed at rest

The live Chromium profile still needs its session files on disk in plaintext while the browser
runs. When the browser closes, the engine seals `Cookies`, `Login Data`, `Web Data` and the
`Local Storage` / `Session Storage` directories into the vault (AES-256-GCM under the vault
password, kind `profiles`) and deletes the plaintext originals; the next launch unseals them
just before Playwright starts (`aa/browser/profile_crypto.py`, `AA_PROFILE_ENCRYPT=0` opts out).

Limits: only those files/directories are sealed — history, cache and service-worker storage stay
plaintext on disk, and the profile is plaintext while the browser runs. Sealing refuses while
Chromium is actually running (live `SingletonLock`), so it never deletes a profile in use. This
protects a stolen disk or a backup, not a live attacker on the machine.

## Warm-up

Idle sessions rot. `warm` scrolls a real page a few times with human pauses, which is enough to
refresh rolling cookies. It runs:

- automatically every four hours in autopilot (`warm_min`);
- on demand with `aa session warm --identity main`;
- implicitly before quest social steps, via `session.ensure`.

`aa session check` answers `ok | logged_out | challenge` per platform, so a host can branch without
guessing.

## Login pre-flight

A quest containing `follow`, `join`, `like`, `retweet` or a Discord step checks the platform first.
Logged out → the run parks with `needs_login`, writes a parked run row, and returns:

```json
{"parked": true, "needs_login": "x", "next": ["aa social login x --identity main"]}
```

Autopilot skips that quest for six hours so it does not burn the queue.

## Commands

```bash
aa session status --identity main
aa session check --identity main --platforms x discord gmail
aa session warm --identity main
aa session save --identity main
aa session restore --identity main
aa social login x --identity main --user … --password … --totp …
```

## Profile locks

Chromium writes `SingletonLock` and refuses to start if a killed instance left it. The engine reads
the pid from the lock, clears it when the process is dead, and retries the launch three times with
a short delay. If it still fails, delete `browser/<identity>/main/Singleton*` and retry.

## Practical rules

- Keep one identity = one proxy. A new IP invalidates more than Cloudflare.
- Do not run two browsers on the same identity at once; the profile is a single-writer resource.
- Warm before a big run, not during it.
- Back up the vault, not the profile; `session restore` is the rebuild path.
