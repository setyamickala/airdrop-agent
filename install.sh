#!/usr/bin/env bash
# airdrop-agent v4 installer — macOS + Linux. Non-interactive unless it must ask.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL=0
BROWSER=1
SERVICE=""
PY="${PYTHON:-python3}"

usage() {
  cat <<'EOF'
usage: ./install.sh [--full] [--no-browser] [--service=systemd|launchd|none]

  --full           install every optional extra (browser, solana, discord, dev)
  --no-browser     skip the Chromium download
  --service=X      register the autopilot service after install
EOF
}

for arg in "$@"; do
  case "$arg" in
    --full) FULL=1 ;;
    --no-browser) BROWSER=0 ;;
    --service=*) SERVICE="${arg#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $arg"; usage; exit 2 ;;
  esac
done

say() { printf '\033[1m→ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || [ "$(uname -s)" = "Linux" ] || die "only macOS and Linux are supported"
command -v "$PY" >/dev/null || die "python3 not found"

"$PY" - <<'EOF' || die "python 3.10+ required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
EOF

say "creating venv (this stays local to $REPO)"
"$PY" -m venv "$REPO/.venv"
VPY="$REPO/.venv/bin/python"
"$VPY" -m pip install -q --upgrade pip setuptools wheel
[ "$FULL" = "1" ] && EXTRAS="[full,browser]" || { [ "$BROWSER" = "1" ] && EXTRAS="[browser]" || EXTRAS=""; }
say "installing package + dependencies"
"$VPY" -m pip install -q -e "$REPO$EXTRAS"

if [ "$BROWSER" = "1" ]; then
  say "downloading chromium"
  "$VPY" -m playwright install chromium || die "browser download failed (rerun with --no-browser to skip)"
fi

say "initialising ~/.airdrop-agent"
AIRDROP_HOME="${AIRDROP_HOME:-$HOME/.airdrop-agent}" "$VPY" -m aa init --random-vault-password

case "$SERVICE" in
  systemd)
    command -v systemctl >/dev/null || die "systemd not found"
    UNIT="$HOME/.config/systemd/user/airdrop-agent.service"
    mkdir -p "$(dirname "$UNIT")"
    sed -e "s|__REPO__|$REPO|g" -e "s|__HOME__|$HOME|g" \
      "$REPO/templates/systemd/airdrop-agent.service" > "$UNIT"
    systemctl --user daemon-reload
    systemctl --user enable --now airdrop-agent.service
    say "systemd unit installed: $UNIT"
    ;;
  launchd)
    [ "$(uname -s)" = "Darwin" ] || die "launchd is macOS only"
    PLIST="$HOME/Library/LaunchAgents/com.airdrop-agent.plist"
    mkdir -p "$(dirname "$PLIST")"
    sed -e "s|__REPO__|$REPO|g" -e "s|__HOME__|$HOME|g" \
      "$REPO/templates/launchd/com.airdrop-agent.plist" > "$PLIST"
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load -w "$PLIST"
    say "launchd agent installed: $PLIST"
    ;;
  ""|none) say "no service registered" ;;
  *) die "unknown service: $SERVICE" ;;
esac

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$REPO/.venv/bin/aa" "$BIN_DIR/aa"
say "linked $BIN_DIR/aa"

cat <<EOF

selesai. langkah berikutnya:
  1. ${EDITOR:-vi} ~/.airdrop-agent/.env    (RPC, Telegram, email — lihat config/env.example)
  2. $BIN_DIR/aa doctor
  3. $BIN_DIR/aa identity new main --wallets 3
  4. $BIN_DIR/aa mode balanced

pastikan $BIN_DIR ada di PATH. backup frasa vault (~/.airdrop-agent/.env).
EOF
