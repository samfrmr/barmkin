#!/usr/bin/env bash
set -euo pipefail

# Install Barmkin for Claude Code and/or opencode.
#
# Usage: ./install.sh [claude|opencode|all]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/barmkin"
CONFIG="$SCRIPT_DIR/rules.yaml"
PLUGIN="$SCRIPT_DIR/plugins/barmkin.ts"
SYS_CONF="/etc/barmkin/rules.yaml"

if [[ ! -f "$BINARY" ]]; then
  echo "[barmkin] binary not found at $BINARY - run 'go build' first"
  exit 1
fi

# Binary → ~/.local/bin
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
cp "$BINARY" "$LOCAL_BIN/barmkin"
chmod +x "$LOCAL_BIN/barmkin"
echo "[barmkin] binary → $LOCAL_BIN/barmkin"

# Config → /etc/barmkin/ (authoritative)
if [[ -w "/etc/barmkin" ]] || [[ "$EUID" -eq 0 ]]; then
  mkdir -p /etc/barmkin
  cp "$CONFIG" "$SYS_CONF"
  echo "[barmkin] config → $SYS_CONF"
else
  echo "[barmkin] installing config with sudo..."
  sudo mkdir -p /etc/barmkin
  sudo cp "$CONFIG" "$SYS_CONF"
  echo "[barmkin] config → $SYS_CONF"
fi

# Validate
if "$LOCAL_BIN/barmkin" validate >/dev/null 2>&1; then
  echo "[barmkin] config valid"
else
  echo "[barmkin] WARNING: config validation failed"
fi

install_claude() {
  command -v jq >/dev/null 2>&1 || { echo "[barmkin] error: jq is required (brew install jq / apt install jq)"; exit 1; }

  local settings="$HOME/.claude/settings.json"
  mkdir -p "$(dirname "$settings")"
  [[ -f "$settings" ]] || echo '{}' > "$settings"

  local tmp; tmp=$(mktemp)
  # Merge: remove any existing barmkin entry by command path, then append.
  # This preserves other PreToolUse hooks instead of overwriting them.
  jq --arg bin "$LOCAL_BIN/barmkin" '
    .hooks = ((.hooks // {}) |
      .PreToolUse = (
        (.PreToolUse // [])
        | map(select(.hooks[0].command != $bin))
        + [{"matcher":"*","hooks":[{"type":"command","command":$bin}]}]
      )
    )
  ' "$settings" > "$tmp" && mv "$tmp" "$settings"
  echo "[barmkin] Claude Code: PreToolUse hook installed"
}

install_opencode() {
  local plugins="$HOME/.config/opencode/plugins"
  mkdir -p "$plugins"
  cp "$PLUGIN" "$plugins/barmkin.ts"

  local config="$HOME/.config/opencode/opencode.json"
  mkdir -p "$(dirname "$config")"
  [[ -f "$config" ]] || echo '{"$schema":"https://opencode.ai/config.json"}' > "$config"

  if ! jq -e '.plugin | index("file:///' + "$plugins/barmkin.ts" + '")' "$config" >/dev/null 2>&1; then
    local tmp; tmp=$(mktemp)
    jq --arg p "file://$plugins/barmkin.ts" '.plugin = ((.plugin // []) + [$p] | unique)' \
      "$config" > "$tmp" && mv "$tmp" "$config"
    echo "[barmkin] opencode: plugin registered"
  else
    echo "[barmkin] opencode: already registered"
  fi
}

case "${1:-all}" in
  claude)   install_claude ;;
  opencode) install_opencode ;;
  all)      install_claude; install_opencode ;;
  *) echo "usage: $0 <claude|opencode|all>"; exit 1 ;;
esac

cat <<EOF

[barmkin] Done.

  Test vectors:   barmkin test
  View stats:     barmkin stats
  Validate:       barmkin validate
  Edit rules:     sudo \$EDITOR /etc/barmkin/rules.yaml
EOF
