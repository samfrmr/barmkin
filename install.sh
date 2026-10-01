#!/usr/bin/env bash
set -euo pipefail

# Install Barmkin for Claude Code, opencode, and/or GitHub Copilot CLI.
#
# Usage: ./install.sh [claude|opencode|copilot-cli|all]

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

install_copilot_cli() {
  # GitHub Copilot CLI's admin-exclusive hook-registration channel
  # (report.md §5c/§4.5, and the Copilot-scope addendum §2.1): any
  # *.json file dropped in policy.d is read regardless of folder trust
  # or disableAllHooks, the direct analogue of /etc/barmkin/rules.yaml
  # itself. Unlike Claude Code's settings.json (merged in place above),
  # this is a directory of independent files, so barmkin.json is
  # written standalone rather than merged into anything.
  #
  # NOTE: the preToolUse registration schema below is this scout's
  # best-effort reconstruction from GitHub's hooks reference and
  # tutorial (docs.github.com/en/copilot/reference/hooks-reference,
  # .../tutorials/copilot-cli-hooks) - confirming it fires on a real
  # Copilot CLI >= 1.0.66 install is a Phase 0 operator check (see
  # demo/README.md), not verified by this repo's test suite.
  local sys_bin="/usr/local/bin/barmkin"
  local policy_dir="/etc/github-copilot/policy.d"
  local policy_file="$policy_dir/barmkin.json"

  local tmp; tmp=$(mktemp)
  cat > "$tmp" <<JSON
{
  "hooks": {
    "preToolUse": [
      { "command": "$sys_bin eval" }
    ]
  }
}
JSON

  if [[ -w "$policy_dir" ]] || [[ ! -e "$policy_dir" && -w "$(dirname "$policy_dir")" ]] || [[ "$EUID" -eq 0 ]]; then
    mkdir -p "$policy_dir"
    cp "$BINARY" "$sys_bin"
    chmod +x "$sys_bin"
    mv "$tmp" "$policy_file"
  else
    echo "[barmkin] installing Copilot CLI policy.d hook with sudo..."
    sudo mkdir -p "$policy_dir"
    sudo cp "$BINARY" "$sys_bin"
    sudo chmod +x "$sys_bin"
    sudo mv "$tmp" "$policy_file"
  fi
  echo "[barmkin] Copilot CLI: preToolUse hook registered at $policy_file"
  echo "[barmkin]   NOTE: confirm this fires against your fleet's Copilot CLI version (Phase 0) - see demo/README.md"
}

case "${1:-all}" in
  claude)      install_claude ;;
  opencode)    install_opencode ;;
  copilot-cli) install_copilot_cli ;;
  all)         install_claude; install_opencode; install_copilot_cli ;;
  *) echo "usage: $0 <claude|opencode|copilot-cli|all>"; exit 1 ;;
esac

cat <<EOF

[barmkin] Done.

  Test vectors:   barmkin test
  View stats:     barmkin stats
  Validate:       barmkin validate
  Edit rules:     sudo \$EDITOR /etc/barmkin/rules.yaml
EOF
