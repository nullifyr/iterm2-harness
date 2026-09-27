#!/usr/bin/env bash
# Install a package-aware launcher; keep Python modules OUT of AutoLaunch.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$ROOT/iterm2-harness.py"
TARGET_DIR="$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch"
STATE="${ITERM2_HARNESS_HOME:-$HOME/.iterm2-harness}"
MODE=link
ACTION=install
FORCE=false
fail() { printf '%s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source|--target)
      [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1"
      if [[ "$1" == --source ]]; then SOURCE="$2"; else TARGET_DIR="$2"; fi
      shift 2 ;;
    --copy) MODE=copy; shift ;;
    --link) MODE=link; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    --force) FORCE=true; shift ;;
    -h|--help) printf '%s\n' 'Usage: install.sh [--copy|--link] [--source FILE] [--target DIR] [--force] [--uninstall]'; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done
TARGET="$TARGET_DIR/iterm2-harness.py"
if [[ "$ACTION" == uninstall ]]; then
  if [[ -L "$TARGET" || -f "$TARGET" ]]; then rm -f "$TARGET"; fi
  printf '%s\n' 'AutoLaunch entry removed. Configuration, tokens, logs, and copied runtimes were retained.'
  exit 0
fi
[[ -f "$SOURCE" ]] || fail "Missing source: $SOURCE"
SOURCE_DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
SOURCE="$SOURCE_DIR/$(basename "$SOURCE")"
[[ -d "$SOURCE_DIR/iterm2_harness" ]] || fail 'The iterm2_harness package must be beside the launcher.'
[[ ! -e "$TARGET" || -L "$TARGET" || "$FORCE" == true ]] || fail 'Existing non-symlink launcher: review it, then use --force to replace.'
mkdir -p "$STATE" "$TARGET_DIR"
chmod 700 "$STATE"
if [[ ! -e "$STATE/config.json" && -f "$SOURCE_DIR/config.json" ]]; then
  cp "$SOURCE_DIR/config.json" "$STATE/config.json"
fi
if [[ "$MODE" == copy ]]; then
  STAGE="$(mktemp -d "$STATE/runtime.XXXXXXXX")"
  mkdir "$STAGE/iterm2_harness"
  cp "$SOURCE" "$STAGE/iterm2-harness.py"
  cp "$SOURCE_DIR"/iterm2_harness/*.py "$STAGE/iterm2_harness/"
  chmod +x "$STAGE/iterm2-harness.py"
  SOURCE="$STAGE/iterm2-harness.py"
fi
TEMP="$TARGET_DIR/.harness-link-$$"
trap 'rm -f "$TEMP"' EXIT
ln -s "$SOURCE" "$TEMP"
mv -f "$TEMP" "$TARGET"
printf 'Installed %s\nConfig: %s/config.json\n' "$TARGET" "$STATE"
printf '%s\n' 'Run from iTerm2 > Scripts > AutoLaunch. Restart the harness after upgrading.'
