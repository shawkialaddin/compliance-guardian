#!/usr/bin/env bash
# compliance-guardian installer for Claude Code (user-level / global).
#
#   ./install.sh                 copy skill to ~/.claude/skills/compliance-guardian, add hook + CLAUDE.md pointer
#   ./install.sh --link          symlink instead of copy (for development)
#   ./install.sh --no-hook       do not register the PostToolUse hook
#   ./install.sh --no-claude-md  do not add the global CLAUDE.md pointer
#   ./install.sh --uninstall     remove skill, hook entry and CLAUDE.md block (backups kept)
#
# Installs nothing else: no pip/npm/system packages, no network access.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compliance-guardian"
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
DEST="$CLAUDE_HOME/skills/compliance-guardian"
SETTINGS="$CLAUDE_HOME/settings.json"
CLAUDE_MD="$CLAUDE_HOME/CLAUDE.md"
LINK=0 HOOK=1 CMD=1 UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --link) LINK=1 ;; --no-hook) HOOK=0 ;; --no-claude-md) CMD=0 ;; --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
STAMP="$(date +%Y%m%d%H%M%S)"

edit_settings() {  # $1 = add|remove
  [ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
  cp "$SETTINGS" "$SETTINGS.bak-compliance-guardian-$STAMP"
  python3 - "$SETTINGS" "$1" "$DEST" <<'PY'
import json, sys
path, action, dest = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as fh:
    data = json.load(fh)
marker = "compliance-guardian/scripts/cg.py\" hook"
hooks = data.setdefault("hooks", {})
post = [e for e in hooks.get("PostToolUse", [])
        if not any(marker in h.get("command", "") for h in e.get("hooks", []))]
if action == "add":
    post.append({"matcher": "Write|Edit|MultiEdit",
                 "hooks": [{"type": "command",
                            "command": f"python3 \"{dest}/scripts/cg.py\" hook",
                            "timeout": 15}]})
if post:
    hooks["PostToolUse"] = post
else:
    hooks.pop("PostToolUse", None)
with open(path, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
print(f"settings.json: hook {'registered' if action == 'add' else 'removed'} (backup kept)")
PY
}

edit_claude_md() {  # $1 = add|remove
  touch "$CLAUDE_MD"
  cp "$CLAUDE_MD" "$CLAUDE_MD.bak-compliance-guardian-$STAMP"
  python3 - "$CLAUDE_MD" "$SRC/templates/hooks/CLAUDE.md.snippet" "$1" <<'PY'
import re, sys
path, snippet_path, action = sys.argv[1:4]
text = open(path).read()
text = re.sub(r"\n?<!-- compliance-guardian:start -->.*?<!-- compliance-guardian:end -->\n?", "\n", text, flags=re.S).rstrip()
if action == "add":
    text = (text + "\n\n" if text else "") + open(snippet_path).read().strip()
open(path, "w").write(text + "\n")
print(f"CLAUDE.md: pointer {'added' if action == 'add' else 'removed'} (backup kept)")
PY
}

if [ "$UNINSTALL" = 1 ]; then
  rm -rf "$DEST" && echo "removed $DEST"
  [ -f "$SETTINGS" ] && edit_settings remove
  [ -f "$CLAUDE_MD" ] && edit_claude_md remove
  exit 0
fi

mkdir -p "$CLAUDE_HOME/skills"
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  # keep backups OUTSIDE the skills dir so Claude Code never loads a duplicate skill
  mkdir -p "$CLAUDE_HOME/backups"
  mv "$DEST" "$CLAUDE_HOME/backups/compliance-guardian.skill-$STAMP" && \
    echo "existing install moved to $CLAUDE_HOME/backups/compliance-guardian.skill-$STAMP"
fi
if [ "$LINK" = 1 ]; then
  ln -s "$SRC" "$DEST" && echo "linked $DEST -> $SRC"
else
  mkdir -p "$DEST"
  (cd "$SRC" && tar --exclude='__pycache__' --exclude='.pytest_cache' -cf - .) | (cd "$DEST" && tar -xf -)
  echo "installed to $DEST"
fi
chmod +x "$DEST/scripts/cg.py"

[ "$HOOK" = 1 ] && edit_settings add
[ "$CMD" = 1 ] && edit_claude_md add

python3 -c "import yaml" 2>/dev/null || echo "NOTE: PyYAML missing - install it yourself if desired: python3 -m pip install --user pyyaml"
python3 "$DEST/scripts/cg.py" rules --format json >/dev/null && echo "self-check: scanner loads OK"
echo "Done. In Claude Code: /compliance-guardian (restart running sessions to pick up hooks)."
