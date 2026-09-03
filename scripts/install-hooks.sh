#!/bin/bash
# Installs an OPTIONAL, warn-only pre-push hook that prints the docs drift
# report for the commits you are about to push. It never blocks a push —
# it just tells you now what the PR comment would tell you later.
# Usage (from repo root): ./scripts/install-hooks.sh
set -euo pipefail
HOOK="$(git rev-parse --git-path hooks)/pre-push"
cat > "$HOOK" <<'EOF'
#!/bin/bash
# docs2 drift warning (installed by scripts/install-hooks.sh) — never blocks.
BASE=$(git merge-base origin/develop HEAD 2>/dev/null) || exit 0
REPORT=$(python3 scripts/docs_drift_check.py --base "$BASE" --exit-zero 2>/dev/null) || exit 0
if ! echo "$REPORT" | grep -q '^OK:'; then
  echo ""
  echo "⚠ docs2 drift (warn-only — push continues):"
  echo "$REPORT" | sed 's/^/  /'
  echo "  Fix with the /docs-sync Claude Code skill when ready."
  echo ""
fi
exit 0
EOF
chmod +x "$HOOK"
echo "Installed warn-only pre-push docs-drift hook at $HOOK"
