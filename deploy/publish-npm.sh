#!/bin/bash
set -e

echo "=== cleaner-code — npm Publish ==="

cd "$(dirname "$0")/.."

# Build
echo "[1/3] Building..."
npm run build

# Verify package contents
echo "[2/3] Package contents:"
npm pack --dry-run 2>&1 | head -30

echo ""
echo "[3/3] Publishing..."
# npm login  # Run this once manually
npm publish --access public

echo ""
echo "=== Published ==="
echo "Install: npx cleaner-code"
echo "MCP config:"
echo '  { "command": "npx", "args": ["-y", "cleaner-code"] }'
