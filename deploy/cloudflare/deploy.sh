#!/bin/bash
set -e

echo "=== cleaner-code Web — Cloudflare Pages Deploy ==="

cd "$(dirname "$0")"
PROJECT_ROOT="$(cd ../.. && pwd)"

# Copy static files to a build directory
BUILD_DIR="./build"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

cp -r "${PROJECT_ROOT}/web/public/"* "${BUILD_DIR}/"
cp -r "${PROJECT_ROOT}/functions/" "${BUILD_DIR}/functions/"

echo "[1/2] Logging in to Cloudflare..."
# wrangler login  # Run this once manually

echo "[2/2] Deploying to Cloudflare Pages..."
wrangler pages deploy "${BUILD_DIR}" --project-name cleaner-code

echo ""
echo "=== Deployed ==="
echo "Set webhook secret: wrangler pages secret put PADDLE_WEBHOOK_SECRET --project-name cleaner-code"
