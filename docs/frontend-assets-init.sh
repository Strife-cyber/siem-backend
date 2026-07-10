#!/bin/sh
# ============================================================
#  frontend-assets-init.sh
#  Copies frontend built assets to a shared Docker volume
#  and creates symlinks for any hash mismatches between
#  SSR HTML references and actual file names.
# ============================================================
set -e

CLIENT_DIR="/app/dist/client"
OUTPUT_DIR="/output"

echo "=== Copying frontend assets to shared volume ==="
cp -r "${CLIENT_DIR}/." "${OUTPUT_DIR}/"

echo ""
echo "=== Checking for hash mismatches between SSR and client ==="

# The SSR server.js generates HTML that references hashed assets.
# Sometimes the server build and client build produce different hashes
# for the same asset. We detect this and create symlinks.

cd "${OUTPUT_DIR}/assets"

# Get all asset files referenced in the SSR server code
# (the server might be in a different location depending on build)
SERVER_FILES="/app/dist/server/server.js /app/dist/server/index.js"
for sf in $SERVER_FILES; do
  if [ -f "$sf" ]; then
    echo "Scanning $sf for asset references..."
    # Extract all asset paths referenced in server JS
    # Pattern: assets/[name]-[hash].[ext]
    grep -oE 'assets/[a-zA-Z0-9_-]+\.[a-z]+' "$sf" 2>/dev/null | sort -u > /tmp/server-assets.txt || true
  fi
done

# Also check the actual HTML the SSR would serve (if available)
# and any manifest file
if [ -f "${CLIENT_DIR}/manifest.json" ]; then
  echo "Manifest found, checking..."
  grep -oE '"[^"]*\.(css|js)"' "${CLIENT_DIR}/manifest.json" | tr -d '"' | sed 's|^/||' >> /tmp/server-assets.txt 2>/dev/null || true
fi

sort -u /tmp/server-assets.txt -o /tmp/server-assets.txt 2>/dev/null || true
total_refs=$(wc -l < /tmp/server-assets.txt 2>/dev/null || echo 0)
echo "  Found $total_refs unique asset references"

# For each referenced asset, check if the file exists
missing=0
fixed=0
while IFS= read -r asset; do
  asset_name=$(basename "$asset")
  if [ ! -f "$asset_name" ]; then
    missing=$((missing + 1))
    echo "  MISSING: $asset_name"
    
    # Try to find a matching file by base name (before the hash)
    base=$(echo "$asset_name" | sed 's/-[a-fA-F0-9][a-fA-F0-9]*\.[a-z]*$//')
    ext=".${asset_name##*.}"
    
    # Find existing files matching this base name
    match=$(ls "${base}"-*"${ext}" 2>/dev/null | head -1)
    if [ -n "$match" ] && [ -f "$match" ]; then
      echo "    → Creating symlink: $asset_name -> $match"
      ln -sf "$match" "$asset_name"
      fixed=$((fixed + 1))
    fi
  fi
done < /tmp/server-assets.txt

echo ""
echo "=== Summary ==="
echo "  Total assets referenced: $total_refs"
echo "  Missing from disk: $missing"
echo "  Fixed with symlinks: $fixed"
echo "  Total files in assets/: $(find . -maxdepth 1 -type f | wc -l)"
echo "  Total symlinks: $(find . -maxdepth 1 -type l | wc -l)"

echo ""
echo "=== Assets ready ==="
touch "${OUTPUT_DIR}/.assets-ready"
chmod -R 755 "${OUTPUT_DIR}/"
