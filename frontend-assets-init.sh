#!/bin/sh
# frontend-assets-init.sh
# Copies frontend assets to a shared volume and creates
# symlinks for hash mismatches between SSR and client builds.
set -e

CLIENT_DIR="/app/dist/client"
OUTPUT_DIR="/output"

echo "=== Copying frontend assets ==="
cp -r "${CLIENT_DIR}/." "${OUTPUT_DIR}/"

echo ""
echo "=== Fixing hash mismatches ==="

cd "${OUTPUT_DIR}/assets"

# Scan ALL server JS files for asset references
if [ -d "/app/dist/server" ]; then
  grep -rohE '/assets/[a-zA-Z0-9_-]+\.[a-z]+' /app/dist/server/ | \
    sed 's|/assets/||' | sort -u > /tmp/server-refs.txt || true

  total_refs=$(wc -l < /tmp/server-refs.txt 2>/dev/null || echo 0)
  echo "Found ${total_refs} unique asset references in server code"

  while IFS= read -r asset; do
    if [ -n "$asset" ] && [ ! -f "$asset" ]; then
      # Only fix CSS files — JS mismatches are rare and the wrong symlink
      # breaks more than it fixes. Server-internal files like 'router-*.js'
      # should NOT be symlinked to client assets.
      case "$asset" in
        *.css)
          # Try matching by first word (before first hyphen)
          # 'styles-BHOxIn-4.css' -> 'styles-*.css' (matches styles-DCKp8spY.css)
          first_word=$(echo "$asset" | sed 's/-.*//')
          if [ -n "$first_word" ] && [ "$first_word" != "$asset" ]; then
            pattern="${first_word}-*.${asset##*.}"
            match=$(ls $pattern 2>/dev/null | head -1)
            if [ -n "$match" ] && [ -f "$match" ]; then
              echo "  CSS FIX: $asset -> $(basename "$match")"
              ln -sf "$(basename "$match")" "$asset"
            else
              echo "  CSS MISS: $asset (no matching file found)"
            fi
          fi
          ;;
        *)
          # Skip non-CSS files — they usually exist or are server-internal
          ;;
      esac
    fi
  done < /tmp/server-refs.txt
fi

echo ""
total_files=$(find . -type f | wc -l)
total_links=$(find . -type l | wc -l)
echo "=== Ready: ${total_files} files, ${total_links} symlinks ==="
chmod -R 755 "${OUTPUT_DIR}/"
touch "${OUTPUT_DIR}/.assets-ready"
