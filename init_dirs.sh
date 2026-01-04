#!/usr/bin/env bash
set -euo pipefail

echo ">>> Initializing onion-search-starter folder structure …"

# Basisverzeichnis: dort, wo dieses Skript liegt
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verzeichnisse, die im Repo vorhanden / benutzt werden sollen
DIRS=(
  "analyst"
  "crawler"
  "dashboards"
  "data_copy"
  "data"
  "neo4j-conf"
  "renderer"
  "tools"
  "tor"
)

for d in "${DIRS[@]}"; do
  if [ ! -d "$BASE_DIR/$d" ]; then
    echo "  - creating directory: $d"
    mkdir -p "$BASE_DIR/$d"
  else
    echo "  - directory already exists: $d"
  fi
done

# Mindest-Dateien für Bind-Mounts (werden in docker-compose als :ro gemountet)
SEEDS_FILE="$BASE_DIR/crawler/seeds.txt"
FORUMS_FILE="$BASE_DIR/crawler/forums.yaml"

if [ ! -f "$SEEDS_FILE" ]; then
  echo "  - creating example seeds.txt"
  mkdir -p "$(dirname "$SEEDS_FILE")"
  cat > "$SEEDS_FILE" <<'EOF'
# Example seeds for the crawler
# Add one URL or .onion per line, e.g.:
# http://exampleonion1234567890abcdef.onion/
EOF
fi

if [ ! -f "$FORUMS_FILE" ]; then
  echo "  - creating example forums.yaml"
  mkdir -p "$(dirname "$FORUMS_FILE")"
  cat > "$FORUMS_FILE" <<'EOF'
# Example forums.yaml
# Here you can later define forum parsers / selectors.
forums: []
EOF
fi

echo ">>> Done. You can now run:  docker compose up -d"
