#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=${IMAGE_NAME:-tier2-lava}
OUT_DIR=${OUT_DIR:-./out}

SCRIPT_DIR=$(cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

echo "[+] Building image $IMAGE_NAME..."
docker build -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_NAME" "$REPO_ROOT"

echo "[+] Extracting artifacts to $OUT_DIR"
container=$(docker create "$IMAGE_NAME")
mkdir -p "$OUT_DIR"
docker cp "$container":/app/vuln_file "$OUT_DIR"/
docker cp "$container":/app/magic.mgc "$OUT_DIR"/
docker rm "$container" >/dev/null

echo "[+] Done. Artifacts: $OUT_DIR/vuln_file, $OUT_DIR/magic.mgc"
