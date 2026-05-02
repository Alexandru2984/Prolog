#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/home/micu/prolog"
BACKUP_DIR="$APP_DIR/data/backups"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/prolog-security-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"
tar -czf "$OUT" \
  --exclude="$APP_DIR/.git" \
  --exclude="$APP_DIR/.env" \
  --exclude="$APP_DIR/logs" \
  --exclude="$APP_DIR/data/backups" \
  --exclude="$APP_DIR/data/exports" \
  --exclude="$APP_DIR/data/uploads" \
  -C "$APP_DIR" .

VERIFY_DIR="$(mktemp -d)"
trap 'rm -rf "$VERIFY_DIR"' EXIT
tar -xzf "$OUT" -C "$VERIFY_DIR"
test -f "$VERIFY_DIR/server.pl"
test -f "$VERIFY_DIR/README.md"
test -d "$VERIFY_DIR/src"
test -d "$VERIFY_DIR/tests"

find "$BACKUP_DIR" -type f -name 'prolog-security-*.tar.gz' -mtime +14 -delete
printf '%s\n' "$OUT"
