#!/usr/bin/env bash
set -euo pipefail

port="${1:-3050}"
while ss -ltn "sport = :$port" | awk 'NR>1 { found=1 } END { exit !found }'; do
  port=$((port + 1))
done
printf '%s\n' "$port"
