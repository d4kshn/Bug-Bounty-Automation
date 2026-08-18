#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
[[ -f .env ]] || { echo "missing .env; run: cp .env.example .env" >&2; exit 1; }
docker compose --profile test build test
docker compose --profile test run --rm --no-deps test
