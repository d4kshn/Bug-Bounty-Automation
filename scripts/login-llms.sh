#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
[[ -f .env ]] || { echo "missing .env; run: cp .env.example .env" >&2; exit 1; }

provider="${1:-all}"
case "$provider" in
  codex)
    docker compose --profile llm build codex-worker
    docker compose --profile llm run --rm --no-deps --entrypoint codex \
      codex-worker login --device-auth
    ;;
  claude)
    docker compose --profile llm build claude-worker
    docker compose --profile llm run --rm --no-deps --entrypoint claude \
      claude-worker login
    ;;
  all)
    "$0" codex
    "$0" claude
    ;;
  *)
    echo "usage: $0 [codex|claude|all]" >&2
    exit 2
    ;;
esac
