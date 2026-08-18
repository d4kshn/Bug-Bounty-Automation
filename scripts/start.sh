#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

with_llm=0
if [[ "${1:-}" == "--with-llm" ]]; then
  with_llm=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--with-llm]" >&2
  exit 2
fi

"${project_dir}/scripts/preflight.sh"
docker compose up -d db api scheduler scanner grafana

if (( with_llm )); then
  docker compose --profile llm up -d codex-worker claude-worker
fi

docker compose ps
echo "services started; no job is created unless an approved manifest has a schedule or you enqueue one"
