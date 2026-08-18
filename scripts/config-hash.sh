#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
[[ -f .env ]] || { echo "missing .env; run: cp .env.example .env" >&2; exit 1; }

kind="${1:-}"
path="${2:-}"
[[ "$kind" == "manifest" || "$kind" == "profile" || "$kind" == "policy" ]] || {
  echo "usage: $0 manifest|profile|policy PATH" >&2
  exit 2
}
[[ -f "$path" ]] || { echo "file not found: $path" >&2; exit 1; }
source_directory="$(cd -- "$(dirname -- "$path")" && pwd -P)"
absolute_path="${source_directory}/$(basename -- "$path")"

if [[ "$kind" == "policy" ]]; then
  printf 'sha256:'
  sha256sum "$absolute_path" | cut -d ' ' -f 1
  exit 0
fi

case "$absolute_path" in
  "$project_dir"/*) container_path="/config-hash/${absolute_path#"$project_dir"/}" ;;
  *) echo "path must be inside ${project_dir}" >&2; exit 1 ;;
esac

docker compose run --rm --no-deps \
  -v "${project_dir}:/config-hash:ro" \
  api "${kind}-hash" "$container_path"
