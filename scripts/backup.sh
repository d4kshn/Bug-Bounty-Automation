#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="${1:-/var/lib/bug-bounty-automation/backups/${timestamp}}"

[[ "$destination" == /* ]] || { echo "backup destination must be absolute" >&2; exit 2; }
install -d -m 0700 "$destination"
docker compose exec -T db sh -c \
  'exec pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format custom' \
  >"${destination}/database.dump"

api_container="$(docker compose ps -q api)"
[[ -n "$api_container" ]] || { echo "api container is not running" >&2; exit 1; }
install -d -m 0700 "${destination}/evidence"
docker cp "${api_container}:/data/evidence/." "${destination}/evidence"
cp -a config "${destination}/config"
chmod -R go-rwx "$destination"
echo "backup written to ${destination}; secret files were intentionally excluded"
