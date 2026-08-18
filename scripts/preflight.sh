#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

[[ -f .env ]] || { echo "missing .env; run: cp .env.example .env" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }
docker compose version >/dev/null

secrets_dir="$(sed -n 's/^SECRETS_DIR=//p' .env | tail -n 1)"
secrets_dir="${secrets_dir:-/etc/bug-bounty-automation/secrets}"
case "$secrets_dir" in
  /*) ;;
  *) secrets_dir="${project_dir}/${secrets_dir}" ;;
esac

required=(postgres_password grafana_db_password grafana_admin_password api_token researcher_headers.json)
for name in "${required[@]}"; do
  [[ -s "${secrets_dir}/${name}" ]] || {
    echo "required secret is missing or empty: ${secrets_dir}/${name}" >&2
    exit 1
  }
done

# Compose mounts these as secrets, so each file must exist even while it is empty.
for name in discord_webhook github_token shodan_api_key anthropic_api_key openai_api_key; do
  [[ -e "${secrets_dir}/${name}" ]] || {
    echo "secret file must exist even if empty: ${secrets_dir}/${name}" >&2
    echo "run: sudo ./scripts/bootstrap-secrets.sh" >&2
    exit 1
  }
done

for name in discord_webhook github_token shodan_api_key; do
  [[ -s "${secrets_dir}/${name}" ]] || echo "warning: optional integration is empty: ${name}" >&2
done

for provider in anthropic openai; do
  if [[ -s "${secrets_dir}/${provider}_api_key" ]]; then
    echo "note: ${provider} worker will use metered API-key authentication" >&2
  else
    echo "note: ${provider} worker will use its subscription login" >&2
  fi
done

for variable in API_BIND DASHBOARD_BIND; do
  value="$(sed -n "s/^${variable}=//p" .env | tail -n 1)"
  [[ "$value" != "0.0.0.0" && "$value" != "::" ]] || {
    echo "refusing public administrative bind: ${variable}=${value}" >&2
    exit 1
  }
done

jq empty "${secrets_dir}/researcher_headers.json" >/dev/null
docker compose config --quiet

if [[ "${1:-}" == "--build" ]]; then
  docker compose build api scheduler scanner
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--build]" >&2
  exit 2
fi

echo "preflight passed; no service or scan was started"
