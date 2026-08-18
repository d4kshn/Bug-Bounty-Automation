#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
[[ -f .env ]] || { echo "missing .env" >&2; exit 1; }

secrets_dir="$(sed -n 's/^SECRETS_DIR=//p' .env | tail -n 1)"
secrets_dir="${secrets_dir:-/etc/bug-bounty-automation/secrets}"
case "$secrets_dir" in
  /*) ;;
  *) secrets_dir="${project_dir}/${secrets_dir}" ;;
esac
api_bind="$(sed -n 's/^API_BIND=//p' .env | tail -n 1)"
api_port="$(sed -n 's/^API_PORT=//p' .env | tail -n 1)"
api_bind="${api_bind:-127.0.0.1}"
api_port="${api_port:-8080}"
token="$(tr -d '\r\n' <"${secrets_dir}/api_token")"

(( $# > 0 )) || { echo "usage: $0 CURL_ARGUMENT..." >&2; exit 2; }
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  "http://${api_bind}:${api_port}$1" "${@:2}"
