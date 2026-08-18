#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
secrets_dir="/etc/bug-bounty-automation/secrets"

if [[ "${1:-}" == "--secrets-dir" ]]; then
  [[ -n "${2:-}" ]] || { echo "--secrets-dir requires a path" >&2; exit 2; }
  secrets_dir="$2"
  shift 2
fi
(( $# == 0 )) || { echo "usage: sudo $0 [--secrets-dir PATH]" >&2; exit 2; }
(( EUID == 0 )) || { echo "run this script with sudo" >&2; exit 1; }

install -d -o root -g root -m 0700 "$secrets_dir"

create_random() {
  local name="$1"
  local path="${secrets_dir}/${name}"
  if [[ -e "$path" ]]; then
    echo "kept existing ${path}"
    return
  fi
  openssl rand -base64 48 >"$path"
  chmod 0600 "$path"
  echo "created ${path}"
}

create_empty() {
  local name="$1"
  local path="${secrets_dir}/${name}"
  if [[ -e "$path" ]]; then
    echo "kept existing ${path}"
    return
  fi
  install -m 0600 /dev/null "$path"
  echo "created empty ${path}; populate it before enabling the integration"
}

create_random postgres_password
create_random grafana_db_password
create_random grafana_admin_password
create_random api_token
create_empty discord_webhook
create_empty github_token
create_empty shodan_api_key
# Leave these empty to use each LLM CLI's subscription login. Populating one switches
# that worker to metered API-key authentication and a stricter sandbox.
create_empty anthropic_api_key
create_empty openai_api_key

headers_path="${secrets_dir}/researcher_headers.json"
if [[ ! -e "$headers_path" ]]; then
  temporary="$(mktemp)"
  printf '{}\n' >"$temporary"
  install -m 0600 "$temporary" "$headers_path"
  rm -f -- "$temporary"
  echo "created ${headers_path}"
else
  echo "kept existing ${headers_path}"
fi

cat <<EOF

Secrets are ready under ${secrets_dir}. Add the Discord webhook, GitHub token,
and Shodan key with a root-only editor. Do not commit or paste them into logs.

anthropic_api_key and openai_api_key are optional and intentionally empty. Leave
them empty to use the subscription logins created by scripts/login-llms.sh.
EOF
