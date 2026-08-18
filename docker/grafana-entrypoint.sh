#!/usr/bin/env sh
set -eu

GRAFANA_READER_PASSWORD="$(tr -d '\r\n' </run/secrets/grafana_db_password)"
export GRAFANA_READER_PASSWORD
exec /run.sh
