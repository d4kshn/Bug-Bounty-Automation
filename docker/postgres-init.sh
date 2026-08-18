#!/usr/bin/env bash
set -Eeuo pipefail

reader_password="$(tr -d '\r\n' </run/secrets/grafana_db_password)"
export PGPASSWORD="$(tr -d '\r\n' </run/secrets/postgres_password)"

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=reader_password="$reader_password" \
  --set=database_name="$POSTGRES_DB" \
  --set=database_owner="$POSTGRES_USER" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'grafana_reader', :'reader_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_reader') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', 'grafana_reader', :'reader_password') \gexec
ALTER ROLE grafana_reader SET default_transaction_read_only = on;
SELECT format('GRANT CONNECT ON DATABASE %I TO grafana_reader', :'database_name') \gexec
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader',
  :'database_owner'
) \gexec
SQL
