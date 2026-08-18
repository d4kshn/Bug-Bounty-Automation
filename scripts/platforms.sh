#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
umask 077

usage() {
  cat >&2 <<'EOF'
usage:
  ./scripts/platforms.sh discover PLATFORM
  ./scripts/platforms.sh enroll PLATFORM REMOTE_IDENTIFIER PROGRAM_ID [SOURCE_ID]
  ./scripts/platforms.sh sync [SOURCE_ID]
  ./scripts/platforms.sh status
  ./scripts/platforms.sh export SOURCE_ID

PLATFORM is hackerone, intigriti, yeswehack, or bugcrowd. Enroll creates only a
small source selector. Sync fetches a non-authoritative candidate; export writes
it below config/candidates/ for review and never overwrites an approved manifest.
EOF
  exit 2
}

(( $# >= 1 )) || usage
action="$1"
shift
tool_runner=(docker compose run --rm --no-TTY --no-deps scanner)
db_runner=(docker compose run --rm --no-TTY scanner)

case "$action" in
  discover)
    (( $# == 1 )) || usage
    "${tool_runner[@]}" platform-discover --platform "$1"
    ;;
  enroll)
    (( $# == 3 || $# == 4 )) || usage
    platform="$1"
    remote="$2"
    program_id="$3"
    source_id="${4:-${platform}-${program_id}}"
    case "$platform" in
      hackerone|intigriti|yeswehack|bugcrowd) ;;
      *) echo "unsupported platform: ${platform}" >&2; exit 2 ;;
    esac
    [[ "$program_id" =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] || {
      echo "PROGRAM_ID must contain 2-64 lowercase letters, digits, _ or -" >&2
      exit 2
    }
    [[ "$source_id" =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] || {
      echo "SOURCE_ID must contain 2-64 lowercase letters, digits, _ or -" >&2
      exit 2
    }
    mkdir -p config/platform-sources
    destination="config/platform-sources/${source_id}.yml"
    [[ ! -e "$destination" ]] || {
      echo "refusing to overwrite ${destination}" >&2
      exit 1
    }
    temporary="$(mktemp)"
    trap 'rm -f -- "$temporary"' EXIT
    "${tool_runner[@]}" platform-source-template \
      --platform "$platform" --remote "$remote" --program "$program_id" \
      --source "$source_id" >"$temporary"
    install -m 0640 "$temporary" "$destination"
    echo "enrolled ${source_id} in ${destination}; no scan is authorized yet"
    "${db_runner[@]}" platform-sync --source "$source_id"
    ;;
  sync)
    (( $# <= 1 )) || usage
    if (( $# == 1 )); then
      "${db_runner[@]}" platform-sync --source "$1"
    else
      "${db_runner[@]}" platform-sync
    fi
    ;;
  status)
    (( $# == 0 )) || usage
    "${db_runner[@]}" platform-candidates
    ;;
  export)
    (( $# == 1 )) || usage
    source_id="$1"
    [[ "$source_id" =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] || {
      echo "invalid SOURCE_ID" >&2
      exit 2
    }
    temporary="$(mktemp)"
    trap 'rm -f -- "$temporary"' EXIT
    "${db_runner[@]}" platform-candidate --source "$source_id" >"$temporary"
    manifest_name="$(jq -r '.manifest_filename' "$temporary")"
    policy_name="$(jq -r '.policy_filename' "$temporary")"
    [[ "$manifest_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
      echo "unsafe manifest filename returned by pipeline" >&2
      exit 1
    }
    [[ "$policy_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
      echo "unsafe policy filename returned by pipeline" >&2
      exit 1
    }
    destination="config/candidates/${source_id}"
    [[ ! -e "$destination" ]] || {
      echo "refusing to overwrite ${destination}; move or remove the reviewed copy" >&2
      exit 1
    }
    mkdir -p "$destination/programs" "$destination/policies"
    jq -r '.manifest_yaml' "$temporary" >"$destination/programs/$manifest_name"
    jq -r '.policy_snapshot' "$temporary" >"$destination/policies/$policy_name"
    chmod 0640 "$destination/programs/$manifest_name" "$destination/policies/$policy_name"
    echo "candidate exported to ${destination}; review it and the live brief before approval"
    ;;
  *) usage ;;
esac
