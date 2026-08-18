#!/usr/bin/env bash
set -Eeuo pipefail

umask 027

readonly APP_NAME="bug-bounty-automation"
readonly SERVICE_USER="bbpipeline"
readonly SERVICE_GROUP="bbpipeline"
readonly INSTALL_ROOT="/opt/${APP_NAME}"
readonly CONFIG_ROOT="/etc/${APP_NAME}"
readonly DATA_ROOT="/var/lib/${APP_NAME}"
readonly LOG_ROOT="/var/log/${APP_NAME}"

DRY_RUN=0
SKIP_DOCKER=0
SKIP_TAILSCALE=0
PULL_IMAGES=0

log() {
  printf '[%s] %s\n' "$APP_NAME" "$*"
}

warn() {
  printf '[%s] WARNING: %s\n' "$APP_NAME" "$*" >&2
}

die() {
  printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: sudo bash ./install.sh [options]

Bootstrap a Debian VPS for the bug bounty automation pipeline. The script
installs host prerequisites and creates protected directories. It does not
deploy services, start scans, open firewall ports, or authenticate Tailscale.

Options:
  --dry-run         Print intended changes without making them
  --skip-docker     Do not install or validate Docker Engine/Compose
  --skip-tailscale  Do not install or validate Tailscale
  --pull-images     Pull images from compose.yml after validating it
  -h, --help        Show this help
USAGE
}

run() {
  if (( DRY_RUN )); then
    printf '[%s] DRY-RUN:' "$APP_NAME"
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --skip-docker)
        SKIP_DOCKER=1
        ;;
      --skip-tailscale)
        SKIP_TAILSCALE=1
        ;;
      --pull-images)
        PULL_IMAGES=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done
}

require_root() {
  if (( ! DRY_RUN )) && (( EUID != 0 )); then
    die "Run this installer as root (for example: sudo bash ./install.sh)."
  fi
}

check_platform() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release."

  # shellcheck disable=SC1091
  . /etc/os-release

  [[ "${ID:-}" == "debian" ]] || die "This installer supports Debian only; detected ${ID:-unknown}."
  [[ -n "${VERSION_ID:-}" ]] || die "Debian VERSION_ID is missing."
  [[ -n "${VERSION_CODENAME:-}" ]] || die "Debian VERSION_CODENAME is missing."

  local major_version="${VERSION_ID%%.*}"
  [[ "$major_version" =~ ^[0-9]+$ ]] || die "Invalid Debian version: ${VERSION_ID}."
  if (( major_version < 12 || major_version > 13 )); then
    die "Supported releases are Debian 12 and 13; detected Debian ${VERSION_ID}."
  fi

  command -v apt-get >/dev/null 2>&1 || die "apt-get is required."
  command -v dpkg >/dev/null 2>&1 || die "dpkg is required."
  command -v systemctl >/dev/null 2>&1 || die "systemd is required on the target VPS."

  DEBIAN_CODENAME="$VERSION_CODENAME"
  export DEBIAN_CODENAME
}

install_base_packages() {
  log "Installing base packages from Debian repositories."
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    openssl
}

write_managed_file() {
  local destination="$1"
  local mode="$2"
  local content="$3"

  if (( DRY_RUN )); then
    log "DRY-RUN: write ${destination} with mode ${mode}"
    return 0
  fi

  local temporary_file
  temporary_file="$(mktemp)"
  printf '%s' "$content" >"$temporary_file"

  if [[ -f "$destination" ]] && cmp -s "$temporary_file" "$destination"; then
    rm -f -- "$temporary_file"
    return 0
  fi

  install -m "$mode" "$temporary_file" "$destination"
  rm -f -- "$temporary_file"
}

download_managed_file() {
  local url="$1"
  local destination="$2"
  local mode="$3"

  if (( DRY_RUN )); then
    log "DRY-RUN: download ${url} to ${destination} with mode ${mode}"
    return 0
  fi

  local temporary_file
  temporary_file="$(mktemp)"
  if ! curl --fail --silent --show-error --location "$url" --output "$temporary_file"; then
    rm -f -- "$temporary_file"
    die "Failed to download ${url}."
  fi
  install -m "$mode" "$temporary_file" "$destination"
  rm -f -- "$temporary_file"
}

package_is_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -qx 'install ok installed'
}

configure_docker_repository() {
  if (( SKIP_DOCKER )); then
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    if package_is_installed docker-ce && docker compose version >/dev/null 2>&1; then
      log "Official Docker Engine and Compose plugin are already installed."
      DOCKER_INSTALL_REQUIRED=0
      export DOCKER_INSTALL_REQUIRED
      return 0
    fi
    die "An existing Docker installation is not the expected docker-ce + Compose plugin. Audit it, then rerun or use --skip-docker."
  fi

  local conflicting_packages=()
  local package
  for package in docker.io docker-compose docker-doc docker-buildx podman-docker containerd runc; do
    if package_is_installed "$package"; then
      conflicting_packages+=("$package")
    fi
  done
  if (( ${#conflicting_packages[@]} > 0 )); then
    die "Conflicting container packages are installed: ${conflicting_packages[*]}. Review and remove them manually before installing Docker CE."
  fi

  run install -d -m 0755 /etc/apt/keyrings
  download_managed_file \
    "https://download.docker.com/linux/debian/gpg" \
    "/etc/apt/keyrings/docker.asc" \
    0644

  local architecture
  architecture="$(dpkg --print-architecture)"
  local docker_sources
  docker_sources="Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${DEBIAN_CODENAME}
Components: stable
Architectures: ${architecture}
Signed-By: /etc/apt/keyrings/docker.asc
"
  write_managed_file /etc/apt/sources.list.d/docker.sources 0644 "$docker_sources"

  DOCKER_INSTALL_REQUIRED=1
  export DOCKER_INSTALL_REQUIRED
}

configure_tailscale_repository() {
  if (( SKIP_TAILSCALE )); then
    return 0
  fi

  if command -v tailscale >/dev/null 2>&1; then
    log "Tailscale is already installed."
    TAILSCALE_INSTALL_REQUIRED=0
    export TAILSCALE_INSTALL_REQUIRED
    return 0
  fi

  run install -d -m 0755 /usr/share/keyrings
  download_managed_file \
    "https://pkgs.tailscale.com/stable/debian/${DEBIAN_CODENAME}.noarmor.gpg" \
    "/usr/share/keyrings/tailscale-archive-keyring.gpg" \
    0644
  download_managed_file \
    "https://pkgs.tailscale.com/stable/debian/${DEBIAN_CODENAME}.tailscale-keyring.list" \
    "/etc/apt/sources.list.d/tailscale.list" \
    0644

  TAILSCALE_INSTALL_REQUIRED=1
  export TAILSCALE_INSTALL_REQUIRED
}

install_platform_packages() {
  if (( ${DOCKER_INSTALL_REQUIRED:-0} == 0 && ${TAILSCALE_INSTALL_REQUIRED:-0} == 0 )); then
    return 0
  fi

  run apt-get update

  if (( ${DOCKER_INSTALL_REQUIRED:-0} )); then
    log "Installing Docker Engine and Compose plugin from Docker's official repository."
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      docker-ce \
      docker-ce-cli \
      containerd.io \
      docker-buildx-plugin \
      docker-compose-plugin
  fi

  if (( ${TAILSCALE_INSTALL_REQUIRED:-0} )); then
    log "Installing Tailscale from its official stable repository."
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale
  fi
}

create_service_layout() {
  log "Creating the service account and protected runtime directories."

  if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    run useradd \
      --system \
      --user-group \
      --home-dir "$DATA_ROOT" \
      --shell /usr/sbin/nologin \
      "$SERVICE_USER"
  elif ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    die "User ${SERVICE_USER} exists but group ${SERVICE_GROUP} does not; resolve this account conflict manually."
  fi

  run install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
  run install -d -o root -g "$SERVICE_GROUP" -m 0750 \
    "$CONFIG_ROOT" \
    "$CONFIG_ROOT/programs" \
    "$CONFIG_ROOT/policies" \
    "$CONFIG_ROOT/secrets"
  run install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 \
    "$DATA_ROOT" \
    "$DATA_ROOT/jobs" \
    "$DATA_ROOT/evidence" \
    "$DATA_ROOT/exports" \
    "$DATA_ROOT/backups" \
    "$LOG_ROOT"
}

warn_on_small_host() {
  local cpu_count memory_kib disk_kib disk_path
  cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '0')"
  memory_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || printf '0')"
  disk_path="$DATA_ROOT"
  [[ -d "$disk_path" ]] || disk_path=/var
  disk_kib="$(df -Pk "$disk_path" | awk 'NR == 2 {print $4}')"

  if [[ "$cpu_count" =~ ^[0-9]+$ ]] && (( cpu_count < 8 )); then
    warn "${cpu_count} CPU cores detected; 8 vCPU is the suggested pilot size."
  fi
  if [[ "$memory_kib" =~ ^[0-9]+$ ]] && (( memory_kib < 16777216 )); then
    warn "Less than 16 GiB RAM detected; concurrent recon containers may need tighter limits."
  fi
  if [[ "$disk_kib" =~ ^[0-9]+$ ]] && (( disk_kib < 104857600 )); then
    warn "Less than 100 GiB free under ${disk_path}; evidence retention may fill the disk."
  fi
}

enable_and_verify_services() {
  if (( DRY_RUN )); then
    (( SKIP_DOCKER )) || log "DRY-RUN: enable and verify docker.service"
    (( SKIP_TAILSCALE )) || log "DRY-RUN: enable and verify tailscaled.service"
    return 0
  fi

  if (( ! SKIP_DOCKER )); then
    systemctl enable --now docker.service
    docker version --format 'Docker Engine: {{.Server.Version}}'
    docker compose version
  fi

  if (( ! SKIP_TAILSCALE )); then
    systemctl enable --now tailscaled.service
    tailscale version
  fi
}

find_compose_file() {
  local script_directory candidate
  script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  for candidate in \
    "$script_directory/compose.yml" \
    "$script_directory/deploy/compose.yml"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

validate_compose() {
  local compose_file
  if ! compose_file="$(find_compose_file)"; then
    if (( PULL_IMAGES )); then
      die "--pull-images was requested, but no compose.yml exists beside the installer or under deploy/."
    fi
    log "No compose.yml is present yet; host bootstrap is complete without deploying pipeline services."
    return 0
  fi

  if (( ! DRY_RUN )) && ! command -v docker >/dev/null 2>&1; then
    die "A compose.yml exists, but Docker is unavailable."
  fi
  log "Validating ${compose_file}."
  run docker compose -f "$compose_file" config --quiet

  if (( PULL_IMAGES )); then
    log "Pulling pinned images without starting services."
    run docker compose -f "$compose_file" pull
  fi
}

print_next_steps() {
  local tailscale_steps
  if (( SKIP_TAILSCALE )); then
    tailscale_steps="  - Tailscale installation was skipped; establish an equivalent private administrative path."
  else
    tailscale_steps="  - Join the private network explicitly: sudo tailscale up
  - Confirm the VPS's private address: tailscale ip -4"
  fi

  cat <<NEXT_STEPS

Host bootstrap finished.

Next steps on the VPS:
${tailscale_steps}
  - From the cloned repository: cp .env.example .env
  - Generate protected runtime secrets: sudo ./scripts/bootstrap-secrets.sh
  - Follow docs/VPS-DEPLOYMENT.md, run the tests, and onboard one canary program.
  - Keep the dashboard/API on localhost or the Tailscale address—not 0.0.0.0.
  - After the pilot build is verified, review and pin external images by digest.

This installer did not start scans, deploy containers, alter firewall rules, add a
human account to the docker group, or make an administrative service public.
NEXT_STEPS
}

main() {
  parse_args "$@"
  require_root
  check_platform

  log "Bootstrapping Debian ${VERSION_ID} (${DEBIAN_CODENAME})."
  install_base_packages
  configure_docker_repository
  configure_tailscale_repository
  install_platform_packages
  create_service_layout
  warn_on_small_host
  enable_and_verify_services
  validate_compose
  print_next_steps
}

main "$@"
