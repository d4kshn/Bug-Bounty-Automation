ARG BBOT_BASE_IMAGE=blacklanternsecurity/bbot:stable-full
FROM golang:1.24-bookworm AS bbscope-builder

ARG BBSCOPE_COMMIT=1e2b837c30789a20784b4fbad3dd09e0ea8e481e
RUN git clone https://github.com/sw33tLie/bbscope.git /src/bbscope \
    && git -C /src/bbscope checkout --detach "${BBSCOPE_COMMIT}" \
    && test "$(git -C /src/bbscope rev-parse HEAD)" = "${BBSCOPE_COMMIT}"
WORKDIR /src/bbscope
COPY docker/bbscope-cookie-helper.go ./cmd/bbpipeline-bbscope/main.go
RUN CGO_ENABLED=0 go build -trimpath -o /out/bbscope . \
    && CGO_ENABLED=0 go build -trimpath -o /out/bbscope-cookie ./cmd/bbpipeline-bbscope

FROM ${BBOT_BASE_IMAGE}

ARG BBOT_VERSION=3.0.1
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=10.4.7
ARG NUCLEI_TEMPLATES_COMMIT=83234ce
ARG GITLEAKS_VERSION=8.28.0

COPY --from=bbscope-builder /out/bbscope /usr/local/bin/bbscope
COPY --from=bbscope-builder /out/bbscope-cookie /usr/local/bin/bbscope-cookie

USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates curl git python3-venv unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    architecture="$(dpkg --print-architecture)"; \
    case "$architecture" in \
      amd64) nuclei_arch="amd64"; gitleaks_arch="x64" ;; \
      arm64) nuclei_arch="arm64"; gitleaks_arch="arm64" ;; \
      *) echo "Unsupported architecture: $architecture" >&2; exit 1 ;; \
    esac; \
    temporary="$(mktemp -d)"; \
    cd "$temporary"; \
    nuclei_archive="nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
    curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${nuclei_archive}"; \
    curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep "  ${nuclei_archive}$" "nuclei_${NUCLEI_VERSION}_checksums.txt" | sha256sum -c -; \
    unzip -q "$nuclei_archive" nuclei; \
    install -m 0755 nuclei /usr/local/bin/nuclei; \
    gitleaks_archive="gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz"; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gitleaks_archive}"; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    grep "  ${gitleaks_archive}$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "$gitleaks_archive" gitleaks; \
    install -m 0755 gitleaks /usr/local/bin/gitleaks; \
    rm -rf "$temporary"; \
    bbot --version 2>&1 | grep -F "$BBOT_VERSION"; \
    nuclei -version; \
    gitleaks version; \
    bbscope --help >/dev/null; \
    bbscope-cookie --help >/dev/null

# Fail the image build if the bundled/default Gitleaks rules silently detect nothing.
RUN set -eux; \
    temporary="$(mktemp -d)"; \
    printf '%s\n' 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"' >"$temporary/sample.txt"; \
    set +e; \
    gitleaks dir --no-banner --no-color --exit-code 42 "$temporary"; \
    status="$?"; \
    set -e; \
    rm -rf "$temporary"; \
    test "$status" -eq 42

RUN git clone --depth 1 --branch "v${NUCLEI_TEMPLATES_VERSION}" \
      https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates \
    && test "$(git -C /opt/nuclei-templates rev-parse --short=7 HEAD)" = \
       "${NUCLEI_TEMPLATES_COMMIT}" \
    && rm -rf /opt/nuclei-templates/.git

WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY bbpipeline ./bbpipeline
COPY schemas ./schemas
COPY methodology ./methodology
COPY skills ./skills
RUN python3 -m venv --system-site-packages /opt/bbpipeline-venv \
    && /opt/bbpipeline-venv/bin/pip install --no-cache-dir . \
    && if ! getent group 10001 >/dev/null; then groupadd --gid 10001 bbpipeline; fi \
    && if ! getent passwd 10001 >/dev/null; then \
         useradd --uid 10001 --gid 10001 --home-dir /home/bbpipeline \
           --create-home --shell /usr/sbin/nologin bbpipeline; \
       fi \
    && install -d -o 10001 -g 10001 -m 0770 /data/evidence \
    && install -d -o 10001 -g 10001 -m 0750 /home/bbpipeline \
    && chown -R 10001:10001 /home/bbpipeline

ENV PATH=/opt/bbpipeline-venv/bin:${PATH} \
    HOME=/home/bbpipeline \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["bbpipeline"]
