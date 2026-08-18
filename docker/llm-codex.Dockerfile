FROM node:22-bookworm-slim

ARG CODEX_VERSION=0.147.0
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates python3 python3-pip python3-venv \
    && npm install --global "@openai/codex@${CODEX_VERSION}" \
    && rm -rf /var/lib/apt/lists/* /root/.npm \
    # The npm package is a wrapper that copies a platform-native binary during its
    # postinstall. Fail the build now rather than on the first job if that left a stub.
    && codex --version | grep -F "${CODEX_VERSION}"

WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY bbpipeline ./bbpipeline
COPY schemas ./schemas
COPY methodology ./methodology
COPY skills ./skills
RUN python3 -m venv /opt/bbpipeline-venv \
    && /opt/bbpipeline-venv/bin/pip install --no-cache-dir . \
    && groupadd --gid 10001 bbpipeline \
    && useradd --uid 10001 --gid 10001 --home-dir /home/bbpipeline --create-home \
       --shell /usr/sbin/nologin bbpipeline \
    && install -d -o 10001 -g 10001 -m 0700 /home/bbpipeline/.codex \
    && install -d -o 10001 -g 10001 -m 0770 /data/evidence

ENV PATH=/opt/bbpipeline-venv/bin:${PATH} \
    HOME=/home/bbpipeline \
    CODEX_HOME=/home/bbpipeline/.codex \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["bbpipeline"]
