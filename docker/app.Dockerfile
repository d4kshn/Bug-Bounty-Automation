ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/bbpipeline

WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY bbpipeline ./bbpipeline
COPY schemas ./schemas
COPY methodology ./methodology
COPY skills ./skills
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 bbpipeline \
    && useradd --uid 10001 --gid 10001 --home-dir /home/bbpipeline --create-home \
       --shell /usr/sbin/nologin bbpipeline \
    && install -d -o 10001 -g 10001 -m 0770 /data/evidence

USER 10001:10001
ENTRYPOINT ["bbpipeline"]

FROM runtime AS test
USER root
COPY requirements-dev.txt ./
COPY tests ./tests
RUN pip install --no-cache-dir -r requirements-dev.txt
USER 10001:10001
ENTRYPOINT []
CMD ["pytest"]
