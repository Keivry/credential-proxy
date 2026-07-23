FROM python:3.12-slim

# TPM 工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# uv — 快速 Python 依赖管理
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_SYSTEM_PYTHON=1

# 依赖（利用层缓存：uv sync 在源码之前）
COPY pyproject.toml uv.lock /tmp/deps/
RUN cd /tmp/deps && uv sync --frozen --no-dev --no-install-project

# 源码
COPY *.py /app/

# 入口
COPY --chmod=+x docker-entrypoint.sh /

WORKDIR /data
VOLUME ["/data/tpm", "/data/db"]

EXPOSE 8877

ENTRYPOINT ["/docker-entrypoint.sh"]
