FROM python:3.12-slim

# TPM 工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# uv — 快速 Python 依赖管理（锁定版本，避免 :latest 穿透缓存）
COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /usr/local/bin/uv
ENV UV_SYSTEM_PYTHON=1

# 依赖（利用层缓存 + BuildKit cache mount 避免重复下载）
COPY pyproject.toml uv.lock /tmp/deps/
RUN --mount=type=cache,target=/root/.cache/uv \
    cd /tmp/deps && uv sync --frozen --no-dev --no-install-project \
    && rm -rf /tmp/deps

# 源码
COPY *.py /app/

# 入口
COPY --chmod=+x docker-entrypoint.sh /

WORKDIR /data
VOLUME ["/data/tpm", "/data/db"]

EXPOSE 8877

ENTRYPOINT ["/docker-entrypoint.sh"]
