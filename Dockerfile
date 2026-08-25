FROM python:3.12-slim

# TPM 工具链 + gosu（用于 entrypoint 降权）
RUN apt-get update && apt-get install -y --no-install-recommends \
    tpm2-tools \
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && gosu nobody true  # 验证 gosu 安装

# 创建非 root 用户 + 专用组（用于 TPM 设备访问控制）
RUN addgroup --system credential-proxy \
    && adduser --system --ingroup credential-proxy credential-proxy

# uv — 快速 Python 依赖管理（锁定版本，避免 :latest 穿透缓存）
COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /usr/local/bin/uv

# 依赖（Export locked deps → pip install to system Python）
COPY pyproject.toml uv.lock /tmp/deps/
RUN --mount=type=cache,target=/root/.cache/uv \
    cd /tmp/deps && uv export --frozen --no-dev --no-hashes --no-emit-project --extra orjson -o requirements.txt \
    && uv pip install --system --no-cache -r requirements.txt \
    && rm -rf /tmp/deps

# 源码
COPY *.py /app/

# 入口
COPY --chmod=+x docker-entrypoint.sh /

WORKDIR /data
VOLUME ["/data/tpm", "/data/db"]

EXPOSE 8877

ENTRYPOINT ["/docker-entrypoint.sh"]
