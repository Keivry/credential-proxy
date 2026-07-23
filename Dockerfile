FROM python:3.12-slim

# TPM 工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# Python 依赖
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# 源码
COPY *.py /app/

# 入口
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

WORKDIR /data
VOLUME ["/data/tpm", "/data/db"]

EXPOSE 8877

ENTRYPOINT ["/docker-entrypoint.sh"]
