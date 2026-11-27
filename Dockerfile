# =============================================================================
# LanMux — Single-Image All-in-One Dockerfile (v1.0.2)
# Bundles: mihomo v1.19.34 + Geodata + metacubexd + FastAPI + Web UI
# Multi-arch ready: linux/amd64, linux/arm64
#
# Build:
#   docker build -t lanmux:latest .
#
# China mirror accelerated build example:
#   docker build \
#     --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
#     --build-arg GITHUB_MIRROR=https://gh-proxy.com \
#     -t lanmux:latest .
# =============================================================================

# H-13/M-47：基础镜像钉 digest（tag 可被移动，digest 不能）。digest 由
# 维护者用 crane 从 registry 实测（2026-11-26），见 scripts/asset-checksums.sha256 头部。
# metacubex/mihomo:v1.19.34 的 digest 是多架构 OCI index 的 digest。
ARG MIHOMO_IMAGE=metacubex/mihomo:v1.19.34@sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532

# --- Stage 1: Official mihomo binary (auto-matches TARGETARCH) ---------------
FROM ${MIHOMO_IMAGE} AS mihomo-bin

# --- Stage 2: Pre-bundle Geodata + metacubexd static assets ------------------
# Alpine 3.24.4, pinned by tag + digest (crane digest, 2026-11-26).
# 3.20 went EOL 2026-04-01; 3.24 is supported until 2028-06-01 (audit M-48).
# NOTE: the digest below is the manifest digest for the multi-arch index;
# re-verify with `crane digest alpine:3.24.4` when bumping the patch version.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS assets
ARG METACUBEXD_VERSION=1.276.0
ARG GITHUB_MIRROR=""
# 校验清单（与 install.sh 共用同一文件，唯一信任根）。
COPY scripts/asset-checksums.sha256 /tmp/asset-checksums.sha256

# H-13：四路下载全部按清单做 SHA256 校验，不匹配即构建失败。
# 注意 geodata 的 URL 仍用 latest：上游 MetaCubeX/meta-rules-dat 只有
# 一个滚动发布（tag 字面就是 "latest"，无固定 tag 可钉）；内容由哈希
# 钉死——上游滚动更新后旧哈希会让构建明确失败，不会静默换内容。
# 维护者更新 geodata 时须同步更新清单与下方 label 里的快照日期。
RUN apk add --no-cache curl tar ca-certificates     && mkdir -p /assets/ui     && MIRROR="${GITHUB_MIRROR%/}"     && PREFIX="${MIRROR:+${MIRROR}/}"     && echo "Downloading Geodata..."     && curl -fsSL --retry 3 "${PREFIX}https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat" -o /assets/geoip.dat     && curl -fsSL --retry 3 "${PREFIX}https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat" -o /assets/geosite.dat     && curl -fsSL --retry 3 "${PREFIX}https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb" -o /assets/country.mmdb     && echo "Downloading metacubexd v${METACUBEXD_VERSION}..."     && curl -fsSL --retry 3 "${PREFIX}https://github.com/MetaCubeX/metacubexd/releases/download/v${METACUBEXD_VERSION}/compressed-dist.tgz" -o /assets/compressed-dist.tgz     && echo "Verifying SHA256 against scripts/asset-checksums.sha256..."     && grep -E ' (geoip\.dat|geosite\.dat|country\.mmdb|compressed-dist\.tgz)$' /tmp/asset-checksums.sha256 > /tmp/assets.sha256     && test "$(wc -l < /tmp/assets.sha256)" = "4"     && (cd /assets && sha256sum -c /tmp/assets.sha256)     && mv /assets/geoip.dat /assets/GeoIP.dat && mv /assets/geosite.dat /assets/GeoSite.dat && mv /assets/country.mmdb /assets/Country.mmdb     && tar -xzf /assets/compressed-dist.tgz -C /assets/ui     && test -f /assets/ui/index.html     && rm -f /assets/compressed-dist.tgz /tmp/assets.sha256

# --- Stage 3: Final All-in-One runtime image ---------------------------------
FROM python:3.12-slim

ARG PIP_INDEX_URL=""

ARG LANMUX_VERSION="1.0.2"
ARG LANMUX_COMMIT="unknown"
ARG LANMUX_BUILD_TIME="unknown"

ENV LANMUX_VERSION=${LANMUX_VERSION}     LANMUX_COMMIT=${LANMUX_COMMIT}     LANMUX_BUILD_TIME=${LANMUX_BUILD_TIME}

# M-47：记录钉住的资产版本与 geodata 快照（上游 meta-rules-dat 只有滚动
# latest 发布，tag/日期是快照信息，内容由 scripts/asset-checksums.sha256
# 里的哈希钉死）。不要改 /api/version——版本面是别的簇的。
LABEL org.lanmux.mihomo-version="1.19.34" \
      org.lanmux.metacubexd-version="1.276.0" \
      org.lanmux.geodata-release-tag="latest" \
      org.lanmux.geodata-release-date="2026-11-26T04:16:13Z" \
      org.lanmux.geodata-release-name="Release 2026-11-26 12:14"

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     TZ=Asia/Shanghai     LANMUX_DB_PATH=/data/lanmux.db     LANMUX_CONFIG_PATH=/data/mihomo/config.yaml     LANMUX_ASSETS_DIR=/opt/lanmux-assets     MIHOMO_BIN=/usr/local/bin/mihomo     MIHOMO_BASE_URL="http://127.0.0.1:{port}"     LANMUX_WEB_PORT=8086

RUN apt-get update     && apt-get install -y --no-install-recommends ca-certificates tzdata     && rm -rf /var/lib/apt/lists/*

# Unprivileged service user (H-12): every long-lived process (mihomo,
# uvicorn) runs as `lanmux` (UID/GID 10001). /data and /opt/lanmux-assets
# are pre-owned by it so a plain `docker run -v lanmux-data:/data`
# (named volume, which inherits the image's /data ownership) works with
# the image default USER below. For a host bind mount (docker-compose
# ./data), the daemon creates the directory root-owned on first run, so
# docker-compose.yml deliberately starts the entrypoint as 0:0 and
# app/docker_runner.py fixes /data ownership, then drops to this user
# before starting any service. The UID is fixed so the host-side
# remediation is always `chown -R 10001:10001 <host-dir>`.
RUN groupadd -r -g 10001 lanmux     && useradd -r -u 10001 -g lanmux -d /nonexistent -s /usr/sbin/nologin lanmux     && mkdir -p /data /opt/lanmux-assets     && chown lanmux:lanmux /data /opt/lanmux-assets

WORKDIR /app
# Pinned, hashed production dependencies (audit M-45 / L-43): install from the
# pip-compile lockfile with --require-hashes. The PyPI mirror is passed as a
# one-shot environment variable for this single RUN only — never written to a
# persistent pip config file inside the image (a credential-bearing index URL
# must not be baked into a layer).
COPY backend/requirements-prod.lock ./requirements-prod.lock
RUN if [ -n "$PIP_INDEX_URL" ]; then \
      PIP_INDEX_URL="$PIP_INDEX_URL" pip install --no-cache-dir --require-hashes -r requirements-prod.lock; \
    else \
      pip install --no-cache-dir --require-hashes -r requirements-prod.lock; \
    fi

COPY --from=mihomo-bin /mihomo /usr/local/bin/mihomo
RUN chmod +x /usr/local/bin/mihomo

COPY --from=assets /assets /opt/lanmux-assets
RUN chown -R lanmux:lanmux /opt/lanmux-assets
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY backend/app/healthcheck.py /app/healthcheck.py

WORKDIR /app/backend

# Run as the unprivileged service user by default. All four service
# ports (8086/10001/7890/9090) are > 1024, so no capability is needed.
# NOTE: docker-compose.yml overrides this to `user: "0:0"` on purpose —
# the entrypoint (app/docker_runner.py) starts as root ONLY to chown a
# host bind-mounted /data (the daemon creates a fresh ./data as root),
# then drops to `lanmux` before starting mihomo/uvicorn. The drop is
# enforced in docker_runner.main(); no long-lived process runs as root
# in any deployment path. Do not "fix" this by removing the compose
# override without also fixing bind-mount ownership another way, or a
# fresh ./data cold start will crash-loop on PermissionError.
USER lanmux

VOLUME ["/data"]

# Default ports (Web UI / Shadowsocks / Mixed / Mihomo Controller)
EXPOSE 8086/tcp 10001/tcp 10001/udp 7890/tcp 7890/udp 9090/tcp

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python /app/healthcheck.py

ENTRYPOINT ["python", "-m", "app.docker_runner"]
