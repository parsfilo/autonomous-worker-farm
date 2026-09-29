FROM node:24.19.0-bookworm-slim@sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        git \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/awf-worker-toolchain
COPY containers/worker-toolchain/package.json containers/worker-toolchain/package-lock.json ./

RUN NPM_CONFIG_UPDATE_NOTIFIER=false npm ci --omit=dev --no-audit --no-fund --strict-allow-scripts \
    && test "$(./node_modules/.bin/opencode --version)" = "opencode v2.0.18" \
    && test "$(./node_modules/@pnpm/exe.linux-x64/pnpm --version)" = "12.4.2" \
    && install -m 0755 ./node_modules/@opencode/cli/bin/opencode.exe /usr/local/bin/opencode \
    && install -m 0755 ./node_modules/@pnpm/exe.linux-x64/pnpm /usr/local/bin/pnpm \
    && test "$(opencode --version)" = "opencode v2.0.18" \
    && test "$(pnpm --version)" = "12.4.2" \
    && rm -rf /opt/awf-worker-toolchain/node_modules /root/.npm \
    && mkdir -p /home/worker \
    && chown 65532:65532 /home/worker

ENV HOME=/home/worker \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_DATA_HOME=/tmp/.local/share \
    TMPDIR=/tmp

WORKDIR /run
USER 65532:65532

CMD ["opencode", "--version"]
