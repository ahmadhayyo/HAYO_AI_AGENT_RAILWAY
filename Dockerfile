FROM node:20-slim AS base

RUN corepack enable && corepack prepare pnpm@10.26.1 --activate

# ── Install System Dependencies ──────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    binutils \
    xxd \
    wabt \
    wget \
    unzip \
    zip \
    curl \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure for reverse-engineering tools
RUN mkdir -p /home/runner/jadx/bin /home/runner/apktool

# ── Download JADX (fault-tolerant — reverse engineering is optional) ──
RUN wget -q --timeout=60 \
    "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip" \
    -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /home/runner/jadx \
    && chmod +x /home/runner/jadx/bin/jadx /home/runner/jadx/bin/jadx-gui \
    && ln -sf /home/runner/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip \
    || echo "WARNING: JADX download failed — reverse engineering features will be limited"

# ── Download APKTool (fault-tolerant — reverse engineering is optional) ──
RUN wget -q --timeout=60 \
    "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar" \
    -O /home/runner/apktool/apktool.jar \
    && printf '#!/bin/bash\njava -jar /home/runner/apktool/apktool.jar "$@"\n' \
       > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    || echo "WARNING: APKTool download failed — reverse engineering features will be limited"

# ── Generate debug keystore (fault-tolerant) ─────────────────────
RUN keytool -genkeypair -v \
    -keystore /home/runner/debug.keystore \
    -storepass android \
    -alias androiddebugkey \
    -keypass android \
    -keyalg RSA -keysize 2048 -validity 36500 \
    -dname "CN=Android Debug,O=Android,C=US" \
    || echo "WARNING: Keystore generation failed"

# ── Node.js App Build ─────────────────────────────────────────────
WORKDIR /app

# Set environment variables BEFORE build steps for correct build behavior
ENV NODE_ENV=production
ENV PORT=8080
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# ── Copy workspace config first (maximizes Docker layer cache) ────
# .npmrc MUST be copied before pnpm install so shamefully-hoist=true is applied
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json tsconfig.base.json .npmrc ./
COPY lib/ ./lib/

# ── Copy ALL package.json files for every workspace package ───────
# pnpm needs all workspace package.json files present before running install
COPY artifacts/api-server/package.json     ./artifacts/api-server/
COPY artifacts/hayo-ai/package.json        ./artifacts/hayo-ai/
COPY artifacts/mockup-sandbox/package.json ./artifacts/mockup-sandbox/
COPY scripts/package.json                  ./scripts/

# ── Install all dependencies (including devDeps needed for build) ─
RUN pnpm install --no-frozen-lockfile --prod=false

# ── Copy all source code ──────────────────────────────────────────
COPY artifacts/ ./artifacts/
COPY scripts/   ./scripts/
COPY shared/    ./shared/
# attached_assets may be empty but the directory must exist for path aliases
COPY attached_assets/ ./attached_assets/

# ── Build frontend (React/Vite) ───────────────────────────────────
RUN pnpm --filter @workspace/hayo-ai run build

# ── Build backend (Express/tRPC/esbuild) ─────────────────────────
RUN pnpm --filter @workspace/api-server run build

EXPOSE 8080

# Start the application
CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]
