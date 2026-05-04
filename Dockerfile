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
    python3-pip \
    make \
    g++ \
    zipalign \
    apksigner \
    file \
    binwalk \
    strace \
    ltrace \
    aapt \
    && rm -rf /var/lib/apt/lists/*

# ── Install Python dependencies ───────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages colorama

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

# ── Download dex2jar (fault-tolerant) ─────────────────────────────
RUN wget -q --timeout=60 \
    "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip" \
    -O /tmp/dex2jar.zip \
    && unzip -q /tmp/dex2jar.zip -d /home/runner/ \
    && mv /home/runner/dex-tools-v2.4 /home/runner/dex2jar \
    && chmod +x /home/runner/dex2jar/*.sh \
    && ln -sf /home/runner/dex2jar/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar.sh \
    && rm /tmp/dex2jar.zip \
    || echo "WARNING: dex2jar download failed"

# ── Download radare2 (fault-tolerant) ─────────────────────────────
RUN wget -q --timeout=60 \
    "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb" \
    -O /tmp/radare2.deb \
    && dpkg -i /tmp/radare2.deb \
    && rm /tmp/radare2.deb \
    || echo "WARNING: radare2 download failed"

# ── Download UPX (fault-tolerant — not in Debian bookworm repos) ──
RUN wget -q --timeout=60 \
    "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz" \
    -O /tmp/upx.tar.xz \
    && tar -xJf /tmp/upx.tar.xz -C /tmp/ \
    && cp /tmp/upx-4.2.4-amd64_linux/upx /usr/local/bin/upx \
    && chmod +x /usr/local/bin/upx \
    && rm -rf /tmp/upx.tar.xz /tmp/upx-4.2.4-amd64_linux \
    || echo "WARNING: UPX download failed"

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
