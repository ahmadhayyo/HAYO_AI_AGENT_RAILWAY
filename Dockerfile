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
    xz-utils \
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

# ── Download Android SDK build-tools (zipalign + apksigner) ──────
# NOTE: The correct URL format is build-tools_r34-linux.zip (NOT r34.0.0)
# zipalign requires libc++.so from lib64/ — we copy it to /usr/local/lib for reliable resolution
RUN mkdir -p /opt/android-sdk/build-tools && \
    wget -q --timeout=180 \
    "https://dl.google.com/android/repository/build-tools_r34-linux.zip" \
    -O /tmp/build-tools.zip \
    && unzip -q /tmp/build-tools.zip -d /tmp/build-tools-extract \
    && mv /tmp/build-tools-extract/android-14 /opt/android-sdk/build-tools/34.0.0 \
    && cp /opt/android-sdk/build-tools/34.0.0/lib64/libc++.so /usr/local/lib/ \
    && cp /opt/android-sdk/build-tools/34.0.0/lib64/libc++.so.1 /usr/local/lib/ \
    && ldconfig \
    && chmod +x /opt/android-sdk/build-tools/34.0.0/zipalign \
    && chmod +x /opt/android-sdk/build-tools/34.0.0/apksigner \
    && chmod +x /opt/android-sdk/build-tools/34.0.0/aapt2 \
    && ln -sf /opt/android-sdk/build-tools/34.0.0/zipalign /usr/local/bin/zipalign \
    && ln -sf /opt/android-sdk/build-tools/34.0.0/apksigner /usr/local/bin/apksigner \
    && ln -sf /opt/android-sdk/build-tools/34.0.0/aapt2 /usr/local/bin/aapt2 \
    && rm -rf /tmp/build-tools.zip /tmp/build-tools-extract \
    && echo "✅ Android build-tools installed successfully" \
    || echo "WARNING: Android build-tools download failed — zipalign/apksigner will NOT be available"

# ── Verify build-tools installation ──────────────────────────────
RUN zipalign 2>&1 | head -1 || echo "❌ zipalign NOT working" && \
    apksigner --version 2>&1 | head -1 || echo "❌ apksigner NOT working"

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
ENV LD_LIBRARY_PATH=/opt/android-sdk/build-tools/34.0.0/lib64:/usr/local/lib

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
