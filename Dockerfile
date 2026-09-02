FROM debian:trixie-slim

ENV UBS_NO_AUTO_UPDATE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq ripgrep rsync python3 unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Ship the language modules and helpers with the image so scans work offline
# (the meta-runner resolves modules next to itself before any download), and
# pre-provision the pinned ast-grep binary into the tools cache at build time
# (digest-verified by ubs) so JavaScript/TypeScript scans do not need network.
COPY ubs install.sh README.md /app/
COPY modules /app/modules

ENV UBS_TOOLS_DIR=/opt/ubs/tools

RUN chmod +x /app/ubs /app/install.sh \
 && mkdir -p /opt/ubs/tools /opt/ubs/smoke \
 && printf 'const value = getUserValue();\nif (value === NaN) { console.log("bad"); }\n' > /opt/ubs/smoke/smoke.js \
 && /app/ubs --only=js --ci --format=json /opt/ubs/smoke >/dev/null 2>&1 || true \
 && test -x "$(find /opt/ubs/tools -type f -name ast-grep | head -n 1)"

ENTRYPOINT ["/app/ubs"]
CMD ["--help"]

LABEL org.opencontainers.image.title="Ultimate Bug Scanner" \
      org.opencontainers.image.description="Meta-runner for multi-language bug scanning" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Dicklesworthstone/ultimate_bug_scanner"
