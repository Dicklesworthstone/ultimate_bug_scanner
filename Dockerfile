FROM debian:bookworm-slim

ENV UBS_NO_AUTO_UPDATE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq ripgrep \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ubs install.sh README.md /app/

RUN chmod +x /app/ubs /app/install.sh

ENTRYPOINT ["/app/ubs"]
CMD ["--help"]

LABEL org.opencontainers.image.title="Ultimate Bug Scanner" \
      org.opencontainers.image.description="Meta-runner for multi-language bug scanning" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Dicklesworthstone/ultimate_bug_scanner"
