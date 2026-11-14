# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT

# Signet Multi-stage Dockerfile
# Both images are pinned by digest: the Go that compiles Signet decides its
# standard-library fixes.  Move a pin in a commit of its own.
# Build stage
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Set working directory
WORKDIR /app

# .dockerignore admits only the source, the vendored dependencies and the web files
COPY . .

# `make docker-image` passes these; a plain docker build reports "unknown".
ARG GIT_HASH=unknown
ARG BUILD_TIME=unknown

# Build from vendor/ alone, as the OpenBSD port does.
RUN CGO_ENABLED=1 GOFLAGS=-mod=vendor GOPROXY=off go build \
    -ldflags "-w -s -X main.gitHash=${GIT_HASH} -X main.buildTime=${BUILD_TIME} -X main.defaultConfig=/etc/signet/config.yaml" \
    -o /signet \
    ./cmd/signet

# Runtime stage
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.source="https://github.com/obtusenet/signet" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S signet && \
    adduser -S signet -u 1001 -G signet

# Create application directories
RUN mkdir -p /etc/signet/templates /etc/signet/static /var/lib/signet /var/www/signet /var/log/signet && \
    chown -R signet:signet /etc/signet /var/lib/signet /var/www/signet /var/log/signet

# Copy binary from build stage
COPY --from=builder --chown=signet:signet /signet /usr/local/bin/signet

# The default pages.  Mount a directory over either path to replace them.
COPY --from=builder --chown=signet:signet /app/web/templates /etc/signet/templates
COPY --from=builder --chown=signet:signet /app/web/static /etc/signet/static

# Example claims hooks and web-server configs, for operators to reference
# from inside the container (mirrors the OpenBSD share/examples location).
COPY --from=builder /app/examples /usr/share/doc/signet/examples
COPY --from=builder /app/LICENSE /usr/share/doc/signet/LICENSE

# Run as the unprivileged account created above
USER signet

# Expose port (the listen address in config/example.yaml)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

# Default command
CMD ["signet", "serve", "-config", "/etc/signet/config.yaml"]
