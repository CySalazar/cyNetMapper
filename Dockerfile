# Multi-stage build for cyNetMapper
# Stage 1: Build environment
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build dependencies (this step is cached if dependencies don't change)
RUN cargo build --release --workspace

# Stage 2: Runtime environment
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cynetmapper && useradd -r -g cynetmapper cynetmapper

# Create directories
RUN mkdir -p /app/bin /app/data /app/config \
    && chown -R cynetmapper:cynetmapper /app

# Copy binaries from builder stage
COPY --from=builder /usr/src/app/target/release/cynetmapper /app/bin/
COPY --from=builder /usr/src/app/target/release/cyndiff /app/bin/

# Copy configuration files
COPY docker/config/ /app/config/
COPY docker/entrypoint.sh /app/

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Set working directory
WORKDIR /app

# Switch to non-root user
USER cynetmapper

# Add binaries to PATH
ENV PATH="/app/bin:${PATH}"

# Expose default ports (if any web interface is added later)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD cynetmapper --version || exit 1

# Default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="cyNetMapper" \
      org.opencontainers.image.description="Advanced network discovery and port scanning tool" \
      org.opencontainers.image.vendor="cyNetMapper Team" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cynetmapper/cynetmapper" \
      org.opencontainers.image.documentation="https://github.com/cynetmapper/cynetmapper/blob/main/README.md"