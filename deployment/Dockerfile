# =============================================================================
# Multi-stage build for auth-server
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM alpine:3.19 AS builder

ARG DB_BACKEND=sqlite

RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    openssl-dev \
    argon2-dev \
    linux-headers \
    && if [ "$DB_BACKEND" = "postgresql" ]; then \
        apk add --no-cache libpq-dev; \
    fi

WORKDIR /build

COPY Makefile ./
COPY src/ ./src/
COPY include/ ./include/
COPY vendor/ ./vendor/

RUN make clean && make DB_BACKEND=${DB_BACKEND}

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM alpine:3.19

ARG DB_BACKEND=sqlite

RUN apk add --no-cache \
    openssl \
    argon2-libs \
    ca-certificates \
    wget \
    && if [ "$DB_BACKEND" = "postgresql" ]; then \
        apk add --no-cache libpq; \
    fi \
    && addgroup -g 1000 authserver \
    && adduser -u 1000 -G authserver -s /bin/sh -D authserver \
    && mkdir -p /app/data \
    && chown -R authserver:authserver /app

WORKDIR /app

# Binary from build stage
COPY --from=builder /build/auth-server /app/auth-server

# Runtime files (static assets, SQL schemas)
COPY static/ /app/static/
COPY sql/ /app/sql/
COPY templates/ /app/templates/

RUN chown -R authserver:authserver /app

USER authserver

ENV AUTH_SERVER_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO /dev/null http://localhost:${AUTH_SERVER_PORT}/health || exit 1

VOLUME ["/app/data"]

ENTRYPOINT ["/app/auth-server"]
