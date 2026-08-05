# syntax=docker/dockerfile:1.6
#
# F.E.A.R. Messenger — server image.
# Compiles only the relay/server CLI (no GUI, no audio/video — those run on
# clients). Final image is debian:bookworm-slim + statically-named libsodium23
# plus the fear binary, ~30–50 MB.
#
# Build:  docker build -t fear-server .
# Run:    docker run -d --name fear -p 8888:8888 --restart unless-stopped fear-server
# Custom port:  docker run -d -p 9999:8888 fear-server  (host:9999 → container:8888)

# ───── Build stage ─────
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev libsodium-dev libsqlite3-dev libssl-dev pkg-config make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Copy only the parts needed for the server binary.
COPY client-console ./client-console
COPY identity       ./identity

# Build directly with gcc — no CMake needed. Mirrors what
# client-console/CMakeLists.txt does, minus Windows branches.
# Phase B-2 added server_db.c (SQLite-backed handle registry + opaque
# user-blob store), so we link against -lsqlite3.
RUN mkdir -p /out && gcc -O2 -Wall -Wextra -pthread \
        -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
        -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
        -o /out/fear \
        client-console/src/main.c \
        client-console/src/common.c \
        client-console/src/network.c \
        client-console/src/client.c \
        client-console/src/server.c \
        client-console/src/server_db.c \
        identity/identity.c \
        identity/identity_at_rest.c \
        identity/call_invite.c \
        identity/media_keys.c \
        identity/key_schedule.c \
        identity/chat_frame.c \
        identity/room_keys.c \
        identity/rotation_bundle.c \
        identity/rotation.c \
        identity/tls.c \
        -I client-console/include \
        -I identity \
        -DFEAR_HAVE_TLS=1 -lssl -lcrypto -lsodium -lsqlite3

# ───── Runtime stage ─────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsodium23 libsqlite3-0 libssl3 ca-certificates netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin fear

COPY --from=build /out/fear /usr/local/bin/fear

USER fear
WORKDIR /home/fear
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z 127.0.0.1 8888 || exit 1

# Entrypoint runs fear server. Pass extra flags via `docker run ... fear-server --port 9000`.
ENTRYPOINT ["fear", "server"]
CMD ["--port", "8888"]
