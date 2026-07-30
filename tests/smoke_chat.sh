#!/usr/bin/env bash
# Integration smoke test: relay server + two console clients.
#
# Checks the full happy path end to end:
#   * server starts and accepts connections
#   * alice creates a room (--create, auto-generated key, signed ECDH responder)
#   * bob joins via ECDH (--join) with mandatory signature verification
#   * a message goes alice -> bob and another bob -> alice
#
# The relay stores nothing, so both clients must be online when a message
# is sent - the sleeps below stagger the two clients accordingly.
#
# Each client gets its own HOME so ~/.fear (identity, known_keys) is
# sandboxed and the real user profile is never touched.

set -u

FEAR_BIN="${1:?usage: smoke_chat.sh /path/to/fear}"
# The server is exec'd from inside the sandbox dir - the path must survive cd.
FEAR_BIN=$(readlink -f "$FEAR_BIN")

WORK=$(mktemp -d /tmp/fear-smoke-XXXXXX)
PORT=$(( 20000 + $$ % 20000 ))
ROOM=smoketest

SERVER_PID=""
A_PID=""
B_PID=""

cleanup() {
    [ -n "$A_PID" ]      && kill "$A_PID"      2>/dev/null
    [ -n "$B_PID" ]      && kill "$B_PID"      2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    echo "--- server.log ---" >&2; cat "$WORK/server.log" 2>/dev/null >&2
    echo "--- alice.log ---"  >&2; cat "$WORK/alice.log"  2>/dev/null >&2
    echo "--- bob.log ---"    >&2; cat "$WORK/bob.log"    2>/dev/null >&2
    exit 1
}

mkdir -p "$WORK/alice" "$WORK/bob" "$WORK/server"

HOME="$WORK/alice" "$FEAR_BIN" gen-identity >/dev/null 2>&1 || fail "alice gen-identity"
HOME="$WORK/bob"   "$FEAR_BIN" gen-identity >/dev/null 2>&1 || fail "bob gen-identity"

# The server drops its SQLite files into CWD - keep them in the sandbox.
( cd "$WORK/server" && exec "$FEAR_BIN" server --port "$PORT" ) \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server did not start on port $PORT"

# Timeline (seconds from now):
#   t=0  alice connects and creates the room
#   t=2  bob connects and runs the ECDH join
#   t=4  alice sends her message (bob is in the room by then)
#   t=5  bob sends his reply
#   t=8  both clients hit EOF on stdin and disconnect
( sleep 4; printf 'hello from alice\n'; sleep 4 ) | \
    HOME="$WORK/alice" "$FEAR_BIN" client \
        --host 127.0.0.1 --port "$PORT" --room "$ROOM" --name alice --create \
        > "$WORK/alice.log" 2>&1 &
A_PID=$!

sleep 2

( sleep 3; printf 'hi from bob\n'; sleep 3 ) | \
    HOME="$WORK/bob" "$FEAR_BIN" client \
        --host 127.0.0.1 --port "$PORT" --room "$ROOM" --name bob --join \
        > "$WORK/bob.log" 2>&1 &
B_PID=$!

wait "$B_PID" 2>/dev/null
wait "$A_PID" 2>/dev/null
A_PID=""
B_PID=""

grep -q "hello from alice" "$WORK/bob.log"   || fail "bob did not receive alice's message"
grep -q "hi from bob"      "$WORK/alice.log" || fail "alice did not receive bob's reply"

echo "smoke_chat: OK"
