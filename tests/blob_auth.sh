#!/usr/bin/env bash
# Wrapper for test_blob_auth: boots the relay server in a sandbox dir
# (it drops SQLite files into CWD) and runs the protocol test against it.
#
# args: [1] path to fear binary, [2] path to test_blob_auth binary

set -u

FEAR_BIN=$(readlink -f "${1:?usage: blob_auth.sh /path/to/fear /path/to/test_blob_auth}")
TEST_BIN=$(readlink -f "${2:?missing test_blob_auth path}")

WORK=$(mktemp -d /tmp/fear-blobauth-XXXXXX)
PORT=$(( 40000 + $$ % 20000 ))
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

( cd "$WORK" && exec "$FEAR_BIN" server --port "$PORT" ) > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: server did not start on port $PORT" >&2
    cat "$WORK/server.log" >&2
    exit 1
fi

"$TEST_BIN" 127.0.0.1 "$PORT"
rc=$?
if [ $rc -ne 0 ]; then
    echo "--- server.log ---" >&2
    cat "$WORK/server.log" >&2
fi
exit $rc
