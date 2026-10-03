#!/usr/bin/env bash
# Кому ретранслятор рассылает медиа: только звонкам и никогда тому же
# участнику. Поднимает сервер и запускает test_media_routing против него.
#
# args: [1] fear  [2] test_media_routing
set -u

FEAR_BIN=$(readlink -f "${1:?usage: media_routing.sh /path/to/fear /path/to/test_media_routing}")
TEST_BIN=$(readlink -f "${2:?missing test_media_routing path}")

WORK=$(mktemp -d /tmp/fear-mediarouting-XXXXXX)
PORT=$(( 20000 + ($$ + 1237) % 20000 ))
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
