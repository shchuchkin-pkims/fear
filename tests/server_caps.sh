#!/usr/bin/env bash
# The connection caps are what stop one source from taking every slot. They
# were added as audit remediation and nothing exercised them until now.
#
# Deterministic on purpose: no timing is asserted, only how many connections
# survive. The throughput numbers live in a manual run of the same tool.
set -u

SERVER="$1"
LOADER="$2"
PORT="${3:-47911}"

WORK="$(mktemp -d /tmp/fear-caps-XXXXXX)"
trap 'kill "${SRV_PID:-0}" 2>/dev/null; rm -rf "$WORK"' EXIT

( cd "$WORK" && "$SERVER" server --port "$PORT" >server.log 2>&1 ) &
SRV_PID=$!

for _ in $(seq 1 40); do
    grep -q "listening" "$WORK/server.log" 2>/dev/null && break
    sleep 0.25
done
if ! grep -q "listening" "$WORK/server.log" 2>/dev/null; then
    echo "FAIL: server did not start"; cat "$WORK/server.log"; exit 1
fi

RC=0

# One source address: the per-IP cap decides, whatever we ask for.
if ! "$LOADER" 127.0.0.1 "$PORT" --conns 40 --msgs 1 --spread 1 --expect 16; then
    echo "FAIL: per-IP cap did not hold at 16"
    RC=1
fi

if ! grep -q "already has" "$WORK/server.log"; then
    echo "FAIL: server refused connections without saying so"
    RC=1
fi

[ "$RC" -eq 0 ] && echo "server_caps: per-IP cap holds"
exit "$RC"
