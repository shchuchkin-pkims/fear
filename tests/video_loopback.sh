#!/usr/bin/env bash
# Three-party loopback for video_call, audio path only.
#
# The home PC has no display and no camera, so SDL runs on the dummy driver
# and --no-video is forced: this exercises the per-sender Opus decoders and
# the mixer, not the VP8 or display changes.
#
# Asserts the same contract as tests/media_loopback.sh:
#   [MEDIA] peer <sid> decrypted N mixed M
# with N > 0 and M > 0 for both of the other two participants.

set -u
VC=$(readlink -f "${1:?usage: vc_loopback.sh /path/to/video_call}")
WORK=$(mktemp -d /tmp/fear-vcloop-XXXXXX)
PORT=$(( 47000 + $$ % 15000 ))
CALL_ID=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
export SDL_VIDEODRIVER=dummy

HUB=""
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    [ -n "$HUB" ] && kill "$HUB" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

"$VC" genkey 2>/dev/null | tr -d '\n' | tail -c 64 > "$WORK/key"
[ "$(wc -c < "$WORK/key")" -eq 64 ] || { echo "FAIL: genkey"; exit 1; }

"$VC" hub "$PORT" > "$WORK/hub.log" 2>&1 &
HUB=$!
sleep 1
kill -0 "$HUB" 2>/dev/null || { echo "FAIL: hub did not start"; cat "$WORK/hub.log"; exit 1; }

for i in 1 2 3; do
    mkdir -p "$WORK/p$i"
    HOME="$WORK/p$i" "$VC" call 127.0.0.1 "$PORT" \
        --key-file "$WORK/key" --call-id "$CALL_ID" --no-video --no-sign \
        > "$WORK/p$i.log" 2>&1 &
    PIDS+=("$!")
    sleep 0.5
done

sleep 8
for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
sleep 3
for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
wait "${PIDS[@]}" 2>/dev/null
PIDS=()

echo "=== [MEDIA] lines ==="
for i in 1 2 3; do
    echo "--- p$i ---"
    grep -E '^\[(MEDIA|VIDEO)\] peer' "$WORK/p$i.log" || echo "(none)"
done

RC=0
for i in 1 2 3; do
    n=$(grep -cE '^\[MEDIA\] peer [0-9a-f]{6} decrypted [0-9]+ mixed [0-9]+$' "$WORK/p$i.log")
    [ "$n" -eq 2 ] || { echo "FAIL: p$i has $n [MEDIA] peer lines, expected 2"; RC=1; }
    while read -r d m; do
        [ "${d:-0}" -gt 0 ] || { echo "FAIL: p$i decrypted 0 from a peer"; RC=1; }
        [ "${m:-0}" -gt 0 ] || { echo "FAIL: p$i decrypted $d but mixed 0 (single-decoder defect)"; RC=1; }
    done < <(grep -oP '^\[MEDIA\] peer [0-9a-f]{6} decrypted \K[0-9]+ mixed [0-9]+' "$WORK/p$i.log" | sed 's/ mixed / /')
done
[ $RC -eq 0 ] && echo "vc_loopback: OK"
echo "logs kept in $WORK"
exit $RC
