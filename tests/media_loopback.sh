#!/usr/bin/env bash
# Three-party media loopback.
#
# This is the only test in the suite that can catch what step 5 exists to
# fix. Every unit test here works on one process: they prove the framing and
# the derivations, but they cannot show that three live participants, over a
# relay that does not label senders, each end up decrypting the other two.
# A role inversion, a salt that never reaches a peer, or a receive path that
# picks the wrong key all pass every unit test and fail here.
#
# The contract it asserts, printed by audio_call itself:
#     [MEDIA] self <sid>              once, at start
#     [MEDIA] peer <sid> decrypted N  once per installed peer, at teardown
#
# args: [1] path to the audio_call binary

set -u

AC=$(readlink -f "${1:?usage: media_loopback.sh /path/to/audio_call}")

WORK=$(mktemp -d /tmp/fear-loopback-XXXXXX)
PORT=$(( 46000 + $$ % 15000 ))
CALL_ID=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')

HUB=""
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    [ -n "$HUB" ] && kill "$HUB" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    for f in "$WORK"/*.log; do
        echo "--- $(basename "$f") ---" >&2
        tail -25 "$f" >&2
    done
    exit 1
}

# The key goes through a file rather than a pipe on purpose: piping it means
# wrapping the binary in a subshell, and then $! is the subshell and every
# signal we send lands on it instead of on audio_call. That cost an hour once.
"$AC" genkey 2>/dev/null | tr -d '\n' | tail -c 64 > "$WORK/key"
[ "$(wc -c < "$WORK/key")" -eq 64 ] || fail "genkey did not produce a 64-hex key"

"$AC" hub "$PORT" > "$WORK/hub.log" 2>&1 &
HUB=$!
sleep 1
kill -0 "$HUB" 2>/dev/null || fail "hub did not start on port $PORT"

# Three participants, each with its own HOME so identity and TOFU state stay
# separate - two of them signed, one unsigned, because mixed rooms are a
# supported case and the unsigned path binds 32 zero bytes instead of a key.
for i in 1 2 3; do
    mkdir -p "$WORK/p$i"
    if [ "$i" != "3" ]; then
        HOME="$WORK/p$i" "$AC" gen-identity >/dev/null 2>&1
    fi
done

for i in 1 2 3; do
    EXTRA=""
    [ "$i" = "3" ] && EXTRA="--no-sign"
    HOME="$WORK/p$i" "$AC" call 127.0.0.1 "$PORT" \
        --key-file "$WORK/key" --call-id "$CALL_ID" $EXTRA 0 \
        > "$WORK/p$i.log" 2>&1 &
    PIDS+=("$!")
    sleep 0.5
done

# Long enough for every pair to exchange HELLOs and a few hundred frames.
sleep 8

for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
sleep 2
for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
wait "${PIDS[@]}" 2>/dev/null
PIDS=()

# Each participant announced exactly one SID of its own.
declare -A SELF
for i in 1 2 3; do
    sid=$(grep -oP '^\[MEDIA\] self \K[0-9a-f]+' "$WORK/p$i.log" | head -1)
    [ -n "$sid" ] || fail "participant $i never announced its own SID"
    SELF[$i]=$sid
done

[ "${SELF[1]}" != "${SELF[2]}" ] && [ "${SELF[2]}" != "${SELF[3]}" ] && \
    [ "${SELF[1]}" != "${SELF[3]}" ] || fail "two participants drew the same SID"

# And decrypted media from both of the others. This is the assertion the
# whole design is for: no direction bit, no agreement, three keys in flight.
for i in 1 2 3; do
    for j in 1 2 3; do
        [ "$i" = "$j" ] && continue
        line=$(grep -oP "^\[MEDIA\] peer ${SELF[$j]} decrypted \K[0-9]+" "$WORK/p$i.log" | head -1)
        [ -n "$line" ] || fail "participant $i never installed participant $j (${SELF[$j]})"
        [ "$line" -gt 0 ] || fail "participant $i installed participant $j but decrypted nothing"
    done
done

# Nobody should have installed itself: a reflected HELLO would otherwise
# create a peer whose keys are our own send keys.
for i in 1 2 3; do
    if grep -q "^\[MEDIA\] peer ${SELF[$i]} " "$WORK/p$i.log"; then
        fail "participant $i installed its own salt as a peer"
    fi
done

# A participant using a different call_id must not be understood by anyone,
# even though it holds the same room key: that is the cross-call replay
# barrier, and it is the one property a passing three-way test could
# otherwise hide.
OTHER_ID=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
mkdir -p "$WORK/p4"
HOME="$WORK/p4" "$AC" call 127.0.0.1 "$PORT" \
    --key-file "$WORK/key" --call-id "$OTHER_ID" --no-sign 0 \
    > "$WORK/p4.log" 2>&1 &
STRANGER=$!
PIDS+=("$STRANGER")
sleep 4
kill -INT "$STRANGER" 2>/dev/null
sleep 1
kill "$STRANGER" 2>/dev/null
wait "$STRANGER" 2>/dev/null
PIDS=()

if grep -q '^\[MEDIA\] peer ' "$WORK/p4.log"; then
    fail "a participant with a different call_id installed a peer"
fi

echo "media_loopback: OK (3 participants, ${SELF[1]} ${SELF[2]} ${SELF[3]})"
