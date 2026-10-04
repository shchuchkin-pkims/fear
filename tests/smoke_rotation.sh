#!/usr/bin/env bash
# Integration test: the room key follows the membership.
#
# Three members join and one leaves, and the four things that have to hold
# are checked end to end:
#
#   * a membership change produces exactly one new generation, not one per
#     member - only the member the room elects rotates
#   * every other member installs that generation from the bundle
#   * the chat does not skip a beat across a rotation
#   * what was said before a member arrived stays unreadable to it, and what
#     is said after one leaves stays unreadable to that one
#
# Unit tests cover the pieces (test_room_keys, test_rotation_bundle); this is
# the one that can catch them being wired together wrongly - a rotation that
# elects two members, or one that nobody but the sender can open.
#
# Each client gets its own HOME so ~/.fear is sandboxed and the real user
# profile is never touched.

set -u

FEAR_BIN="${1:?usage: smoke_rotation.sh /path/to/fear}"
FEAR_BIN=$(readlink -f "$FEAR_BIN")

WORK=$(mktemp -d /tmp/fear-rot-XXXXXX)
PORT=$(( 20000 + ($$ + 7919) % 20000 ))
ROOM=rotatest

SERVER_PID=""
PIDS=""

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    for n in a b c; do
        echo "--- $n.log ---" >&2
        cat "$WORK/$n.log" 2>/dev/null >&2
    done
    exit 1
}

mkdir -p "$WORK/a" "$WORK/b" "$WORK/c" "$WORK/server"

# The room key the three of them start from. b64_decode wants URL-safe
# base64 without padding, which is what the tr/tr pipeline produces.
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$WORK/key"

for n in a b c; do
    HOME="$WORK/$n" "$FEAR_BIN" gen-identity >/dev/null 2>&1 || fail "$n gen-identity"
done

( cd "$WORK/server" && exec "$FEAR_BIN" server --port "$PORT" ) \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server did not start on port $PORT"

# A member is a client reading from a fifo, so that what it says and when it
# leaves are both under our control.
start() {
    n=$1
    mkfifo "$WORK/$n.in"
    # Held open from here, or the client sees EOF between two messages and
    # disconnects on its own.
    exec {fd}<> "$WORK/$n.in"
    eval "FD_$n=$fd"
    ( HOME="$WORK/$n" exec "$FEAR_BIN" client --host 127.0.0.1 --port "$PORT" \
        --room "$ROOM" --name "$n" --key-file "$WORK/key" \
        < "$WORK/$n.in" ) > "$WORK/$n.log" 2>&1 &
    eval "PID_$n=\$!"
    PIDS="$PIDS $!"
    sleep 4
}

say() {
    echo "$2" > "$WORK/$1.in"
    sleep 2
}

start a
start b                       # change 1
say a "before-c-arrived"
start c                       # change 2
say b "after-c-arrived"

eval "kill \$PID_b" 2>/dev/null   # change 3
sleep 6
say a "after-b-left"
sleep 2

# --- what has to be true -------------------------------------------------
gens=$(grep -c "room key is now generation" "$WORK/a.log" 2>/dev/null || true)
[ "$gens" = "3" ] || fail "three membership changes produced $gens generations, expected 3"

grep -q "room key is now generation 3" "$WORK/c.log" \
    || fail "c did not follow the room to generation 3"

# The message sent right after c arrived is the one a mis-elected joiner
# silently loses: it rotates to a generation the room has already used, so
# everyone else discards its bundle and it can no longer read them.
grep -q "after-c-arrived" "$WORK/c.log" \
    || fail "c could not read the room straight after joining it"

grep -q "after-b-left" "$WORK/c.log" \
    || fail "c stopped receiving after a rotation"

grep -q "before-c-arrived" "$WORK/c.log" \
    && fail "c read what was said before it joined"

grep -q "after-b-left" "$WORK/b.log" \
    && fail "b read what was said after it left"

# A room that elects two rotators is the failure this test exists for, and it
# shows up as a member refusing the other's bundle.
grep -q "not this room's rotator" "$WORK"/[abc].log \
    && fail "the room did not agree on who rotates"

echo "smoke_rotation: OK"
