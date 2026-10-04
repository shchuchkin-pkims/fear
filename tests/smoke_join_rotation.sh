#!/usr/bin/env bash
# Integration test: a member that came in through the ECDH join still takes
# part in the next election.
#
# The relay announces a new connection's arrival the moment it registers it,
# and a joiner registers with its KEY_REQUEST - long before the room key comes
# back. The join used to read frames itself and drop everything that was not
# the answer, the arrival list included. Its main loop then took the NEXT
# membership change for its own arrival, and a member sits out the election
# for its own arrival. When the joiner was the member the room elected for
# that change, nobody rotated: the newest member stayed on generation zero,
# unable to read the room, while everyone else carried on as if all was well.
#
# smoke_rotation.sh cannot see this. It hands all three members the same key
# up front, so none of them ever goes through the join.
#
# The roles are not left to chance. Election is by the lowest identity key, so
# the creator is whichever of two fresh identities has the higher key and the
# joiner the lower: when the third member arrives, the joiner is the only
# member allowed to rotate. With the old join that rotation never happens, on
# every run, which is what makes this a regression test rather than a dice
# roll.
#
# Each client gets its own HOME so ~/.fear is sandboxed and the real user
# profile is never touched.

set -u

FEAR_BIN="${1:?usage: smoke_join_rotation.sh /path/to/fear}"
FEAR_BIN=$(readlink -f "$FEAR_BIN")

WORK=$(mktemp -d /tmp/fear-joinrot-XXXXXX)
PORT=$(( 20000 + ($$ + 4801) % 20000 ))
ROOM=joinrotatest

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
    for n in x y c; do
        echo "--- $n.log ---" >&2
        cat "$WORK/$n.log" 2>/dev/null >&2
    done
    exit 1
}

mkdir -p "$WORK/x" "$WORK/y" "$WORK/c" "$WORK/server"

for n in x y c; do
    HOME="$WORK/$n" "$FEAR_BIN" gen-identity >/dev/null 2>&1 || fail "$n gen-identity"
done

# The public key as lowercase hex, for an unsigned byte-wise comparison: the
# same order memcmp gives the election.
pkhex() {
    local b64
    b64=$(sed -n 's/^PK://p' "$WORK/$1/.fear/identity" | tr '_-' '/+')
    while [ $(( ${#b64} % 4 )) -ne 0 ]; do b64="$b64="; done
    printf '%s' "$b64" | base64 -d | od -An -tx1 | tr -d ' \n'
}

PKX=$(pkhex x); PKY=$(pkhex y)
[ ${#PKX} -eq 64 ] && [ ${#PKY} -eq 64 ] || fail "could not read the identity keys"
if [[ "$PKX" > "$PKY" ]]; then CREATOR=x; JOINER=y; else CREATOR=y; JOINER=x; fi

( cd "$WORK/server" && exec "$FEAR_BIN" server --port "$PORT" ) \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server did not start on port $PORT"

# A member is a client reading from a fifo, so that what it says is under our
# control. The fifo is held open, or the client sees EOF between two messages
# and leaves on its own.
start() {
    n=$1; mode=$2
    mkfifo "$WORK/$n.in"
    exec {fd}<> "$WORK/$n.in"
    eval "FD_$n=$fd"
    ( HOME="$WORK/$n" exec "$FEAR_BIN" client --host 127.0.0.1 --port "$PORT" \
        --room "$ROOM" --name "$n" "$mode" \
        < "$WORK/$n.in" ) > "$WORK/$n.log" 2>&1 &
    PIDS="$PIDS $!"
    sleep 4
}

say() {
    echo "$2" > "$WORK/$1.in"
    sleep 2
}

start "$CREATOR" --create
start "$JOINER" --join         # change 1: the creator rotates, nobody else can
grep -q "room key is now generation 1" "$WORK/$JOINER.log" \
    || fail "the joiner did not follow the creator to generation 1"

start c --join                 # change 2: only the joiner may rotate
sleep 6                        # settle, and the deadline for a silent member
say "$CREATOR" "after-c-arrived"
sleep 2

# --- what has to be true -------------------------------------------------
grep -q "room key is now generation 2, sealed for 3 member(s)" "$WORK/$JOINER.log" \
    || fail "the member that joined through ECDH did not rotate when it was elected"

grep -q "room key is now generation 2" "$WORK/c.log" \
    || fail "the newest member was left on an old generation"

grep -q "after-c-arrived" "$WORK/c.log" \
    || fail "the newest member cannot read the room"

gens=$(grep -c "room key is now generation" "$WORK/$CREATOR.log" 2>/dev/null || true)
[ "$gens" = "2" ] || fail "two membership changes produced $gens generations at the creator, expected 2"

echo "PASS: a member that joined through ECDH rotates when the room elects it"
