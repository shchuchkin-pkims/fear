#!/usr/bin/env bash
# Личное письмо через офлайн-ящик доходит до адресата - и только до него.
#
# Живой тест на ПК и телефоне нашёл две беды. Ящик был один на пару, и
# каждая сторона забирала из него всё: отправитель через двадцать секунд
# получал своё же письмо «от собеседника» и удалял его с сервера, а если
# успевал первым, адресат не получал ничего. А телефон, сидя в general,
# показывал письмо в general, а не в личном чате.
#
# Здесь A один в личной комнате пары и пишет; B и C сидят в general.
# Утверждается:
#   - B получает письмо строкой [INBOX] с личной комнатой, а не в general;
#   - A своего письма обратно не получает;
#   - C, третий в general, не получает ничего;
#   - письмо показывается ровно один раз, даже если ящик спросили
#     несколько раз подряд: GUI регистрирует ящики пачкой, и раньше каждый
#     /inbox-add давал свой запрос, а письмо приходило в каждом ответе. На
#     localhost ответ возвращается раньше, чем уходит следующий запрос, и
#     этого не видно, поэтому B ходит к серверу через прокси, задерживающий
#     ответы на 200 мс, - как Wi-Fi до малинки, где это и нашлось.
#
# Порядок опросов задан, а не оставлен таймеру: повторный /inbox-add
# опрашивает ящик сразу. Первым спрашивает A - с общим ящиком он забрал бы
# своё письмо и удалил его, и B не получил бы ничего; вторым - B.
#
# args: [1] fear  [2] pm_keys
set -u

FEAR=$(readlink -f "${1:?usage: inbox_direction.sh /path/to/fear /path/to/pm_keys}")
PMKEYS=$(readlink -f "${2:?missing pm_keys path}")

WORK=$(mktemp -d /tmp/fear-inboxdir-XXXXXX)
PORT=$(( 20000 + ($$ + 6151) % 20000 ))
SLOW_PORT=$(( PORT + 1 ))
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
    echo "FAIL: $1"
    for n in a b c; do echo "--- $n.log"; cat "$WORK/$n.log" 2>/dev/null; done
    exit 1
}

# Личности - в песочнице и без системного хранилища ключей: тест не должен
# заводить записей в keyring того, кто его запускает.
unset DBUS_SESSION_BUS_ADDRESS
for n in a b c; do
    mkdir -p "$WORK/$n"
    HOME="$WORK/$n" "$FEAR" gen-identity >/dev/null 2>&1 || fail "gen-identity $n"
done

mapfile -t AB < <("$PMKEYS" "$WORK/a/.fear/identity" "$WORK/b/.fear/identity")
mapfile -t BA < <("$PMKEYS" "$WORK/b/.fear/identity" "$WORK/a/.fear/identity")
ROOM=${AB[0]}; KPM=${AB[1]}; PK_B=${AB[2]}; PK_A=${BA[2]}
[ "$ROOM" = "${BA[0]}" ] && [ "$KPM" = "${BA[1]}" ] || fail "the pair key differs between the two sides"
printf '%s' "$KPM" > "$WORK/kpm"

( cd "$WORK" && exec "$FEAR" server --port "$PORT" ) > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
python3 "$(dirname "$0")/delay_proxy.py" "$SLOW_PORT" "$PORT" 200 &
PIDS="$PIDS $!"
sleep 1

start() {   # name port room mode-args...
    local n=$1 port=$2 room=$3; shift 3
    mkfifo "$WORK/$n.in"
    exec {fd}<> "$WORK/$n.in"
    ( HOME="$WORK/$n" exec "$FEAR" client --host 127.0.0.1 --port "$port" \
        --room "$room" --name "$n" "$@" < "$WORK/$n.in" ) > "$WORK/$n.log" 2>&1 &
    PIDS="$PIDS $!"
    sleep 3
}
say() { echo "$2" > "$WORK/$1.in"; sleep 1; }

start b "$SLOW_PORT" general --create
start c "$PORT" general --join
start a "$PORT" "$ROOM" --key-file "$WORK/kpm"

say b "/inbox-add $ROOM $KPM $PK_A"
say a "/inbox-add $ROOM $KPM $PK_B"
say a "secret-for-b-7Q"
say a "/inbox-add $ROOM $KPM $PK_B"     # A опрашивает первым
sleep 2
# Затем B - пачкой, как это делает GUI при подключении: три запроса уходят
# раньше, чем вернётся первый ответ.
for _ in 1 2 3; do echo "/inbox-add $ROOM $KPM $PK_A" > "$WORK/b.in"; sleep 0.05; done
sleep 4

grep -q "^\[INBOX\] $ROOM a: secret-for-b-7Q" "$WORK/b.log" \
    || fail "B did not get the letter in the private chat"
n=$(grep -c "^\[INBOX\] $ROOM a: secret-for-b-7Q" "$WORK/b.log")
[ "$n" -eq 1 ] || fail "B was shown the letter $n times"
grep -q "\[INBOX\]" "$WORK/a.log" \
    && fail "A got its own letter back from the mailbox"
grep -q "secret-for-b-7Q" "$WORK/c.log" \
    && fail "C in general saw a private letter"

echo "PASS: a private letter reaches its addressee only, in the private chat"
