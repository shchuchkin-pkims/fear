#!/usr/bin/env bash
# Звонок обязан завершаться, когда его просят, даже если в нём тихо.
#
# В режиме relay поток приёма читал TCP-сокет ретранслятора без таймаута.
# Стоило собеседникам уйти первыми - и данных больше не было: поток сидел в
# recv вечно, video_call_stop ждал его в pthread_join, процесс не выходил.
# GUI ждал две секунды и добивал его SIGKILL: разбор не выполнялся никогда,
# ключи не затирались, а камера оставалась занятой для следующего звонка.
# SIGTERM же - то, чем GUI кладёт трубку, - и вовсе не был штатным выходом.
#
# Здесь звонок подключается к серверу, где больше никого нет, и получает
# сначала SIGINT, потом (в новом процессе) SIGTERM. Оба раза он обязан выйти
# за три секунды, дойти до конца разбора и не назвать свою же остановку
# потерей соединения. --no-video --no-audio: ни камеры, ни звука, ни окна -
# тест годится и для CI без устройств.
#
# args: [1] fear  [2] video_call
set -u

# Окно звонку не нужно, но SDL_Init требует видеодрайвер и без --no-video:
# на машине без дисплея (CI) звонок иначе выходит сразу, а на машине с
# дисплеем тест лез бы в сеанс того, кто за ней сидит.
export SDL_VIDEODRIVER=dummy

FEAR_BIN=$(readlink -f "${1:?usage: call_quit.sh /path/to/fear /path/to/video_call}")
VC_BIN=$(readlink -f "${2:?missing video_call path}")

WORK=$(mktemp -d /tmp/fear-callquit-XXXXXX)
PORT=$(( 20000 + ($$ + 3571) % 20000 ))
SERVER_PID=""
VC_PID=""

cleanup() {
    [ -n "$VC_PID" ] && kill -KILL "$VC_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

( cd "$WORK" && exec "$FEAR_BIN" server --port "$PORT" ) > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || { echo "FAIL: server did not start"; exit 1; }

head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/key"
RC=0

for SIG in INT TERM; do
    CALL_ID=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    # exec: $! должен быть PID самого video_call, а не оболочки вокруг него.
    exec "$VC_BIN" relay 127.0.0.1 "$PORT" --room "r:call-quit-$SIG" --name "quitter$SIG" \
        --call-id "$CALL_ID" --no-video --no-audio --no-sign \
        < "$WORK/key" > "$WORK/vc-$SIG.log" 2>&1 &
    VC_PID=$!
    sleep 2
    if ! kill -0 "$VC_PID" 2>/dev/null; then
        echo "FAIL: video_call exited before it was asked to (SIG$SIG run)"
        cat "$WORK/vc-$SIG.log"; RC=1; VC_PID=""; continue
    fi

    kill -"$SIG" "$VC_PID"
    for _ in $(seq 1 30); do
        kill -0 "$VC_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$VC_PID" 2>/dev/null; then
        echo "FAIL: SIG$SIG did not stop a quiet call within 3 s"
        RC=1
        kill -KILL "$VC_PID" 2>/dev/null
    elif ! grep -q "Video call ended" "$WORK/vc-$SIG.log"; then
        echo "FAIL: SIG$SIG stopped the call without its teardown"
        cat "$WORK/vc-$SIG.log"; RC=1
    elif grep -q "TCP connection lost" "$WORK/vc-$SIG.log"; then
        echo "FAIL: SIG$SIG stop was reported as a lost connection"
        RC=1
    else
        echo "ok   SIG$SIG stops a quiet call cleanly"
    fi
    wait "$VC_PID" 2>/dev/null
    VC_PID=""
done

[ $RC -eq 0 ] && echo "PASS: a call stops when asked, even with nobody talking"
exit $RC
