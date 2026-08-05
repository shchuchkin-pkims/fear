/**
 * @file test_server_admin.c
 * @brief Чёрный список ключей и список живых сессий.
 *
 * Обе таблицы существуют ради утилиты администрирования, но чёрный список -
 * ещё и правило, по которому сервер отказывает в обслуживании, поэтому
 * проверяется не «пишется ли строка», а то, что чтение и снятие блокировки
 * ведут себя ровно так, как на них рассчитывает вызывающий код.
 */
#include "server_db.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"

int main(void) {
    char tmpl[] = "/tmp/fear-admin-db-XXXXXX";
    CHECK(mkdtemp(tmpl) != NULL);

    char path[512];
    snprintf(path, sizeof path, "%s/db.sqlite", tmpl);
    CHECK(server_db_open(path) == 0);

    uint8_t pk[32], other[32];
    memset(pk, 0xA1, sizeof pk);
    memset(other, 0xB2, sizeof other);

    /* --- чёрный список ---------------------------------------------------- */
    CHECK(server_db_is_blocked(pk) == 0);
    CHECK(server_db_block_key(pk, "spam") == 0);
    CHECK(server_db_is_blocked(pk) == 1);
    /* Блокировка одного ключа - это блокировка одного ключа. */
    CHECK(server_db_is_blocked(other) == 0);

    /* Повторная блокировка не ошибка: администратор мог уточнить причину. */
    CHECK(server_db_block_key(pk, "spam, повторно") == 0);
    CHECK(server_db_is_blocked(pk) == 1);

    CHECK(server_db_unblock_key(pk) == 1);
    CHECK(server_db_is_blocked(pk) == 0);
    /* Снять несуществующую - не ошибка, но и не «сняли». */
    CHECK(server_db_unblock_key(pk) == 0);

    /* Заблокированный ключ не может занять имя. Это и есть то единственное
     * место, где сервер видит ключ и потому может отказать. */
    CHECK(server_db_register_handle("blockeduser", pk) == HANDLE_REGISTER_OK);
    CHECK(server_db_block_key(pk, NULL) == 0);
    CHECK(server_db_is_blocked(pk) == 1);
    /* Сама запись имени при этом не пропадает: блокировка - это отказ в
     * обслуживании, а не удаление, и снимающий её администратор ожидает
     * увидеть всё как было. */
    uint8_t found[32];
    CHECK(server_db_lookup_handle("blockeduser", found) == 0);
    CHECK(memcmp(found, pk, 32) == 0);

    /* --- живые сессии ------------------------------------------------------ */
    server_db_sessions_reset(4242);
    server_db_session_add(7, "alice", "room1", "10.0.0.1", 0);
    server_db_session_add(8, "bob", "room1", "10.0.0.2", 1);
    server_db_session_remove(7);
    /* Ни одна из этих функций не возвращает ошибку намеренно: сервер не
     * должен ронять соединение из-за того, что не смог обновить витрину
     * для администратора. Проверяем, что они выполняются и не портят базу -
     * следующее обращение к ней обязано работать. */
    CHECK(server_db_is_blocked(pk) == 1);

    server_db_close();

    /* Перезапуск: сессии от прошлого прогона никого не описывают, а
     * блокировки переживают его. */
    CHECK(server_db_open(path) == 0);
    CHECK(server_db_is_blocked(pk) == 1);
    server_db_sessions_reset(4243);
    CHECK(server_db_is_blocked(pk) == 1);
    server_db_close();

    unlink(path);
    rmdir(tmpl);
    return t_report("test_server_admin");
}
