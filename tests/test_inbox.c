/**
 * @file test_inbox.c
 * @brief Офлайн-ящик: квоты, срок хранения и чужие письма.
 *
 * Проверяется не «пишется ли строка», а правила, на которые рассчитывает
 * остальной код: выключенное хранение действительно ничего не хранит,
 * квота ограничивает один адрес и не задевает соседний, а удалить письмо
 * можно только зная его адрес - иначе номер записи был бы достаточным
 * основанием стереть чужую почту.
 */
#include "server_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"

static void addr_fill(uint8_t a[INBOX_ADDR_BYTES], uint8_t v) {
    memset(a, v, INBOX_ADDR_BYTES);
}

int main(void) {
    char tmpl[] = "/tmp/fear-inbox-XXXXXX";
    CHECK(mkdtemp(tmpl) != NULL);
    char path[512];
    snprintf(path, sizeof path, "%s/db.sqlite", tmpl);
    CHECK(server_db_open(path) == 0);

    uint8_t a1[INBOX_ADDR_BYTES], a2[INBOX_ADDR_BYTES];
    addr_fill(a1, 0x11);
    addr_fill(a2, 0x22);
    const uint8_t body[] = "sealed";

    /* --- выключено значит выключено ---------------------------------- */
    server_db_inbox_set_ttl(0);
    CHECK(server_db_inbox_put(a1, body, sizeof body) == INBOX_PUT_DISABLED);
    inbox_item_t items[INBOX_FETCH_LIMIT];
    CHECK(server_db_inbox_fetch(a1, items, INBOX_FETCH_LIMIT) == 0);

    /* --- обычный оборот ------------------------------------------------ */
    server_db_inbox_set_ttl(3600);
    CHECK(server_db_inbox_put(a1, body, sizeof body) == INBOX_PUT_OK);
    CHECK(server_db_inbox_put(a1, body, sizeof body) == INBOX_PUT_OK);
    CHECK(server_db_inbox_put(a2, body, sizeof body) == INBOX_PUT_OK);

    size_t n = server_db_inbox_fetch(a1, items, INBOX_FETCH_LIMIT);
    CHECK(n == 2);
    CHECK(items[0].id < items[1].id);           /* старые первыми */
    CHECK(items[0].len == sizeof body);
    CHECK(memcmp(items[0].ciphertext, body, sizeof body) == 0);

    /* Выдача не удаляет: оборванное соединение не должно терять почту. */
    CHECK(server_db_inbox_fetch(a1, items, INBOX_FETCH_LIMIT) == 2);

    /* --- удалить можно только своё ------------------------------------- */
    int64_t ids[2] = { items[0].id, items[1].id };
    server_db_inbox_delete(a2, ids, 2);         /* чужим адресом - мимо */
    CHECK(server_db_inbox_fetch(a1, items, INBOX_FETCH_LIMIT) == 2);
    for (size_t i = 0; i < 2; i++) free(items[i].ciphertext);

    server_db_inbox_delete(a1, ids, 2);
    CHECK(server_db_inbox_fetch(a1, items, INBOX_FETCH_LIMIT) == 0);
    /* Соседний адрес не задет. */
    n = server_db_inbox_fetch(a2, items, INBOX_FETCH_LIMIT);
    CHECK(n == 1);
    free(items[0].ciphertext);

    /* --- квота по числу записей ---------------------------------------- */
    for (int i = 0; i < INBOX_MAX_ITEMS_PER_ADDR; i++) {
        inbox_put_result_t r = server_db_inbox_put(a1, body, sizeof body);
        CHECK(r == INBOX_PUT_OK);
    }
    CHECK(server_db_inbox_put(a1, body, sizeof body) == INBOX_PUT_FULL);
    /* Полный ящик соседа не мешает: квота считается по адресу. */
    CHECK(server_db_inbox_put(a2, body, sizeof body) == INBOX_PUT_OK);

    /* --- сводка --------------------------------------------------------- */
    int64_t cnt = 0, bytes = 0, addrs = 0;
    server_db_inbox_stats(&cnt, &bytes, &addrs);
    CHECK(cnt == INBOX_MAX_ITEMS_PER_ADDR + 2);
    CHECK(addrs == 2);
    CHECK(bytes == cnt * (int64_t)sizeof body);

    /* --- срок хранения --------------------------------------------------- */
    /* Час назад ничего не устарело. */
    server_db_inbox_expire();
    server_db_inbox_stats(&cnt, NULL, NULL);
    CHECK(cnt == INBOX_MAX_ITEMS_PER_ADDR + 2);

    /* Нулевой срок - выключатель, и он выбрасывает накопленное: иначе
     * выключение хранения ничего бы не выключало. */
    server_db_inbox_set_ttl(0);
    server_db_inbox_expire();
    server_db_inbox_stats(&cnt, NULL, &addrs);
    CHECK(cnt == 0);
    CHECK(addrs == 0);

    server_db_close();
    unlink(path);
    rmdir(tmpl);
    return t_report("test_inbox");
}
