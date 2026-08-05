/**
 * @file server_db.h
 * @brief SQLite-backed state for the F.E.A.R. relay server (Phase B-2).
 *
 * The relay was historically stateless; this module gives it a persistent
 * `handles` registry (Mastodon-style `@username` claims keyed to identity_pk)
 * and a `user_blobs` store (for the encrypted-contacts blob in Phase B-3).
 *
 * Schema v1:
 *   handles(handle TEXT PRIMARY KEY, identity_pk BLOB(32) NOT NULL,
 *           claimed_at INTEGER NOT NULL)
 *   user_blobs(identity_pk BLOB NOT NULL, blob_type TEXT NOT NULL,
 *              ciphertext BLOB NOT NULL, updated_at INTEGER NOT NULL,
 *              PRIMARY KEY (identity_pk, blob_type))
 *
 * Path: $FEAR_SERVER_DB or `./fear-server.sqlite` relative to the CWD the
 * server was launched from. Single connection, single-thread (the relay is
 * already single-threaded around its select() loop).
 */
#ifndef FEAR_SERVER_DB_H
#define FEAR_SERVER_DB_H

#include <stddef.h>
#include <stdint.h>

/** Result codes from server_db_register_handle. */
typedef enum {
    HANDLE_REGISTER_OK         = 0,  /* claim recorded */
    HANDLE_REGISTER_CONFLICT   = 1,  /* handle taken by a different identity_pk */
    HANDLE_REGISTER_INVALID    = 2,  /* malformed handle string */
    HANDLE_REGISTER_DB_ERROR   = 3,
} handle_register_result_t;

/**
 * Open / create the server DB file. Idempotent — calling twice is a no-op.
 * @param path Absolute or relative DB path; pass NULL to use the default.
 * @return 0 on success, -1 on error.
 */
int  server_db_open(const char *path);

/** Close the DB. Safe to call without a prior open. */
void server_db_close(void);

/**
 * Validate a handle string.
 * Rules: 3..32 chars; first char alpha; rest alpha/num/underscore/dot/hyphen.
 * Lowercase-only on storage; we don't accept Unicode for now.
 */
int  server_db_handle_is_valid(const char *handle);

/**
 * Register `handle` to `pk`. If the same `pk` already owns it → still OK.
 * If a different `pk` owns it → CONFLICT.
 */
handle_register_result_t server_db_register_handle(
    const char *handle, const uint8_t pk[32]);

/**
 * Look up a handle. Writes the owner's pk into `pk_out` on success.
 * @return 0 on found, 1 on not found, -1 on db error.
 */
int  server_db_lookup_handle(const char *handle, uint8_t pk_out[32]);

/**
 * Reverse lookup — given an identity_pk, return the handle it registered
 * (if any). Used by clients after identity import to detect that a handle
 * is already claimed for them on this server, so the user is not asked
 * to register again.
 *
 * @param pk           32-byte identity public key.
 * @param handle_out   Caller-supplied buffer; receives a NUL-terminated
 *                     handle string on success.
 * @param handle_cap   Capacity of handle_out (>= 64 recommended).
 * @return 0 on found, 1 on not found, -1 on db error.
 */
int  server_db_lookup_handle_by_pk(const uint8_t pk[32],
                                   char *handle_out, size_t handle_cap);

/**
 * Store / replace an encrypted blob for `pk` of kind `blob_type`.
 * Used for the contacts blob (Phase B-3) and any future per-user state.
 * @return 0 on success, -2 if the identity's storage quota is exceeded,
 *         -1 on any other error.
 */
int  server_db_put_blob(const uint8_t pk[32], const char *blob_type,
                        const uint8_t *cipher, size_t cipher_len);

/**
 * Fetch the most recent blob. `out` is malloc'd; caller frees.
 * @return 0 on success, 1 on not found, -1 on db error.
 */
int  server_db_get_blob(const uint8_t pk[32], const char *blob_type,
                        uint8_t **out, size_t *out_len);

/* ------------------------------------------------------------------ *
 * Administration
 *
 * Two tables the relay itself only writes, and the admin tool reads.
 * ------------------------------------------------------------------ */

/**
 * Refuse to serve an identity key.
 *
 * What this can and cannot do is worth being precise about. The relay sees
 * an identity key only where the protocol hands it one: registering a
 * handle, looking one up by key, and the signed challenge that guards a
 * blob. It never sees the key of an ordinary chat connection - that is the
 * point of the design, and it is why a member's identity is announced inside
 * the room's own encryption rather than to the server.
 *
 * So a block stops the key from claiming a name, being found by one, or
 * keeping anything in the blob store. It does not stop whoever holds it from
 * joining a room, because the relay cannot tell that they have. Making it
 * able to tell would mean every client proving its identity to the server on
 * connect, which would hand the operator exactly the list of who is talking
 * that the rest of this design goes out of its way not to produce.
 */
int server_db_block_key(const uint8_t pk[32], const char *reason);

/** Lift a block. Returns 1 if there was one, 0 if not, -1 on error. */
int server_db_unblock_key(const uint8_t pk[32]);

/** 1 if blocked, 0 if not. Errors read as "not blocked" so that a database
 *  problem cannot lock everybody out. */
int server_db_is_blocked(const uint8_t pk[32]);

/**
 * Start a fresh record of who is connected.
 *
 * Live state lives in the server's memory, so the table is a projection of
 * it, cleared at startup: rows from a run that crashed describe nobody. The
 * heartbeat is what lets a reader tell a busy relay from a dead one.
 */
void server_db_sessions_reset(long pid);

/** Note a connection that has told us its name and room. */
void server_db_session_add(int fd, const char *name, const char *room,
                           const char *addr, int is_media);

/** Forget one. Called wherever a client leaves the array. */
void server_db_session_remove(int fd);

/**
 * Как часто ретранслятор отмечается живым, в секундах.
 *
 * Значение попадает и в саму базу, чтобы утилите не приходилось его
 * угадывать: разъехавшись, эти два числа сделали бы работающий сервер
 * «мёртвым» на экране администратора.
 */
#define SERVER_HEARTBEAT_SEC 10

/** Say the relay is still alive. Cheap; called from the idle scan. */
void server_db_heartbeat(void);

/* ------------------------------------------------------------------ *
 * Offline inbox
 *
 * Письмо тому, кого сейчас нет в комнате. Ретранслятор по-прежнему не
 * знает, кто с кем говорит: запись адресована не открытому ключу, а
 * «слепому адресу» - хешу от общего секрета пары. Вычислить его может
 * только тот, у кого этот секрет есть, то есть двое собеседников; для
 * сервера это просто непрозрачная метка.
 *
 * Знание адреса и есть право забрать. Подписи тут не проверить: ключа
 * пары у сервера нет и быть не должно, а значит и MAC под ним он не
 * сосчитает. Адрес выводится из секрета, известного только двоим, так
 * что «кто знает адрес» и «кому письмо» - это одно и то же множество.
 * Слабое место - канал: пока нет TLS, адрес идёт по проводу открытым.
 * Тот, кто слушает канал, и так может выбросить трафик, а содержимое
 * ему в любом случае не прочесть.
 * ------------------------------------------------------------------ */

/** Длина слепого адреса. */
#define INBOX_ADDR_BYTES 32

/** Сколько записей и байтов держим на один адрес. */
#define INBOX_MAX_ITEMS_PER_ADDR 200
#define INBOX_MAX_BYTES_PER_ADDR (5 * 1024 * 1024)

/** Наибольшее число записей, выдаваемых за один запрос. */
#define INBOX_FETCH_LIMIT 32

typedef enum {
    INBOX_PUT_OK = 0,
    INBOX_PUT_DISABLED,   /**< оператор выключил хранение */
    INBOX_PUT_FULL,       /**< у адреса кончилась квота */
    INBOX_PUT_ERROR,
} inbox_put_result_t;

/** Одна запись, как её отдаёт server_db_inbox_fetch. */
typedef struct {
    int64_t  id;
    uint8_t  addr[INBOX_ADDR_BYTES];
    uint8_t *ciphertext;   /**< malloc'нуто, освобождает вызывающий */
    size_t   len;
    int64_t  created_at;
} inbox_item_t;

/**
 * Срок хранения в секундах; 0 - хранение выключено.
 *
 * Живёт в базе рядом с остальным состоянием сервера, чтобы утилита
 * администрирования показывала действующую политику, а не догадывалась.
 */
void   server_db_inbox_set_ttl(int64_t ttl_seconds);
int64_t server_db_inbox_ttl(void);

/** Положить письмо по адресу. */
inbox_put_result_t server_db_inbox_put(const uint8_t addr[INBOX_ADDR_BYTES],
                                       const uint8_t *cipher, size_t len);

/**
 * Забрать до @p cap записей по адресу, самые старые первыми.
 *
 * Записи не удаляются: удаляет отдельный вызов, когда получатель
 * подтвердил, что письмо у него. Иначе оборванное соединение теряло бы
 * почту молча.
 */
size_t server_db_inbox_fetch(const uint8_t addr[INBOX_ADDR_BYTES],
                             inbox_item_t *out, size_t cap);

/** Удалить записи по идентификаторам, но только принадлежащие адресу. */
void server_db_inbox_delete(const uint8_t addr[INBOX_ADDR_BYTES],
                            const int64_t *ids, size_t n);

/** Выбросить всё, что пережило срок хранения. */
void server_db_inbox_expire(void);

/** Сводка для утилиты администрирования. */
void server_db_inbox_stats(int64_t *items, int64_t *bytes, int64_t *addrs);

#endif
