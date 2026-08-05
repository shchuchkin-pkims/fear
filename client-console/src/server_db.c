#include "server_db.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

static sqlite3 *g_db = NULL;

static int exec_or_log(const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[server-db] %s: %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int ensure_schema(void) {
    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS handles ("
        "  handle      TEXT PRIMARY KEY,"
        "  identity_pk BLOB NOT NULL,"
        "  claimed_at  INTEGER NOT NULL"
        ")") < 0) return -1;

    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS user_blobs ("
        "  identity_pk BLOB NOT NULL,"
        "  blob_type   TEXT NOT NULL,"
        "  ciphertext  BLOB NOT NULL,"
        "  updated_at  INTEGER NOT NULL,"
        "  PRIMARY KEY (identity_pk, blob_type)"
        ")") < 0) return -1;

    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS blocked_keys ("
        "  identity_pk BLOB PRIMARY KEY,"
        "  reason      TEXT,"
        "  blocked_at  INTEGER NOT NULL"
        ")") < 0) return -1;

    /* Not persistent state so much as a window into memory: cleared at
     * startup, because rows left by a run that crashed describe nobody. */
    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS live_sessions ("
        "  fd           INTEGER PRIMARY KEY,"
        "  name         TEXT,"
        "  room         TEXT,"
        "  addr         TEXT,"
        "  is_media     INTEGER NOT NULL DEFAULT 0,"
        "  connected_at INTEGER NOT NULL"
        ")") < 0) return -1;

    /* Почта тому, кого нет в комнате. Адрес слепой - см. server_db.h. */
    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS inbox ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  addr        BLOB NOT NULL,"
        "  ciphertext  BLOB NOT NULL,"
        "  created_at  INTEGER NOT NULL"
        ")") < 0) return -1;
    if (exec_or_log(
        "CREATE INDEX IF NOT EXISTS inbox_by_addr ON inbox(addr, id)") < 0) return -1;

    if (exec_or_log(
        "CREATE TABLE IF NOT EXISTS server_state ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ")") < 0) return -1;

    return 0;
}

int server_db_open(const char *path) {
    if (g_db) return 0;
    const char *p = path ? path : (getenv("FEAR_SERVER_DB") ? getenv("FEAR_SERVER_DB")
                                                            : "./fear-server.sqlite");
    int rc = sqlite3_open(p, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[server-db] open(%s) failed: %s\n", p, sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }
    /* WAL: better concurrency between read/write even though we're
       single-threaded today, and resilient to crashes mid-write. */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    if (ensure_schema() < 0) {
        server_db_close();
        return -1;
    }
    fprintf(stderr, "[server-db] opened %s\n", p);
    return 0;
}

void server_db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

int server_db_handle_is_valid(const char *h) {
    if (!h) return 0;
    size_t len = strlen(h);
    if (len < 3 || len > 32) return 0;
    if (!(isalpha((unsigned char)h[0]))) return 0;
    for (size_t i = 1; i < len; ++i) {
        unsigned char c = (unsigned char)h[i];
        if (!(isalnum(c) || c == '_' || c == '.' || c == '-')) return 0;
    }
    return 1;
}

handle_register_result_t server_db_register_handle(
        const char *handle, const uint8_t pk[32]) {
    if (!g_db) return HANDLE_REGISTER_DB_ERROR;
    if (!server_db_handle_is_valid(handle)) return HANDLE_REGISTER_INVALID;

    /* Шаг 1: запрашиваемый handle уже занят кем-то другим? */
    sqlite3_stmt *q = NULL;
    int rc = sqlite3_prepare_v2(g_db,
        "SELECT identity_pk FROM handles WHERE handle = ?", -1, &q, NULL);
    if (rc != SQLITE_OK) return HANDLE_REGISTER_DB_ERROR;
    sqlite3_bind_text(q, 1, handle, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    if (rc == SQLITE_ROW) {
        const void *existing = sqlite3_column_blob(q, 0);
        int existing_len = sqlite3_column_bytes(q, 0);
        const int same_owner =
            (existing_len == 32 && memcmp(existing, pk, 32) == 0);
        sqlite3_finalize(q);
        if (same_owner) return HANDLE_REGISTER_OK;  /* re-claim, no-op */
        return HANDLE_REGISTER_CONFLICT;            /* taken by other pk */
    }
    sqlite3_finalize(q);

    /* Шаг 2: атомарно заменяем все ранее зарегистрированные handle
     * этого pk на новый. Один pk = один handle. Если у pk были другие
     * handle (которые пользователь забросил, когда переименовался) —
     * освобождаем их. Без этого LOOKUP_HANDLE_BY_PK может вернуть
     * устаревшее имя, и новый клиент логинится под старым handle. */
    char *err = NULL;
    rc = sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, &err);
    if (rc != SQLITE_OK) { sqlite3_free(err); return HANDLE_REGISTER_DB_ERROR; }

    sqlite3_stmt *del = NULL;
    rc = sqlite3_prepare_v2(g_db,
        "DELETE FROM handles WHERE identity_pk = ?", -1, &del, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return HANDLE_REGISTER_DB_ERROR;
    }
    sqlite3_bind_blob(del, 1, pk, 32, SQLITE_STATIC);
    rc = sqlite3_step(del);
    sqlite3_finalize(del);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return HANDLE_REGISTER_DB_ERROR;
    }

    sqlite3_stmt *ins = NULL;
    rc = sqlite3_prepare_v2(g_db,
        "INSERT INTO handles(handle, identity_pk, claimed_at) VALUES (?, ?, ?)",
        -1, &ins, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return HANDLE_REGISTER_DB_ERROR;
    }
    sqlite3_bind_text (ins, 1, handle, -1, SQLITE_STATIC);
    sqlite3_bind_blob (ins, 2, pk, 32, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 3, (sqlite3_int64)time(NULL));
    rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        return HANDLE_REGISTER_DB_ERROR;
    }
    sqlite3_exec(g_db, "COMMIT", NULL, NULL, NULL);
    return HANDLE_REGISTER_OK;
}

int server_db_lookup_handle(const char *handle, uint8_t pk_out[32]) {
    if (!g_db) return -1;
    if (!server_db_handle_is_valid(handle)) return 1;

    sqlite3_stmt *q = NULL;
    int rc = sqlite3_prepare_v2(g_db,
        "SELECT identity_pk FROM handles WHERE handle = ?", -1, &q, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(q, 1, handle, -1, SQLITE_STATIC);

    int out = 1;
    if (sqlite3_step(q) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(q, 0);
        if (sqlite3_column_bytes(q, 0) == 32) {
            memcpy(pk_out, blob, 32);
            out = 0;
        }
    }
    sqlite3_finalize(q);
    return out;
}

int server_db_lookup_handle_by_pk(const uint8_t pk[32],
                                  char *handle_out, size_t handle_cap) {
    if (!g_db || !pk || !handle_out || handle_cap < 2) return -1;

    sqlite3_stmt *q = NULL;
    int rc = sqlite3_prepare_v2(g_db,
        "SELECT handle FROM handles WHERE identity_pk = ? LIMIT 1",
        -1, &q, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(q, 1, pk, 32, SQLITE_STATIC);

    int out = 1;
    if (sqlite3_step(q) == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(q, 0);
        int n = sqlite3_column_bytes(q, 0);
        if (txt && n > 0 && (size_t)n < handle_cap) {
            memcpy(handle_out, txt, (size_t)n);
            handle_out[n] = '\0';
            out = 0;
        }
    }
    sqlite3_finalize(q);
    return out;
}

/* Storage quotas (roadmap section 7: 100 KB of blob per user).
 * Ed25519 keypairs cost nothing to generate offline, so BLOB_PUT's signature
 * proves ownership of a key but is not a scarcity barrier: without a quota
 * anyone can mint unlimited identities and fill the server's disk. */
#define BLOB_MAX_BYTES_PER_PK (100 * 1024)
#define BLOB_MAX_TYPES_PER_PK 8

int server_db_put_blob(const uint8_t pk[32], const char *blob_type,
                       const uint8_t *cipher, size_t cipher_len) {
    if (!g_db) return -1;
    if (cipher_len > BLOB_MAX_BYTES_PER_PK) return -2;

    /* Usage already stored for this identity, ignoring the row this call is
     * about to replace (INSERT OR REPLACE overwrites the same pk+blob_type). */
    sqlite3_stmt *cq = NULL;
    sqlite3_int64 used = 0, ntypes = 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COALESCE(SUM(LENGTH(ciphertext)),0), COUNT(*) "
            "FROM user_blobs WHERE identity_pk = ? AND blob_type <> ?",
            -1, &cq, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(cq, 1, pk, 32, SQLITE_STATIC);
        sqlite3_bind_text(cq, 2, blob_type, -1, SQLITE_STATIC);
        if (sqlite3_step(cq) == SQLITE_ROW) {
            used   = sqlite3_column_int64(cq, 0);
            ntypes = sqlite3_column_int64(cq, 1);
        }
    }
    sqlite3_finalize(cq);
    if (used + (sqlite3_int64)cipher_len > BLOB_MAX_BYTES_PER_PK) return -2;
    if (ntypes >= BLOB_MAX_TYPES_PER_PK) return -2;

    sqlite3_stmt *q = NULL;
    int rc = sqlite3_prepare_v2(g_db,
        "INSERT OR REPLACE INTO user_blobs(identity_pk, blob_type, ciphertext, updated_at) "
        "VALUES (?, ?, ?, ?)", -1, &q, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(q, 1, pk, 32, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, blob_type, -1, SQLITE_STATIC);
    sqlite3_bind_blob(q, 3, cipher, (int)cipher_len, SQLITE_STATIC);
    sqlite3_bind_int64(q, 4, (sqlite3_int64)time(NULL));
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : -1;
}

int server_db_get_blob(const uint8_t pk[32], const char *blob_type,
                       uint8_t **out, size_t *out_len) {
    if (!g_db || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    sqlite3_stmt *q = NULL;
    int rc = sqlite3_prepare_v2(g_db,
        "SELECT ciphertext FROM user_blobs WHERE identity_pk = ? AND blob_type = ?",
        -1, &q, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(q, 1, pk, 32, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, blob_type, -1, SQLITE_STATIC);

    int result = 1;
    if (sqlite3_step(q) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(q, 0);
        const void *p = sqlite3_column_blob(q, 0);
        if (n > 0 && p) {
            *out = (uint8_t *)malloc((size_t)n);
            if (*out) {
                memcpy(*out, p, (size_t)n);
                *out_len = (size_t)n;
                result = 0;
            } else {
                result = -1;
            }
        }
    }
    sqlite3_finalize(q);
    return result;
}

/* ------------------------------------------------------------------ *
 * Administration
 * ------------------------------------------------------------------ */

int server_db_block_key(const uint8_t pk[32], const char *reason) {
    if (!g_db || !pk) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO blocked_keys(identity_pk, reason, blocked_at)"
            " VALUES (?, ?, ?)", -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, pk, 32, SQLITE_STATIC);
    if (reason) sqlite3_bind_text(st, 2, reason, -1, SQLITE_STATIC);
    else        sqlite3_bind_null(st, 2);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int server_db_unblock_key(const uint8_t pk[32]) {
    if (!g_db || !pk) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM blocked_keys WHERE identity_pk = ?",
                           -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, pk, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    return sqlite3_changes(g_db) > 0 ? 1 : 0;
}

int server_db_is_blocked(const uint8_t pk[32]) {
    if (!g_db || !pk) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, "SELECT 1 FROM blocked_keys WHERE identity_pk = ?",
                           -1, &st, NULL) != SQLITE_OK) {
        /* A database that cannot be read must not lock everybody out. */
        return 0;
    }
    sqlite3_bind_blob(st, 1, pk, 32, SQLITE_STATIC);
    int blocked = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return blocked;
}

static void state_set(const char *key, const char *value) {
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO server_state(key, value) VALUES (?, ?)",
            -1, &st, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void server_db_sessions_reset(long pid) {
    if (!g_db) return;
    exec_or_log("DELETE FROM live_sessions");
    char buf[64];
    snprintf(buf, sizeof buf, "%lld", (long long)time(NULL));
    state_set("started_at", buf);
    snprintf(buf, sizeof buf, "%ld", pid);
    state_set("pid", buf);
    snprintf(buf, sizeof buf, "%d", SERVER_HEARTBEAT_SEC);
    state_set("heartbeat_period", buf);
    server_db_heartbeat();
}

void server_db_heartbeat(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "%lld", (long long)time(NULL));
    state_set("heartbeat_at", buf);
}

void server_db_session_add(int fd, const char *name, const char *room,
                           const char *addr, int is_media) {
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO live_sessions"
            "(fd, name, room, addr, is_media, connected_at) VALUES (?, ?, ?, ?, ?, ?)",
            -1, &st, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int  (st, 1, fd);
    sqlite3_bind_text (st, 2, name ? name : "", -1, SQLITE_STATIC);
    sqlite3_bind_text (st, 3, room ? room : "", -1, SQLITE_STATIC);
    sqlite3_bind_text (st, 4, addr ? addr : "", -1, SQLITE_STATIC);
    sqlite3_bind_int  (st, 5, is_media ? 1 : 0);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)time(NULL));
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void server_db_session_remove(int fd) {
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM live_sessions WHERE fd = ?",
                           -1, &st, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int(st, 1, fd);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* ------------------------------------------------------------------ *
 * Offline inbox
 * ------------------------------------------------------------------ */

static int64_t g_inbox_ttl = 0;   /* 0 - хранение выключено */

void server_db_inbox_set_ttl(int64_t ttl_seconds) {
    g_inbox_ttl = ttl_seconds > 0 ? ttl_seconds : 0;
    char buf[32];
    snprintf(buf, sizeof buf, "%lld", (long long)g_inbox_ttl);
    state_set("inbox_ttl", buf);
}

int64_t server_db_inbox_ttl(void) { return g_inbox_ttl; }

inbox_put_result_t server_db_inbox_put(const uint8_t addr[INBOX_ADDR_BYTES],
                                       const uint8_t *cipher, size_t len) {
    if (!g_db || !addr || !cipher || len == 0) return INBOX_PUT_ERROR;
    if (g_inbox_ttl <= 0) return INBOX_PUT_DISABLED;

    /* Квота считается по адресу, а не по отправителю: отправителя мы не
     * знаем и знать не хотим. Значит и залить чужой ящик может кто угодно,
     * кому известен адрес - то есть собеседник. Ограничение здесь не от
     * злоумышленника из интернета, а от того, чтобы забытый ящик не рос
     * без предела. */
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0)"
            "  FROM inbox WHERE addr = ?", -1, &q, NULL) != SQLITE_OK) {
        return INBOX_PUT_ERROR;
    }
    sqlite3_bind_blob(q, 1, addr, INBOX_ADDR_BYTES, SQLITE_STATIC);
    int64_t items = 0, bytes = 0;
    if (sqlite3_step(q) == SQLITE_ROW) {
        items = sqlite3_column_int64(q, 0);
        bytes = sqlite3_column_int64(q, 1);
    }
    sqlite3_finalize(q);

    if (items >= INBOX_MAX_ITEMS_PER_ADDR ||
        bytes + (int64_t)len > INBOX_MAX_BYTES_PER_ADDR) {
        return INBOX_PUT_FULL;
    }

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO inbox(addr, ciphertext, created_at) VALUES (?, ?, ?)",
            -1, &ins, NULL) != SQLITE_OK) {
        return INBOX_PUT_ERROR;
    }
    sqlite3_bind_blob (ins, 1, addr, INBOX_ADDR_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob (ins, 2, cipher, (int)len, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 3, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    return (rc == SQLITE_DONE) ? INBOX_PUT_OK : INBOX_PUT_ERROR;
}

size_t server_db_inbox_fetch(const uint8_t addr[INBOX_ADDR_BYTES],
                             inbox_item_t *out, size_t cap) {
    if (!g_db || !addr || !out || cap == 0) return 0;

    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT id, ciphertext, created_at FROM inbox"
            " WHERE addr = ? ORDER BY id LIMIT ?", -1, &q, NULL) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_blob(q, 1, addr, INBOX_ADDR_BYTES, SQLITE_STATIC);
    sqlite3_bind_int (q, 2, (int)cap);

    size_t n = 0;
    while (n < cap && sqlite3_step(q) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(q, 1);
        const int   blen = sqlite3_column_bytes(q, 1);
        if (blen <= 0) continue;
        uint8_t *copy = (uint8_t *)malloc((size_t)blen);
        if (!copy) break;
        memcpy(copy, blob, (size_t)blen);
        out[n].id         = sqlite3_column_int64(q, 0);
        out[n].ciphertext = copy;
        out[n].len        = (size_t)blen;
        out[n].created_at = sqlite3_column_int64(q, 2);
        n++;
    }
    sqlite3_finalize(q);
    return n;
}

void server_db_inbox_delete(const uint8_t addr[INBOX_ADDR_BYTES],
                            const int64_t *ids, size_t n) {
    if (!g_db || !addr || !ids || n == 0) return;

    sqlite3_stmt *del = NULL;
    /* Адрес в условии не для красоты: без него знание чужого номера записи
     * позволяло бы стирать чужую почту. */
    if (sqlite3_prepare_v2(g_db, "DELETE FROM inbox WHERE id = ? AND addr = ?",
                           -1, &del, NULL) != SQLITE_OK) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        sqlite3_reset(del);
        sqlite3_bind_int64(del, 1, (sqlite3_int64)ids[i]);
        sqlite3_bind_blob (del, 2, addr, INBOX_ADDR_BYTES, SQLITE_STATIC);
        sqlite3_step(del);
    }
    sqlite3_finalize(del);
}

void server_db_inbox_expire(void) {
    if (!g_db) return;
    if (g_inbox_ttl <= 0) {
        /* Хранение выключили - выбрасываем и то, что накопилось раньше:
         * оставить его значило бы, что выключатель ничего не выключает. */
        exec_or_log("DELETE FROM inbox");
        return;
    }
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM inbox WHERE created_at < ?",
                           -1, &q, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int64(q, 1, (sqlite3_int64)(time(NULL) - g_inbox_ttl));
    sqlite3_step(q);
    sqlite3_finalize(q);
}

void server_db_inbox_stats(int64_t *items, int64_t *bytes, int64_t *addrs) {
    if (items) *items = 0;
    if (bytes) *bytes = 0;
    if (addrs) *addrs = 0;
    if (!g_db) return;

    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0),"
            "       COUNT(DISTINCT addr) FROM inbox", -1, &q, NULL) != SQLITE_OK) {
        return;
    }
    if (sqlite3_step(q) == SQLITE_ROW) {
        if (items) *items = sqlite3_column_int64(q, 0);
        if (bytes) *bytes = sqlite3_column_int64(q, 1);
        if (addrs) *addrs = sqlite3_column_int64(q, 2);
    }
    sqlite3_finalize(q);
}
