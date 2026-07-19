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
