/**
 * Unit tests: encrypted identity backup (.fbk) - Argon2id + AES-256-GCM.
 *
 * Every negative import costs one Argon2id pass (~64 MB, tens of ms),
 * so the corruption cases are kept to a handful of representative bytes.
 */
#include "identity_backup.h"
#include "identity.h"
#include "test_util.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t pk[IDENTITY_PK_BYTES], sk[IDENTITY_SK_BYTES];
    CHECK(crypto_sign_keypair(pk, sk) == 0);

    const char *password = "correct horse battery staple";

    /* --- buffer roundtrip ----------------------------------------------- */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    CHECK(identity_backup_export_buf(&blob, &blob_len, sk, pk, password) == 0);
    CHECK(blob != NULL && blob_len > 0);

    uint8_t sk2[IDENTITY_SK_BYTES], pk2[IDENTITY_PK_BYTES];
    CHECK(identity_backup_import_buf(blob, blob_len, password, sk2, pk2) == 0);
    CHECK(memcmp(sk, sk2, sizeof sk) == 0);
    CHECK(memcmp(pk, pk2, sizeof pk) == 0);

    /* --- wrong password must fail ---------------------------------------- */
    CHECK(identity_backup_import_buf(blob, blob_len, "wrong password", sk2, pk2) != 0);

    /* --- corruption must fail -------------------------------------------- */
    uint8_t *evil = malloc(blob_len);
    CHECK(evil != NULL);

    /* magic */
    memcpy(evil, blob, blob_len);
    evil[0] ^= 0xFF;
    CHECK(identity_backup_import_buf(evil, blob_len, password, sk2, pk2) != 0);

    /* middle of the ciphertext */
    memcpy(evil, blob, blob_len);
    evil[blob_len / 2] ^= 0x01;
    CHECK(identity_backup_import_buf(evil, blob_len, password, sk2, pk2) != 0);

    /* last byte (GCM tag region) */
    memcpy(evil, blob, blob_len);
    evil[blob_len - 1] ^= 0x01;
    CHECK(identity_backup_import_buf(evil, blob_len, password, sk2, pk2) != 0);

    /* truncation */
    CHECK(identity_backup_import_buf(blob, blob_len - 1, password, sk2, pk2) != 0);
    CHECK(identity_backup_import_buf(blob, 0, password, sk2, pk2) != 0);

    free(evil);
    free(blob);

    /* --- file roundtrip --------------------------------------------------- */
    char dir[] = "/tmp/fear-test-bk-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[600];
    snprintf(path, sizeof path, "%s/backup.fbk", dir);

    CHECK(identity_backup_export(path, sk, pk, password) == 0);
    CHECK(identity_backup_import(path, password, sk2, pk2) == 0);
    CHECK(memcmp(sk, sk2, sizeof sk) == 0);
    CHECK(memcmp(pk, pk2, sizeof pk) == 0);

    /* missing file */
    char nopath[600];
    snprintf(nopath, sizeof nopath, "%s/absent.fbk", dir);
    CHECK(identity_backup_import(nopath, password, sk2, pk2) != 0);

    return t_report("test_backup");
}
