/**
 * Unit tests: identity keypair lifecycle, sign/verify, TOFU database,
 * deterministic PM room id / room key.
 */
#include "identity.h"
#include "test_util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    CHECK(sodium_init() >= 0);

    char dir[] = "/tmp/fear-test-id-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);

    char idpath[600], kkpath[600];
    snprintf(idpath, sizeof idpath, "%s/identity", dir);
    snprintf(kkpath, sizeof kkpath, "%s/known_keys", dir);

    /* --- generate / load ------------------------------------------------ */
    CHECK(identity_generate(idpath) == 0);

    struct stat st;
    CHECK(stat(idpath, &st) == 0);
    /* M2 fix (audit 2026-07): the file must be born with 0600, no wider. */
    CHECK((st.st_mode & 07777) == 0600);

    uint8_t pk[IDENTITY_PK_BYTES], sk[IDENTITY_SK_BYTES];
    CHECK(identity_load(idpath, pk, sk) == 0);

    uint8_t pk_only[IDENTITY_PK_BYTES];
    CHECK(identity_load_pk(idpath, pk_only) == 0);
    CHECK(memcmp(pk, pk_only, sizeof pk) == 0);

    /* Loading a missing file must fail, not fabricate keys. */
    char nopath[600];
    snprintf(nopath, sizeof nopath, "%s/absent", dir);
    CHECK(identity_load(nopath, pk_only, sk) != 0);

    /* --- sign / verify -------------------------------------------------- */
    const uint8_t msg[] = "fear unit test message";
    uint8_t sig[IDENTITY_SIG_BYTES];
    CHECK(identity_sign(msg, sizeof msg, sk, sig) == 0);
    CHECK(identity_verify(msg, sizeof msg, sig, pk) == 0);

    uint8_t bad_sig[IDENTITY_SIG_BYTES];
    memcpy(bad_sig, sig, sizeof sig);
    bad_sig[7] ^= 0x01;
    CHECK(identity_verify(msg, sizeof msg, bad_sig, pk) != 0);

    uint8_t other_msg[] = "fear unit test messagf";
    CHECK(identity_verify(other_msg, sizeof other_msg, sig, pk) != 0);

    /* --- TOFU ----------------------------------------------------------- */
    CHECK(identity_tofu_check(kkpath, "alice", pk) == TOFU_NEW_KEY);
    CHECK(identity_tofu_check(kkpath, "alice", pk) == TOFU_KEY_MATCH);

    uint8_t pk_b[IDENTITY_PK_BYTES], sk_b[IDENTITY_SK_BYTES];
    CHECK(crypto_sign_keypair(pk_b, sk_b) == 0);
    CHECK(identity_tofu_check(kkpath, "alice", pk_b) == TOFU_KEY_CONFLICT);
    /* A different name with a fresh key is a normal first contact. */
    CHECK(identity_tofu_check(kkpath, "bob", pk_b) == TOFU_NEW_KEY);

    CHECK(identity_mark_verified(kkpath, "alice") == 0);
    CHECK(identity_mark_verified(kkpath, "nobody") != 0);

    CHECK(identity_remove_key(kkpath, "bob") == 0);
    CHECK(identity_tofu_check(kkpath, "bob", pk_b) == TOFU_NEW_KEY);

    /* --- deterministic PM room id --------------------------------------- */
    char id_ab[IDENTITY_PM_ROOM_ID_LEN], id_ba[IDENTITY_PM_ROOM_ID_LEN];
    CHECK(identity_pm_room_id(pk, pk_b, id_ab) == 0);
    CHECK(identity_pm_room_id(pk_b, pk, id_ba) == 0);
    CHECK(strcmp(id_ab, id_ba) == 0);
    CHECK(strncmp(id_ab, "pm:", 3) == 0);

    uint8_t pk_c[IDENTITY_PK_BYTES], sk_c[IDENTITY_SK_BYTES];
    CHECK(crypto_sign_keypair(pk_c, sk_c) == 0);
    char id_ac[IDENTITY_PM_ROOM_ID_LEN];
    CHECK(identity_pm_room_id(pk, pk_c, id_ac) == 0);
    CHECK(strcmp(id_ab, id_ac) != 0);

    /* --- deterministic PM room key --------------------------------------- */
    uint8_t k_ab[32], k_ba[32], k_ac[32];
    CHECK(identity_pm_room_key(sk, pk_b, k_ab) == 0);
    CHECK(identity_pm_room_key(sk_b, pk, k_ba) == 0);
    CHECK(memcmp(k_ab, k_ba, 32) == 0);

    CHECK(identity_pm_room_key(sk, pk_c, k_ac) == 0);
    CHECK(memcmp(k_ab, k_ac, 32) != 0);

    return t_report("test_identity");
}
