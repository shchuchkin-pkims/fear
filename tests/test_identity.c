/**
 * Unit tests: identity keypair lifecycle, sign/verify, TOFU database,
 * deterministic PM room id / room key.
 */
#include "identity.h"
#include "identity_at_rest.h"
#include "test_util.h"

#include <sodium.h>
#include <stdio.h>
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
    CHECK(identity_pm_room_id_v1(pk, pk_b, id_ab) == 0);
    CHECK(identity_pm_room_id_v1(pk_b, pk, id_ba) == 0);
    CHECK(strcmp(id_ab, id_ba) == 0);
    CHECK(strncmp(id_ab, "pm:", 3) == 0);

    uint8_t pk_c[IDENTITY_PK_BYTES], sk_c[IDENTITY_SK_BYTES];
    CHECK(crypto_sign_keypair(pk_c, sk_c) == 0);
    char id_ac[IDENTITY_PM_ROOM_ID_LEN];
    CHECK(identity_pm_room_id_v1(pk, pk_c, id_ac) == 0);
    CHECK(strcmp(id_ab, id_ac) != 0);

    /* --- метка комнаты на проводе -----------------------------------------
     *
     * Ретранслятор видит её вместо названия. Вектор закреплён, потому что то
     * же самое вычисляет Android: разойдясь, две стороны оказались бы в
     * разных комнатах и молча не видели друг друга.
     */
    {
        char wr[IDENTITY_WIRE_ROOM_LEN];
        CHECK(identity_wire_room("general", wr) == 0);
        CHECK(strcmp(wr, "r:z6fjUIe2RRC26KwaOZ3Gpg") == 0);
        CHECK(identity_wire_room("", wr) == 0);
        CHECK(strcmp(wr, "r:XoI6MSrHqeZYdQA_Q2HegQ") == 0);

        char wr2[IDENTITY_WIRE_ROOM_LEN];
        CHECK(identity_wire_room("work", wr2) == 0);
        CHECK(strcmp(wr, wr2) != 0);
    }

    /* --- метка сессии ----------------------------------------------------
     *
     * Метка случайна, поэтому проверяем не значение, а свойства: она нужной
     * длины, годится для base64url и каждый раз новая. Повторись она между
     * подключениями - вся затея теряет смысл: связать два сеанса одного
     * человека стало бы так же просто, как раньше по имени.
     */
    {
        char t1[IDENTITY_SESSION_TAG_LEN], t2[IDENTITY_SESSION_TAG_LEN];
        CHECK(identity_session_tag(t1) == 0);
        CHECK(identity_session_tag(t2) == 0);
        CHECK(strlen(t1) == IDENTITY_SESSION_TAG_LEN - 1);
        CHECK(strcmp(t1, t2) != 0);
        for (size_t i = 0; t1[i]; i++) {
            int ok = (t1[i] >= 'A' && t1[i] <= 'Z') || (t1[i] >= 'a' && t1[i] <= 'z') ||
                     (t1[i] >= '0' && t1[i] <= '9') || t1[i] == '-' || t1[i] == '_';
            CHECK(ok);
        }
    }

    /* --- что подписывает анонс личности -----------------------------------
     *
     * Подпись покрывает метку сессии вместе с именем, а не одно имя: иначе
     * чужой анонс можно было бы взять целиком и повторить под своей меткой,
     * забрав вместе с ним и имя.
     *
     * Вектор закреплён, потому что ровно те же байты подписывает Android.
     * Разойдись склейка хоть на байт - подписи перестали бы сходиться, и
     * каждая сторона показывала бы собеседника неизвестным, ничего при этом
     * не сломав вслух.
     */
    {
        uint8_t buf[128];
        size_t n = identity_announce_signed_bytes("AAAAAAAAAAAAAAAAAAAAAA", "alice",
                                                  buf, sizeof buf);
        const char *want = "fear.announce.v2AAAAAAAAAAAAAAAAAAAAAAalice";
        CHECK(n == strlen(want));
        CHECK(memcmp(buf, want, n) == 0);

        /* Метка постоянной длины, поэтому склейка читается однозначно:
         * подмена части метки частью имени невозможна. */
        size_t n2 = identity_announce_signed_bytes("AAAAAAAAAAAAAAAAAAAAAB", "alice",
                                                   buf, sizeof buf);
        CHECK(n2 == n);
        CHECK(memcmp(buf, want, n) != 0);

        /* Не помещается - честный отказ, а не обрезанная подпись. */
        uint8_t tiny[8];
        CHECK(identity_announce_signed_bytes("AAAAAAAAAAAAAAAAAAAAAA", "alice",
                                             tiny, sizeof tiny) == 0);
    }

    /* --- идентификатор ЛС, выведенный под ключом пары ---------------------
     *
     * Старый вывод считался из двух открытых ключей и без секрета, поэтому
     * ретранслятор, знающий ключи всех, кто занял имя, мог перебрать пары и
     * подписать каждую личную комнату именами обоих собеседников. Новый
     * считается под K_pm - снаружи его не повторить.
     *
     * Вектор закреплён, потому что то же самое вычисляет Android: разойдясь,
     * две стороны оказались бы в разных комнатах и молча не видели друг
     * друга.
     */
    {
        uint8_t k_fixed[32];
        for (int i = 0; i < 32; i++) k_fixed[i] = (uint8_t)i;
        char id_v2[IDENTITY_PM_ROOM_ID_LEN];
        CHECK(identity_pm_room_id_v2(k_fixed, id_v2) == 0);
        CHECK(strcmp(id_v2, "pm:2cqzkCvp122e_u-J5N7BnQ") == 0);

        /* Другой ключ пары - другая комната. */
        uint8_t k_other[32];
        memset(k_other, 0x5A, sizeof k_other);
        char id_other[IDENTITY_PM_ROOM_ID_LEN];
        CHECK(identity_pm_room_id_v2(k_other, id_other) == 0);
        CHECK(strcmp(id_v2, id_other) != 0);

        /* И он не совпадает со старым: иначе переносить было бы нечего. */
        uint8_t k_ab_check[32];
        CHECK(identity_pm_room_key(sk, pk_b, k_ab_check) == 0);
        char id_new[IDENTITY_PM_ROOM_ID_LEN];
        CHECK(identity_pm_room_id_v2(k_ab_check, id_new) == 0);
        CHECK(strcmp(id_new, id_ab) != 0);
    }

    /* --- deterministic PM room key --------------------------------------- */
    uint8_t k_ab[32], k_ba[32], k_ac[32];
    CHECK(identity_pm_room_key(sk, pk_b, k_ab) == 0);
    CHECK(identity_pm_room_key(sk_b, pk, k_ba) == 0);
    CHECK(memcmp(k_ab, k_ba, 32) == 0);

    CHECK(identity_pm_room_key(sk, pk_c, k_ac) == 0);
    CHECK(memcmp(k_ab, k_ac, 32) != 0);

    /* --- the secret key at rest ------------------------------------------
     *
     * The public key stays in the clear - identity_load_pk is called on paths
     * that only want a fingerprint and have no business unlocking a keyring.
     * The secret key is wrapped when there is somewhere to keep the wrapping
     * key, and written the old way when there is not. Both have to load, and
     * a file written before any of this existed still has to load, or an
     * upgrade would look exactly like a lost identity.
     */
    {
        char path[512];
        snprintf(path, sizeof path, "%s/at_rest_identity", dir);

        CHECK(identity_generate(path) == 0);

        uint8_t gpk[IDENTITY_PK_BYTES], gsk[IDENTITY_SK_BYTES];
        CHECK(identity_load(path, gpk, gsk) == 0);

        uint8_t only_pk[IDENTITY_PK_BYTES];
        CHECK(identity_load_pk(path, only_pk) == 0);
        CHECK(memcmp(only_pk, gpk, IDENTITY_PK_BYTES) == 0);

        /* Whatever the store situation, the file says which one it is, and
         * the secret key is only in the clear when it says so. */
        FILE *f = fopen(path, "r");
        CHECK(f != NULL);
        char buf[4096];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = '\0';
        fclose(f);

        if (iar_available() != IAR_NONE) {
            CHECK(strstr(buf, "\nSKENC:") != NULL);
            CHECK(strstr(buf, "\nSK:") == NULL);
        } else {
            CHECK(strstr(buf, "\nSK:") != NULL);
        }

        /* A file from before any of this: two lines, secret key in base64. */
        char legacy[512];
        snprintf(legacy, sizeof legacy, "%s/legacy_identity", dir);
        char pk_b64[128], sk_b64[256];
        CHECK(sodium_bin2base64(pk_b64, sizeof pk_b64, gpk, IDENTITY_PK_BYTES,
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL);
        CHECK(sodium_bin2base64(sk_b64, sizeof sk_b64, gsk, IDENTITY_SK_BYTES,
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL);
        FILE *lf = fopen(legacy, "w");
        CHECK(lf != NULL);
        fprintf(lf, "PK:%s\nSK:%s\n", pk_b64, sk_b64);
        fclose(lf);

        uint8_t lpk[IDENTITY_PK_BYTES], lsk[IDENTITY_SK_BYTES];
        CHECK(identity_load(legacy, lpk, lsk) == 0);
        CHECK(memcmp(lpk, gpk, IDENTITY_PK_BYTES) == 0);
        CHECK(memcmp(lsk, gsk, IDENTITY_SK_BYTES) == 0);

        /* And on a machine that has a store now, it has been rewritten under
         * it - reading an old file is what triggers the move. */
        if (iar_available() != IAR_NONE) {
            FILE *lf2 = fopen(legacy, "r");
            CHECK(lf2 != NULL);
            n = fread(buf, 1, sizeof buf - 1, lf2);
            buf[n] = '\0';
            fclose(lf2);
            CHECK(strstr(buf, "\nSKENC:") != NULL);

            uint8_t rpk[IDENTITY_PK_BYTES], rsk[IDENTITY_SK_BYTES];
            CHECK(identity_load(legacy, rpk, rsk) == 0);
            CHECK(memcmp(rsk, gsk, IDENTITY_SK_BYTES) == 0);
        }
    }

    return t_report("test_identity");
}
