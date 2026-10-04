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

    /* --- fingerprint: one value on every platform ------------------------ */
    {
        /* BLAKE2b with an 8-byte output, not a prefix of BLAKE2b-256. The same
         * vector is pinned in the Android FingerprintTest and was computed a
         * third time with Python's hashlib.blake2b(digest_size=8). Before the
         * fix this side printed cb:2f:51:60:fc:1f:7e:05 for the same key, and
         * a phone and a PC could never agree on whom they were talking to. */
        uint8_t vk[IDENTITY_PK_BYTES];
        for (size_t i = 0; i < IDENTITY_PK_BYTES; i++) vk[i] = (uint8_t)i;
        char fp[IDENTITY_FINGERPRINT_LEN];
        identity_pk_fingerprint(vk, fp);
        CHECK(strcmp(fp, "40:f6:8f:4a:d2:4e:57:5b") == 0);
    }

    /* --- offline inbox: one mailbox per direction -------------------------
     *
     * The address depends on the recipient, so the two sides of a pair use
     * two mailboxes. With one shared mailbox each side collected its own
     * letters too, showed them as incoming and deleted them from the relay
     * before the other side could. The vector is pinned on Android as well
     * (MailboxTest) and was computed a third time with Python's hashlib.
     */
    {
        uint8_t k[32], a[IDENTITY_PK_BYTES], b[IDENTITY_PK_BYTES];
        for (int i = 0; i < 32; i++) {
            k[i] = (uint8_t)i;
            a[i] = (uint8_t)(32 + i);
            b[i] = (uint8_t)(64 + i);
        }
        uint8_t to_a[IDENTITY_INBOX_ADDR_BYTES], to_b[IDENTITY_INBOX_ADDR_BYTES];
        CHECK(identity_inbox_addr(k, a, to_a) == 0);
        CHECK(identity_inbox_addr(k, b, to_b) == 0);
        char hex[2 * IDENTITY_INBOX_ADDR_BYTES + 1];
        sodium_bin2hex(hex, sizeof hex, to_a, sizeof to_a);
        CHECK(strcmp(hex, "f28bfab028371d40570de2bee5a7aac50c2870ee79dc76f64b06796cfc233787") == 0);
        sodium_bin2hex(hex, sizeof hex, to_b, sizeof to_b);
        CHECK(strcmp(hex, "87ce0c2c561b4dd809ec8e6931df61cf93c24134c80d9b3c53bfbcb804ed5c76") == 0);
        CHECK(memcmp(to_a, to_b, sizeof to_a) != 0);
    }

    /* --- known_keys after the fingerprint change ------------------------
     *
     * video_call files a peer under its fingerprint, and before 0.6.0 that
     * was the BLAKE2b-256 prefix. The upgrade renames those entries instead
     * of letting the next call file a second one beside it, keeps the
     * "verified" mark, merges an entry a call already made under the new
     * name, and leaves everything else alone.
     */
    {
        char up[600];
        snprintf(up, sizeof up, "%s/known_keys_upgrade", dir);

        uint8_t vk[IDENTITY_PK_BYTES];
        for (size_t i = 0; i < IDENTITY_PK_BYTES; i++) vk[i] = (uint8_t)i;
        char vk_b64[128], pkb_b64[128];
        CHECK(sodium_bin2base64(vk_b64, sizeof vk_b64, vk, IDENTITY_PK_BYTES,
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL);
        CHECK(sodium_bin2base64(pkb_b64, sizeof pkb_b64, pk_b, IDENTITY_PK_BYTES,
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL);

        FILE *f = fopen(up, "w");
        CHECK(f != NULL);
        fprintf(f, "alice\t%s\t1\n", pkb_b64);                       /* chat entry */
        fprintf(f, "cb:2f:51:60:fc:1f:7e:05\t%s\t1\n", vk_b64);      /* old formula */
        fprintf(f, "40:f6:8f:4a:d2:4e:57:5b\t%s\t0\n", vk_b64);      /* a call since */
        fprintf(f, "00:11:22:33:44:55:66:77\t%s\t0\n", pkb_b64);     /* not its key */
        fclose(f);

        CHECK(identity_known_keys_upgrade(up) == 1);
        CHECK(identity_tofu_check(up, "40:f6:8f:4a:d2:4e:57:5b", vk) == TOFU_KEY_MATCH_VERIFIED);
        CHECK(identity_tofu_check(up, "alice", pk_b) == TOFU_KEY_MATCH_VERIFIED);

        f = fopen(up, "r");
        CHECK(f != NULL);
        char all[2048];
        size_t n = fread(all, 1, sizeof all - 1, f);
        all[n] = '\0';
        fclose(f);
        CHECK(strstr(all, "cb:2f:51:60") == NULL);
        CHECK(strstr(all, "00:11:22:33:44:55:66:77\t") != NULL);
        /* One entry for the key, not two. */
        const char *first = strstr(all, "40:f6:8f:4a:d2:4e:57:5b\t");
        CHECK(first != NULL && strstr(first + 1, "40:f6:8f:4a:d2:4e:57:5b\t") == NULL);

        /* Nothing left to do the second time. */
        CHECK(identity_known_keys_upgrade(up) == 0);
        /* No file is not an error. */
        char none[600];
        snprintf(none, sizeof none, "%s/no_such_known_keys", dir);
        CHECK(identity_known_keys_upgrade(none) == 0);
    }

    return t_report("test_identity");
}
