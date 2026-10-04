/*
 * pm_keys - то, что GUI выводит для личного чата, но из командной строки:
 * для интеграционных тестов, где личную переписку ведут консольные клиенты.
 *
 *   pm_keys <моя-личность> <личность-собеседника>
 *
 * Печатает три строки: идентификатор личной комнаты (pm:…, тот же у обоих),
 * ключ пары K_pm (base64url) и открытый ключ собеседника (base64url).
 */
#include "identity.h"

#include <sodium.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3 || sodium_init() < 0) {
        fprintf(stderr, "usage: pm_keys <my-identity> <their-identity>\n");
        return 2;
    }
    uint8_t my_pk[IDENTITY_PK_BYTES], my_sk[IDENTITY_SK_BYTES];
    uint8_t their_pk[IDENTITY_PK_BYTES];
    if (identity_load(argv[1], my_pk, my_sk) != 0 ||
        identity_load_pk(argv[2], their_pk) != 0) {
        fprintf(stderr, "pm_keys: cannot load identities\n");
        return 1;
    }
    uint8_t k_pm[32];
    char room[IDENTITY_PM_ROOM_ID_LEN];
    if (identity_pm_room_key(my_sk, their_pk, k_pm) != 0 ||
        identity_pm_room_id_v2(k_pm, room) != 0) {
        fprintf(stderr, "pm_keys: cannot derive the pair key\n");
        return 1;
    }
    char kb64[64], pkb64[64];
    sodium_bin2base64(kb64, sizeof kb64, k_pm, sizeof k_pm,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    sodium_bin2base64(pkb64, sizeof pkb64, their_pk, sizeof their_pk,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    printf("%s\n%s\n%s\n", room, kb64, pkb64);
    sodium_memzero(my_sk, sizeof my_sk);
    sodium_memzero(k_pm, sizeof k_pm);
    return 0;
}
