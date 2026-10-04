/**
 * @file fear-sign.c
 * @brief Release signing helper for the F.E.A.R. updater.
 *
 * The updater refuses to install an archive that is not signed by the release
 * key, so releases have to be signed with the matching secret key. This tool
 * does both halves of that.
 *
 * Usage:
 *   fear-sign keygen
 *       Generates a new Ed25519 release keypair and prints both halves.
 *       Put PUBLIC into updater.conf (pubkey=...) and keep SECRET in a
 *       GitHub Actions secret. The secret key never leaves your hands.
 *
 *   FEAR_SIGN_KEY=<base64 secret> fear-sign sign <file>
 *       Prints the base64 detached signature of <file> on stdout.
 *       The key is taken from the environment, not argv, so it does not
 *       show up in process listings.
 *
 * Build: linked against libsodium, see updater/CMakeLists.txt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static int do_keygen(void) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    char pk_b64[crypto_sign_PUBLICKEYBYTES * 2 + 8];
    char sk_b64[crypto_sign_SECRETKEYBYTES * 2 + 8];
    sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk),
                      sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, sizeof(sk),
                      sodium_base64_VARIANT_ORIGINAL);

    printf("PUBLIC (put in updater.conf as  pubkey=<value> ):\n%s\n\n", pk_b64);
    printf("SECRET (store as GitHub secret FEAR_SIGN_KEY, never commit):\n%s\n", sk_b64);

    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(sk_b64, sizeof(sk_b64));
    return 0;
}

static int do_sign(const char *path) {
    const char *key_b64 = getenv("FEAR_SIGN_KEY");
    if (!key_b64 || !*key_b64) {
        fprintf(stderr, "FEAR_SIGN_KEY is not set\n");
        return 1;
    }

    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    size_t sk_len = 0;
    if (sodium_base642bin(sk, sizeof(sk), key_b64, strlen(key_b64),
                          " \t\r\n", &sk_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        sk_len != sizeof(sk)) {
        fprintf(stderr, "FEAR_SIGN_KEY is not a base64 Ed25519 secret key\n");
        sodium_memzero(sk, sizeof(sk));
        return 1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        sodium_memzero(sk, sizeof(sk));
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); sodium_memzero(sk, sizeof(sk)); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); sodium_memzero(sk, sizeof(sk)); return 1; }
    rewind(f);

    unsigned char *data = (unsigned char *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!data) { fclose(f); sodium_memzero(sk, sizeof(sk)); return 1; }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "short read on %s\n", path);
        free(data); fclose(f); sodium_memzero(sk, sizeof(sk));
        return 1;
    }
    fclose(f);

    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, data, (unsigned long long)sz, sk) != 0) {
        fprintf(stderr, "signing failed\n");
        free(data); sodium_memzero(sk, sizeof(sk));
        return 1;
    }
    free(data);
    sodium_memzero(sk, sizeof(sk));

    char sig_b64[crypto_sign_BYTES * 2 + 8];
    sodium_bin2base64(sig_b64, sizeof(sig_b64), sig, sizeof(sig),
                      sodium_base64_VARIANT_ORIGINAL);
    printf("%s\n", sig_b64);
    return 0;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
        return 1;
    }
    if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
        return do_keygen();
    }
    if (argc >= 3 && strcmp(argv[1], "sign") == 0) {
        return do_sign(argv[2]);
    }
    fprintf(stderr,
        "usage:\n"
        "  fear-sign keygen\n"
        "  FEAR_SIGN_KEY=<base64 secret> fear-sign sign <file>\n");
    return 2;
}
