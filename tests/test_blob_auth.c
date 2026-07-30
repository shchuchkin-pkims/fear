/**
 * Protocol test for M10: BLOB_GET is owner-only.
 *
 * Talks to a live relay server (started by blob_auth.sh) through the
 * real sp_* client functions:
 *   - owner can PUT and GET their own blob
 *   - GET with someone else's secret key is rejected by the server
 *   - owner GET of a missing blob is a clean not-found
 *
 * argv: [1] host, [2] port
 */
#include "server_proto.h"
#include "identity.h"
#include "test_util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);

    CHECK(sodium_init() >= 0);

    uint8_t pk_a[32], sk_a[64], pk_b[32], sk_b[64];
    CHECK(crypto_sign_keypair(pk_a, sk_a) == 0);
    CHECK(crypto_sign_keypair(pk_b, sk_b) == 0);

    const uint8_t data[] = "encrypted contacts blob payload";

    /* Owner writes... */
    CHECK(sp_blob_put(host, port, pk_a, sk_a, "test.v1", data, sizeof data) == SP_OK);

    /* ...and reads their own blob back. */
    uint8_t *out = NULL; size_t out_len = 0;
    CHECK(sp_blob_get(host, port, pk_a, sk_a, "test.v1", &out, &out_len) == SP_OK);
    CHECK(out != NULL && out_len == sizeof data);
    CHECK(out && memcmp(out, data, sizeof data) == 0);
    free(out);
    out = NULL;

    /* M10 core: reading A's blob with B's key must fail - no ciphertext
     * exfiltration, no presence oracle. */
    sp_status_t st = sp_blob_get(host, port, pk_a, sk_b, "test.v1", &out, &out_len);
    CHECK(st != SP_OK);
    CHECK(out == NULL);

    /* Same the other way round: A's key does not open B's slot. */
    st = sp_blob_get(host, port, pk_b, sk_a, "test.v1", &out, &out_len);
    CHECK(st != SP_OK);
    CHECK(out == NULL);

    /* A proper owner asking for a blob that was never written gets a
     * clean not-found, so the happy paths still work. */
    CHECK(sp_blob_get(host, port, pk_b, sk_b, "test.v1", &out, &out_len) == SP_NOT_FOUND);

    return t_report("test_blob_auth");
}
