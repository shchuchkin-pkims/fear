/**
 * Media packet framing: layout, the authenticated header, and the counter
 * range.
 *
 * The expected ciphertext is not pinned here - AES-GCM under a key this
 * test derives is not an independent check of anything. What is worth
 * pinning is the framing and the properties, so those are asserted
 * directly, and the Kotlin port asserts the same ones.
 */
#include "media_packet.h"
#include "test_util.h"

#include <sodium.h>
#include <string.h>

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k_call[MK_KEY_BYTES], call_id[MK_CALLID_BYTES], salt[MK_SALT_BYTES];
    for (size_t i = 0; i < sizeof k_call; i++)  k_call[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof call_id; i++) call_id[i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < sizeof salt; i++)    salt[i] = (uint8_t)(0xA0 + i);

    uint8_t zeros[MK_IDBIND_BYTES];
    memset(zeros, 0, sizeof zeros);

    uint8_t key[MK_KEY_BYTES], sid[MK_SID_BYTES];
    CHECK(mk_derive_sender(k_call, MK_STREAM_AUDIO, 0, call_id, salt, zeros, key) == 0);
    CHECK(mk_sender_id(k_call, call_id, salt, zeros, sid) == 0);

    const uint8_t payload[] = "opus frame stand-in";
    uint8_t pkt[256], plain[256];
    size_t pkt_len = 0, plain_len = 0;

    /* --- framing ------------------------------------------------------------ */
    CHECK(mp_encrypt(0x01, sid, 0, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);
    CHECK(pkt_len == MP_HEADER_BYTES + sizeof payload + MP_TAG_BYTES);
    CHECK(pkt[0] == 0x01);
    CHECK(memcmp(pkt + 1, sid, MK_SID_BYTES) == 0);
    for (size_t i = 4; i < 9; i++) CHECK(pkt[i] == 0);   /* counter 0 */

    CHECK(mp_decrypt(pkt, pkt_len, key, plain, sizeof plain, &plain_len) == 0);
    CHECK(plain_len == sizeof payload);
    CHECK(memcmp(plain, payload, sizeof payload) == 0);

    uint8_t type = 0, peek_sid[MK_SID_BYTES];
    uint64_t counter = 999;
    CHECK(mp_peek(pkt, pkt_len, &type, peek_sid, &counter) == 0);
    CHECK(type == 0x01);
    CHECK(memcmp(peek_sid, sid, MK_SID_BYTES) == 0);
    CHECK(counter == 0);

    /* Counter is big endian across all five bytes. */
    CHECK(mp_encrypt(0x01, sid, 0x0102030405ULL, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);
    CHECK(pkt[4] == 0x01 && pkt[5] == 0x02 && pkt[6] == 0x03 &&
          pkt[7] == 0x04 && pkt[8] == 0x05);
    CHECK(mp_peek(pkt, pkt_len, NULL, NULL, &counter) == 0);
    CHECK(counter == 0x0102030405ULL);
    CHECK(mp_decrypt(pkt, pkt_len, key, plain, sizeof plain, &plain_len) == 0);

    CHECK(mp_encrypt(0x01, sid, MP_MAX_COUNTER, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);
    /* Beyond the field: refused rather than silently truncated, which would
     * repeat a counter under the same key. */
    CHECK(mp_encrypt(0x01, sid, MP_MAX_COUNTER + 1, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == -1);

    /* --- the header is authenticated ----------------------------------------- */
    CHECK(mp_encrypt(0x01, sid, 7, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);

    uint8_t evil[256];
    /* Flipping the type byte used to yield a packet that still decrypted and
     * was then handed to the wrong parser. */
    memcpy(evil, pkt, pkt_len); evil[0] = 0x04;
    CHECK(mp_decrypt(evil, pkt_len, key, plain, sizeof plain, &plain_len) == -1);

    /* Same for the counter and the SID. */
    memcpy(evil, pkt, pkt_len); evil[8] ^= 0x01;
    CHECK(mp_decrypt(evil, pkt_len, key, plain, sizeof plain, &plain_len) == -1);
    memcpy(evil, pkt, pkt_len); evil[1] ^= 0x01;
    CHECK(mp_decrypt(evil, pkt_len, key, plain, sizeof plain, &plain_len) == -1);

    /* And the ciphertext itself. */
    memcpy(evil, pkt, pkt_len); evil[pkt_len - 1] ^= 0x01;
    CHECK(mp_decrypt(evil, pkt_len, key, plain, sizeof plain, &plain_len) == -1);

    /* --- a second sender never collides -------------------------------------- */
    uint8_t salt_b[MK_SALT_BYTES], key_b[MK_KEY_BYTES], sid_b[MK_SID_BYTES];
    for (size_t i = 0; i < sizeof salt_b; i++) salt_b[i] = (uint8_t)(0x5A + i);
    CHECK(mk_derive_sender(k_call, MK_STREAM_AUDIO, 0, call_id, salt_b, zeros, key_b) == 0);
    CHECK(mk_sender_id(k_call, call_id, salt_b, zeros, sid_b) == 0);

    uint8_t pkt_b[256];
    size_t pkt_b_len = 0;
    /* Both senders start at counter zero, which is safe only because their
     * keys differ - this is the whole point of the scheme. */
    CHECK(mp_encrypt(0x01, sid_b, 0, key_b, payload, sizeof payload,
                     pkt_b, sizeof pkt_b, &pkt_b_len) == 0);
    CHECK(mp_encrypt(0x01, sid, 0, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);
    CHECK(memcmp(pkt, pkt_b, pkt_len) != 0);
    /* One sender's key does not open the other's packet. */
    CHECK(mp_decrypt(pkt_b, pkt_b_len, key, plain, sizeof plain, &plain_len) == -1);
    CHECK(mp_decrypt(pkt_b, pkt_b_len, key_b, plain, sizeof plain, &plain_len) == 0);

    /* --- bounds ---------------------------------------------------------------- */
    CHECK(mp_encrypt(0x01, sid, 0, key, payload, sizeof payload,
                     pkt, MP_HEADER_BYTES, &pkt_len) == -1);
    CHECK(mp_decrypt(pkt, MP_HEADER_BYTES + MP_TAG_BYTES - 1, key,
                     plain, sizeof plain, &plain_len) == -1);
    /* An oversized packet must not be written past the caller's buffer. */
    CHECK(mp_encrypt(0x01, sid, 0, key, payload, sizeof payload,
                     pkt, sizeof pkt, &pkt_len) == 0);
    CHECK(mp_decrypt(pkt, pkt_len, key, plain, 4, &plain_len) == -1);
    CHECK(mp_peek(pkt, MP_HEADER_BYTES, &type, peek_sid, &counter) == -1);

    return t_report("test_media_packet");
}
