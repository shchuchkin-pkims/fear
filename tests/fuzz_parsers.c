/**
 * @file fuzz_parsers.c
 * @brief Feed malformed input to every parser that sees the network.
 *
 * These four read bytes an attacker chooses, before anything has been
 * authenticated - or, in the media packet's case, decide what to
 * authenticate. A crash in any of them is reachable by anyone who can send
 * to the port, so they are the ones worth beating on.
 *
 * Not libFuzzer: that wants clang, and this has to run wherever the unit
 * tests run, which is a gcc image in CI. What it does instead is the part
 * that finds things - a deterministic driver over random and, more usefully,
 * near-valid input, built with the sanitizers on. Purely random bytes bounce
 * off a length check in the first few lines; mutating one byte of a packet
 * that would otherwise parse is what walks into the code behind it.
 *
 * Deterministic on purpose. The seed is fixed so a failure in CI reproduces
 * locally, and can be overridden on the command line to explore further:
 *
 *     ./fuzz_parsers 12345 200000
 *
 * Everything here asserts one property only: it returned. Whether a
 * malformed packet is rejected with the right status is what the unit tests
 * are for; this one is about not reading past the end of the buffer, not
 * dividing by a length that turned out to be zero, and not being walked into
 * an allocation the size of the attacker's choosing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "call_invite.h"
#include "chat_frame.h"
#include "media_hello.h"
#include "media_keys.h"
#include "media_packet.h"

/** xorshift64*, so the sequence is ours and not the C library's. */
static uint64_t g_state = 0x2545F4914F6CDD1DULL;

static uint64_t rnd(void) {
    g_state ^= g_state >> 12;
    g_state ^= g_state << 25;
    g_state ^= g_state >> 27;
    return g_state * 2685821657736338717ULL;
}

static uint32_t rnd_below(uint32_t n) {
    return n ? (uint32_t)(rnd() % n) : 0;
}

#define MAX_INPUT 4096

/** Every parser under test, given one buffer. */
static void feed(const uint8_t *buf, size_t len,
                 const uint8_t hello_key[MK_KEY_BYTES],
                 const uint8_t call_key[MK_KEY_BYTES],
                 const uint8_t k_room[KS_KEY_BYTES]) {
    mh_hello_t hello;
    (void)mh_parse(buf, len, hello_key, &hello);

    ci_invite_t invite;
    (void)ci_parse(buf, len, &invite);

    uint8_t sid[MK_SID_BYTES];
    uint64_t ctr = 0;
    uint8_t type = 0;
    (void)mp_peek(buf, len, &type, sid, &ctr);

    uint8_t out[MAX_INPUT + 64];
    size_t out_len = 0;
    (void)mp_decrypt(buf, len, call_key, out, sizeof out, &out_len);

    uint8_t nonce[CF_NONCE_BYTES];
    memset(nonce, 0x5A, sizeof nonce);
    (void)cf_open_at(k_room, "live", "peer", buf, len, nonce, 0,
                     out, sizeof out, &out_len);
}

/** A HELLO2 that would parse, so mutations start from somewhere plausible. */
static size_t build_hello(uint8_t *out, size_t cap,
                          const uint8_t hello_key[MK_KEY_BYTES],
                          const uint8_t call_id[MK_CALLID_BYTES]) {
    mh_hello_t h;
    memset(&h, 0, sizeof h);
    h.flags = MH_FLAG_AUDIO | MH_FLAG_VIDEO;
    h.key_version = 0;
    memcpy(h.call_id, call_id, MK_CALLID_BYTES);
    memset(h.sender_salt, 0x33, MK_SALT_BYTES);
    h.width = 640; h.height = 480; h.fps = 25;
    snprintf(h.name, sizeof h.name, "seed");

    size_t len = 0;
    if (mh_build(&h, hello_key, NULL, out, cap, &len) != MH_OK) return 0;
    return len;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    if (argc > 1) g_state = strtoull(argv[1], NULL, 0);
    unsigned long rounds = (argc > 2) ? strtoul(argv[2], NULL, 0) : 500000UL;
    if (g_state == 0) g_state = 1;

    uint8_t k_call[MK_KEY_BYTES], k_room[KS_KEY_BYTES];
    for (size_t i = 0; i < MK_KEY_BYTES; i++) k_call[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < KS_KEY_BYTES; i++) k_room[i] = (uint8_t)(i * 3 + 2);

    uint8_t call_id[MK_CALLID_BYTES];
    for (size_t i = 0; i < sizeof call_id; i++) call_id[i] = (uint8_t)(0x10 + i);

    uint8_t hello_key[MK_KEY_BYTES];
    if (mk_hello_key(k_call, call_id, hello_key) != 0) {
        fprintf(stderr, "mk_hello_key failed\n");
        return 1;
    }

    uint8_t seed_hello[MH_SIZE_SIGNED];
    size_t seed_hello_len = build_hello(seed_hello, sizeof seed_hello, hello_key, call_id);

    uint8_t buf[MAX_INPUT];

    for (unsigned long i = 0; i < rounds; i++) {
        size_t len;

        if (seed_hello_len && (i % 3) != 0) {
            /* Near-valid: a packet that parses, with a few bytes disturbed.
             * This is the case that reaches past the first length check. */
            len = seed_hello_len;
            memcpy(buf, seed_hello, len);

            /* Occasionally change the length too, since several of these
             * parsers dispatch on it. */
            if ((rnd() & 7) == 0) {
                len = rnd_below((uint32_t)seed_hello_len + 8);
                if (len > sizeof buf) len = sizeof buf;
            }

            unsigned flips = 1 + rnd_below(4);
            for (unsigned f = 0; f < flips && len; f++) {
                buf[rnd_below((uint32_t)len)] ^= (uint8_t)(1u << rnd_below(8));
            }
        } else {
            /* Uniformly random, including the empty buffer and the sizes
             * either side of every header this code knows about. */
            static const size_t interesting[] = {
                0, 1, 2, 8, 9, 15, 16, 17, 61, 62, 63, 77, 78, 79,
                157, 158, 159, 173, 174, 175
            };
            if ((rnd() & 3) == 0) {
                len = interesting[rnd_below(sizeof interesting / sizeof interesting[0])];
            } else {
                len = rnd_below(MAX_INPUT);
            }
            for (size_t k = 0; k < len; k++) buf[k] = (uint8_t)rnd();
        }

        feed(buf, len, hello_key, k_call, k_room);
    }

    printf("fuzz_parsers: %lu inputs, no crash\n", rounds);
    return 0;
}
