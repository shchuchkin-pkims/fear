/**
 * @file test_rotation_bundle.c
 * @brief The rotation envelope: who can open it, and who cannot.
 *
 * A bundle is broadcast to a room, so everything about it is public except
 * what each entry seals. The properties worth pinning are all about the
 * things an entry must refuse: another recipient's slot, another room,
 * another generation, another sender, another bundle.
 */
#include "rotation_bundle.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "test_util.h"

#define ROOM "live"

typedef struct {
    uint8_t pk[32];
    uint8_t sk[64];
} party_t;

static void make(party_t *p, uint8_t seed) {
    uint8_t s[32];
    memset(s, seed, sizeof s);
    CHECK(crypto_sign_seed_keypair(p->pk, p->sk, s) == 0);
}

int main(void) {
    CHECK(sodium_init() >= 0);

    party_t alice, bob, carol, mallory;
    make(&alice, 0x11);
    make(&bob, 0x22);
    make(&carol, 0x33);
    make(&mallory, 0x44);

    uint8_t k_new[ROTATION_KEY_BYTES];
    for (size_t i = 0; i < sizeof k_new; i++) k_new[i] = (uint8_t)(0xC0 + i);

    uint8_t recipients[3][32];
    memcpy(recipients[0], alice.pk, 32);
    memcpy(recipients[1], bob.pk, 32);
    memcpy(recipients[2], carol.pk, 32);

    uint8_t bundle[4096];
    size_t blen = 0;

    /* --- the binding, frozen -----------------------------------------------
     *
     * Android computes this too, from the same inputs, and a room with both
     * in it rotates only if the bytes match. Nothing announces a mismatch:
     * each side simply stops being able to read the other, so the vector is
     * pinned on both sides and either one drifting fails its own test.
     *
     * Version 258 is 0x0102, so a big-endian slip shows; the second room id
     * is not ASCII, so a platform hashing UTF-16 shows too.
     */
    {
        uint8_t bind[32];
        char hex[65];

        CHECK(rotation_binding(ROOM, 5, alice.pk, bob.pk, bind) == 0);
        sodium_bin2hex(hex, sizeof hex, bind, sizeof bind);
        CHECK(strcmp(hex,
            "eec1a881cf95bcab46ffa70d341249fdaccb26240acad02cf216f00382d9ea73") == 0);

        CHECK(rotation_binding("ÐºÐ¾Ð¼Ð½Ð°ÑÐ°",
                               258, alice.pk, bob.pk, bind) == 0);
        sodium_bin2hex(hex, sizeof hex, bind, sizeof bind);
        CHECK(strcmp(hex,
            "c5a5d34c2feb013b389232d1c2b2f04d86c819630d4a161d7f8cc23a70b6f0f8") == 0);
    }

    /* --- build and read back ---------------------------------------------- */
    CHECK(rb_build(ROOM, 5, k_new, alice.sk, alice.pk,
                   recipients, 3, bundle, sizeof bundle, &blen) == RB_OK);
    CHECK(blen == rb_size(3));

    rb_view_t view;
    CHECK(rb_parse(bundle, blen, &view) == RB_OK);
    CHECK(view.key_version == 5);
    CHECK(view.entry_count == 3);
    CHECK(memcmp(view.sender_pk, alice.pk, 32) == 0);
    /* Every view lies inside the buffer the caller owns. */
    CHECK(view.sender_pk >= bundle && view.sender_pk + 32 <= bundle + blen);
    CHECK(view.entries + (size_t)view.entry_count * ROTATION_ENTRY_BYTES
          <= bundle + blen);

    /* --- every member gets the same key, including the sender ------------- */
    uint8_t got[ROTATION_KEY_BYTES];
    CHECK(rb_open_for(&view, ROOM, bob.sk, bob.pk, got) == RB_OK);
    CHECK(memcmp(got, k_new, sizeof k_new) == 0);

    memset(got, 0, sizeof got);
    CHECK(rb_open_for(&view, ROOM, carol.sk, carol.pk, got) == RB_OK);
    CHECK(memcmp(got, k_new, sizeof k_new) == 0);

    /* A member that could not open its own bundle would have rotated itself
     * out of the room. */
    memset(got, 0, sizeof got);
    CHECK(rb_open_for(&view, ROOM, alice.sk, alice.pk, got) == RB_OK);
    CHECK(memcmp(got, k_new, sizeof k_new) == 0);

    /* --- and nobody else -------------------------------------------------- */
    CHECK(rb_open_for(&view, ROOM, mallory.sk, mallory.pk, got) == RB_ERR_NOT_FOR_US);

    /* Bob holding his own entry cannot read it as Carol, nor Carol's as his:
     * the recipient is bound into what the entry authenticates. */
    CHECK(rb_open_for(&view, ROOM, bob.sk, carol.pk, got) == RB_ERR_OPEN);

    /* --- a bundle belongs to one room and one generation ------------------ */
    CHECK(rb_open_for(&view, "other", bob.sk, bob.pk, got) == RB_ERR_OPEN);
    {
        rb_view_t moved = view;
        moved.key_version = 6;          /* claim it installs another one */
        CHECK(rb_open_for(&moved, ROOM, bob.sk, bob.pk, got) == RB_ERR_OPEN);
    }

    /* --- and to one sender ------------------------------------------------ */
    {
        rb_view_t forged = view;
        forged.sender_pk = mallory.pk;
        CHECK(rb_open_for(&forged, ROOM, bob.sk, bob.pk, got) == RB_ERR_OPEN);
    }

    /* An entry lifted into a bundle from a different rotation does not open,
     * so a relay cannot mix and match. */
    {
        uint8_t other_bundle[4096];
        size_t olen = 0;
        uint8_t k_other[ROTATION_KEY_BYTES];
        memset(k_other, 0x77, sizeof k_other);
        CHECK(rb_build(ROOM, 5, k_other, mallory.sk, mallory.pk,
                       recipients, 3, other_bundle, sizeof other_bundle, &olen) == RB_OK);

        uint8_t spliced[4096];
        memcpy(spliced, bundle, blen);
        /* Bob's slot replaced with Mallory's entry for Bob. */
        memcpy(spliced + RB_HEADER_BYTES + ROTATION_ENTRY_BYTES,
               other_bundle + RB_HEADER_BYTES + ROTATION_ENTRY_BYTES,
               ROTATION_ENTRY_BYTES);

        rb_view_t sv;
        CHECK(rb_parse(spliced, blen, &sv) == RB_OK);
        CHECK(rb_open_for(&sv, ROOM, bob.sk, bob.pk, got) == RB_ERR_OPEN);
    }

    /* --- refusals --------------------------------------------------------- */
    CHECK(rb_parse(bundle, RB_HEADER_BYTES - 1, &view) == RB_ERR_TOO_SHORT);
    {
        uint8_t evil[4096];
        memcpy(evil, bundle, blen);

        evil[0] = 0x02;                                  /* a format we do not speak */
        CHECK(rb_parse(evil, blen, &view) == RB_ERR_FORMAT);

        memcpy(evil, bundle, blen);
        evil[35] = 4; evil[36] = 0;                      /* claims one more than it has */
        CHECK(rb_parse(evil, blen, &view) == RB_ERR_LENGTH);

        memcpy(evil, bundle, blen);
        evil[35] = 0; evil[36] = 0;                      /* claims none */
        CHECK(rb_parse(evil, blen, &view) == RB_ERR_LENGTH);

        memcpy(evil, bundle, blen);
        evil[35] = 0xFF; evil[36] = 0xFF;                /* claims more than we look at */
        CHECK(rb_parse(evil, blen, &view) == RB_ERR_TOO_MANY);
    }

    CHECK(rb_build(ROOM, 5, k_new, alice.sk, alice.pk, recipients, 3,
                   bundle, rb_size(3) - 1, &blen) == RB_ERR_SPACE);
    CHECK(rb_build(ROOM, 5, k_new, alice.sk, alice.pk, recipients, 0,
                   bundle, sizeof bundle, &blen) == RB_ERR_ARGS);

    printf("test_rotation_bundle: OK\n");
    return 0;
}
