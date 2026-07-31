/**
 * Sender table and replay windows: the bookkeeping that makes a group call
 * work at the receiver.
 *
 * These are behavioural tests rather than frozen vectors - nothing here
 * reaches the wire. What matters is that the rules hold under the cases
 * that motivated them: a full table, a SID collision, a slot released and
 * reused, a repeated HELLO, and a forged counter far in the future.
 */
#include "media_senders.h"
#include "test_util.h"

#include <sodium.h>
#include <string.h>

static void mk_salt(uint8_t out[MK_SALT_BYTES], uint8_t seed) {
    for (size_t i = 0; i < MK_SALT_BYTES; i++) out[i] = (uint8_t)(seed + i);
}

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k_call[MK_KEY_BYTES], call_id[MK_CALLID_BYTES];
    for (size_t i = 0; i < sizeof k_call; i++) k_call[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof call_id; i++) call_id[i] = (uint8_t)(0x10 + i);

    uint8_t zeros[MK_IDBIND_BYTES];
    memset(zeros, 0, sizeof zeros);

    uint8_t own[MK_SALT_BYTES], a[MK_SALT_BYTES], b[MK_SALT_BYTES], c[MK_SALT_BYTES];
    mk_salt(own, 0x01); mk_salt(a, 0xA0); mk_salt(b, 0x5A); mk_salt(c, 0x33);

    static ms_table_t t;
    CHECK(ms_init(&t, k_call, call_id, own) == MS_OK);
    CHECK(ms_count(&t) == 0);

    /* An all-zero call_id is refused here too, so a table can never exist
     * for a call whose keys would be unbound. */
    static ms_table_t bad;
    uint8_t zero_call[MK_CALLID_BYTES];
    memset(zero_call, 0, sizeof zero_call);
    CHECK(ms_init(&bad, k_call, zero_call, NULL) != MS_OK);

    /* --- install and idempotence ---------------------------------------------- */
    int ia = -1, ib = -1, again = -1;
    CHECK(ms_install(&t, a, zeros, 0, &ia) == MS_OK);
    CHECK(ms_install(&t, b, zeros, 0, &ib) == MS_OK);
    CHECK(ia != ib);
    CHECK(ms_count(&t) == 2);

    /* A repeated HELLO must be a no-op: same slot, no reset. */
    CHECK(ms_install(&t, a, zeros, 0, &again) == MS_OK);
    CHECK(again == ia);
    CHECK(ms_count(&t) == 2);

    /* Our own salt coming back at us is refused: installing it would give a
     * "peer" whose keys are our own send keys. */
    int self_idx = -1;
    CHECK(ms_install(&t, own, zeros, 0, &self_idx) == MS_ERR_SELF);
    CHECK(ms_count(&t) == 2);

    /* --- keys differ per sender and per stream --------------------------------- */
    const uint8_t *ka = ms_key(&t, ia, MK_STREAM_AUDIO);
    const uint8_t *kb = ms_key(&t, ib, MK_STREAM_AUDIO);
    const uint8_t *kav = ms_key(&t, ia, MK_STREAM_VIDEO);
    CHECK(ka && kb && kav);
    CHECK(memcmp(ka, kb, MK_KEY_BYTES) != 0);
    CHECK(memcmp(ka, kav, MK_KEY_BYTES) != 0);
    CHECK(ms_key(&t, 999, MK_STREAM_AUDIO) == NULL);

    /* The key a receiver derives for a sender is the one that sender uses. */
    uint8_t expect[MK_KEY_BYTES];
    CHECK(mk_derive_sender(k_call, MK_STREAM_AUDIO, 0, call_id, a, zeros, expect) == 0);
    CHECK(memcmp(ka, expect, MK_KEY_BYTES) == 0);

    /* --- lookup by SID ---------------------------------------------------------- */
    uint8_t sid_a[MK_SID_BYTES];
    CHECK(mk_sender_id(k_call, call_id, a, zeros, sid_a) == 0);

    int cand[MS_SID_CAP];
    int n = ms_find_by_sid(&t, sid_a, cand);
    CHECK(n == 1);
    CHECK(cand[0] == ia);

    uint8_t nobody[MK_SID_BYTES] = { 0xDE, 0xAD, 0xBE };
    CHECK(ms_find_by_sid(&t, nobody, cand) == 0);

    /* --- replay window ----------------------------------------------------------- */
    /* First packet anchors wherever it lands: a stream may be joined mid-flight. */
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 500) == MS_FRESH);
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 500) == MS_REPLAY);
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 501) == MS_FRESH);
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 499) == MS_FRESH);   /* reordered */
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 499) == MS_REPLAY);
    /* Older than the window is refused rather than guessed at. */
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 500 - MS_WINDOW_BITS) == MS_REPLAY);

    /* The counter domains are independent. */
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_VIDEO, 1) == MS_FRESH);
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_VIDEO, 1) == MS_REPLAY);
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 1) == MS_REPLAY);    /* far behind */

    /* And so are senders. */
    CHECK(ms_accept_seq(&t, ib, MK_STREAM_AUDIO, 1) == MS_FRESH);

    /* A forged counter far in the future must not drag the window with it:
     * that is how one packet silences a participant for the rest of a call. */
    CHECK(ms_accept_seq(&t, ib, MK_STREAM_AUDIO, 1 + MK_MAX_CTR_JUMP + 1) == MS_JUMP);
    CHECK(ms_accept_seq(&t, ib, MK_STREAM_AUDIO, 2) == MS_FRESH);     /* still working */
    /* A large but plausible jump is fine - packet loss happens. */
    CHECK(ms_accept_seq(&t, ib, MK_STREAM_AUDIO, 2 + MK_MAX_CTR_JUMP) == MS_FRESH);

    /* --- tombstones -------------------------------------------------------------- */
    /* Release the slot and reinstall the same salt: the window must resume,
     * not restart, or a recording replays cleanly into the new slot. */
    CHECK(ms_accept_seq(&t, ia, MK_STREAM_AUDIO, 900) == MS_FRESH);
    CHECK(ms_retire(&t, ia) == MS_OK);
    CHECK(ms_count(&t) == 1);
    CHECK(ms_key(&t, ia, MK_STREAM_AUDIO) == NULL);
    CHECK(ms_retire(&t, ia) == MS_ERR_NOT_FOUND);

    int ia2 = -1;
    CHECK(ms_install(&t, a, zeros, 0, &ia2) == MS_OK);
    CHECK(ms_accept_seq(&t, ia2, MK_STREAM_AUDIO, 900) == MS_REPLAY);
    /* 899 was never seen and is inside the window, so it is legitimately
     * fresh - the tombstone preserves what was seen, not a floor. */
    CHECK(ms_accept_seq(&t, ia2, MK_STREAM_AUDIO, 899) == MS_FRESH);
    CHECK(ms_accept_seq(&t, ia2, MK_STREAM_AUDIO, 899) == MS_REPLAY);
    CHECK(ms_accept_seq(&t, ia2, MK_STREAM_AUDIO, 901) == MS_FRESH);
    /* Far behind the restored high-water mark stays refused. */
    CHECK(ms_accept_seq(&t, ia2, MK_STREAM_AUDIO, 700) == MS_REPLAY);

    /* --- a full table refuses rather than evicting -------------------------------- */
    static ms_table_t full;
    CHECK(ms_init(&full, k_call, call_id, NULL) == MS_OK);
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        uint8_t s[MK_SALT_BYTES];
        memset(s, 0, sizeof s);
        s[0] = (uint8_t)(i + 1);
        s[1] = 0x77;
        int idx = -1;
        CHECK(ms_install(&full, s, zeros, 0, &idx) == MS_OK);
    }
    CHECK(ms_count(&full) == MS_MAX_SLOTS);

    uint8_t late[MK_SALT_BYTES];
    memset(late, 0xEE, sizeof late);
    int late_idx = -1;
    CHECK(ms_install(&full, late, zeros, 0, &late_idx) == MS_ERR_FULL);
    /* Nobody was displaced by the attempt. */
    CHECK(ms_count(&full) == MS_MAX_SLOTS);

    /* An already-present sender still resolves even when the table is full. */
    uint8_t s1[MK_SALT_BYTES];
    memset(s1, 0, sizeof s1); s1[0] = 1; s1[1] = 0x77;
    int known = -1;
    CHECK(ms_install(&full, s1, zeros, 0, &known) == MS_OK);

    /* --- identity is bound ---------------------------------------------------------- */
    /* The same salt under a different identity is a different sender, with a
     * different key and a different tag. */
    static ms_table_t idt;
    CHECK(ms_init(&idt, k_call, call_id, NULL) == MS_OK);
    uint8_t pk[MK_IDBIND_BYTES];
    memset(pk, 0x42, sizeof pk);
    int i_unsigned = -1, i_signed = -1;
    CHECK(ms_install(&idt, c, zeros, 0, &i_unsigned) == MS_OK);
    CHECK(ms_install(&idt, c, pk, 0, &i_signed) == MS_OK);
    CHECK(i_unsigned != i_signed);
    CHECK(memcmp(ms_key(&idt, i_unsigned, MK_STREAM_AUDIO),
                 ms_key(&idt, i_signed, MK_STREAM_AUDIO), MK_KEY_BYTES) != 0);

    ms_clear(&t);
    ms_clear(&full);
    ms_clear(&idt);

    return t_report("test_media_senders");
}
