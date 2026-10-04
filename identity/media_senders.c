/**
 * @file media_senders.c
 * @brief Per-sender key slots and replay windows (see media_senders.h).
 */
#include "media_senders.h"

#include <sodium.h>
#include <string.h>

static void window_reset(ms_window_t *w) {
    w->max_seq = 0;
    w->bitmap  = 0;
    w->started = 0;
}

ms_status_t ms_init(ms_table_t *t,
                    const uint8_t k_call[MK_KEY_BYTES],
                    const uint8_t call_id[MK_CALLID_BYTES],
                    const uint8_t own_salt[MK_SALT_BYTES]) {
    if (!t || !k_call || !call_id) return MS_ERR_ARGS;
    if (sodium_is_zero(call_id, MK_CALLID_BYTES)) return MS_ERR_ARGS;

    memset(t, 0, sizeof *t);
    memcpy(t->k_call, k_call, MK_KEY_BYTES);
    memcpy(t->call_id, call_id, MK_CALLID_BYTES);
    if (own_salt) {
        memcpy(t->own_salt, own_salt, MK_SALT_BYTES);
        t->have_own_salt = 1;
    }
    t->next_order = 1;
    return MS_OK;
}

void ms_clear(ms_table_t *t) {
    if (!t) return;
    sodium_memzero(t, sizeof *t);
}

/**
 * Index of the slot for this exact announcement, or -1.
 *
 * A sender is the whole announcement, not just the salt. Matching on the
 * salt alone would be a lockout: an attacker who captures a salt and
 * announces it first under a different identity would own the slot, and the
 * real HELLO would then be treated as already installed and ignored,
 * leaving the slot holding keys its owner never uses. Since idbind is also
 * bound into the SID, two such announcements never collide on lookup
 * either.
 */
static int find_slot(const ms_table_t *t,
                     const uint8_t salt[MK_SALT_BYTES],
                     const uint8_t idbind[MK_IDBIND_BYTES],
                     uint16_t key_version) {
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!t->slots[i].used) continue;
        if (t->slots[i].key_version != key_version) continue;
        if (sodium_memcmp(t->slots[i].salt, salt, MK_SALT_BYTES) != 0) continue;
        if (sodium_memcmp(t->slots[i].idbind, idbind, MK_IDBIND_BYTES) != 0) continue;
        return i;
    }
    return -1;
}

/** Tombstone for this announcement, or NULL. Keyed like the slots. */
static ms_tomb_t *find_tomb(ms_table_t *t,
                            const uint8_t salt[MK_SALT_BYTES],
                            const uint8_t idbind[MK_IDBIND_BYTES]) {
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!t->tombs[i].used) continue;
        if (sodium_memcmp(t->tombs[i].salt, salt, MK_SALT_BYTES) != 0) continue;
        if (sodium_memcmp(t->tombs[i].idbind, idbind, MK_IDBIND_BYTES) != 0) continue;
        return &t->tombs[i];
    }
    return NULL;
}

ms_status_t ms_install(ms_table_t *t,
                       const uint8_t salt[MK_SALT_BYTES],
                       const uint8_t idbind[MK_IDBIND_BYTES],
                       uint16_t key_version,
                       int *out_idx) {
    if (!t || !salt || !idbind || !out_idx) return MS_ERR_ARGS;

    /* Our own salt echoed back would install a slot whose keys equal our
     * send keys, so our own packets would decrypt as if they came from a
     * peer. Refuse rather than resolve. */
    if (t->have_own_salt &&
        sodium_memcmp(t->own_salt, salt, MK_SALT_BYTES) == 0) {
        return MS_ERR_SELF;
    }

    /* Already installed: idempotent, which is what makes a repeated HELLO a
     * no-op instead of a way to reset somebody's replay window. */
    int existing = find_slot(t, salt, idbind, key_version);
    if (existing >= 0) {
        *out_idx = existing;
        return MS_OK;
    }

    uint8_t sid[MK_SID_BYTES];
    if (mk_sender_id(t->k_call, t->call_id, salt, idbind, sid) != 0) {
        return MS_ERR_ARGS;
    }

    /* A 3-byte tag collides for real, so collisions are survivable - but
     * only up to a cap, or a member could grind salts until every lookup
     * has to try dozens of keys. */
    int sharing = 0;
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (t->slots[i].used && memcmp(t->slots[i].sid, sid, MK_SID_BYTES) == 0) {
            sharing++;
        }
    }
    if (sharing >= MS_SID_CAP) return MS_ERR_SID_CAP;

    int free_idx = -1;
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!t->slots[i].used) { free_idx = i; break; }
    }
    /* Refuse rather than evict: eviction under pressure is a way for one
     * member to push another out of the call. */
    if (free_idx < 0) return MS_ERR_FULL;

    ms_slot_t *s = &t->slots[free_idx];
    memset(s, 0, sizeof *s);
    s->used = 1;
    memcpy(s->sid, sid, MK_SID_BYTES);
    memcpy(s->salt, salt, MK_SALT_BYTES);
    memcpy(s->idbind, idbind, MK_IDBIND_BYTES);
    s->key_version = key_version;
    s->install_order = t->next_order++;

    if (mk_derive_sender(t->k_call, MK_STREAM_AUDIO, key_version, t->call_id,
                         salt, idbind, s->key[MK_STREAM_AUDIO]) != 0 ||
        mk_derive_sender(t->k_call, MK_STREAM_VIDEO, key_version, t->call_id,
                         salt, idbind, s->key[MK_STREAM_VIDEO]) != 0) {
        sodium_memzero(s, sizeof *s);
        return MS_ERR_ARGS;
    }

    /* If this salt was here before, resume its counters instead of zeroing
     * them: otherwise releasing and reinstalling a slot rewinds the replay
     * window and a recording becomes replayable. */
    ms_tomb_t *tomb = find_tomb(t, salt, idbind);
    if (tomb) {
        for (int st = 0; st < MS_STREAMS; st++) s->win[st] = tomb->win[st];
        sodium_memzero(tomb, sizeof *tomb);
    } else {
        for (int st = 0; st < MS_STREAMS; st++) window_reset(&s->win[st]);
    }

    *out_idx = free_idx;
    return MS_OK;
}

ms_status_t ms_retire(ms_table_t *t, int idx) {
    if (!t || idx < 0 || idx >= MS_MAX_SLOTS) return MS_ERR_ARGS;
    ms_slot_t *s = &t->slots[idx];
    if (!s->used) return MS_ERR_NOT_FOUND;

    /* Keep the replay state alive past the slot. Reuse the tombstone for
     * this salt if one exists, otherwise take a free one; if every
     * tombstone is taken, overwrite the oldest by install order - losing an
     * old tombstone is a smaller problem than losing the newest. */
    ms_tomb_t *tomb = find_tomb(t, s->salt, s->idbind);
    if (!tomb) {
        for (int i = 0; i < MS_MAX_SLOTS; i++) {
            if (!t->tombs[i].used) { tomb = &t->tombs[i]; break; }
        }
    }
    if (!tomb) tomb = &t->tombs[0];

    memset(tomb, 0, sizeof *tomb);
    tomb->used = 1;
    memcpy(tomb->salt, s->salt, MK_SALT_BYTES);
    memcpy(tomb->idbind, s->idbind, MK_IDBIND_BYTES);
    for (int st = 0; st < MS_STREAMS; st++) tomb->win[st] = s->win[st];

    sodium_memzero(s, sizeof *s);
    return MS_OK;
}

int ms_count(const ms_table_t *t) {
    if (!t) return 0;
    int n = 0;
    for (int i = 0; i < MS_MAX_SLOTS; i++) if (t->slots[i].used) n++;
    return n;
}

int ms_find_by_sid(const ms_table_t *t,
                   const uint8_t sid[MK_SID_BYTES],
                   int *out_idx) {
    if (!t || !sid || !out_idx) return 0;

    int found = 0;
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!t->slots[i].used) continue;
        if (memcmp(t->slots[i].sid, sid, MK_SID_BYTES) != 0) continue;
        if (found >= MS_SID_CAP) break;

        /* Insert by install order, oldest first. Ordering by recency would
         * let a late arrival with a ground-out colliding salt be tried
         * first and shadow the participant who was already here. */
        int pos = found;
        while (pos > 0 &&
               t->slots[out_idx[pos - 1]].install_order > t->slots[i].install_order) {
            out_idx[pos] = out_idx[pos - 1];
            pos--;
        }
        out_idx[pos] = i;
        found++;
    }
    return found;
}

const uint8_t *ms_key(const ms_table_t *t, int idx, mk_stream_t stream) {
    if (!t || idx < 0 || idx >= MS_MAX_SLOTS) return NULL;
    if (stream != MK_STREAM_AUDIO && stream != MK_STREAM_VIDEO) return NULL;
    if (!t->slots[idx].used) return NULL;
    return t->slots[idx].key[stream];
}

ms_seq_verdict_t ms_accept_seq(ms_table_t *t, int idx,
                               mk_stream_t stream, uint64_t seq) {
    if (!t || idx < 0 || idx >= MS_MAX_SLOTS) return MS_REPLAY;
    if (stream != MK_STREAM_AUDIO && stream != MK_STREAM_VIDEO) return MS_REPLAY;
    if (!t->slots[idx].used) return MS_REPLAY;

    ms_window_t *w = &t->slots[idx].win[stream];

    if (!w->started) {
        /* First packet from this sender anchors the window wherever it
         * lands: a stream may legitimately be joined in progress. */
        w->started = 1;
        w->max_seq = seq;
        w->bitmap  = 1;
        return MS_FRESH;
    }

    if (seq > w->max_seq) {
        const uint64_t advance = seq - w->max_seq;
        /* One forged packet at a huge counter would otherwise drag the
         * window past everything the real sender will ever send. */
        if (advance > MK_MAX_CTR_JUMP) return MS_JUMP;

        if (advance >= MS_WINDOW_BITS) {
            w->bitmap = 1;
        } else {
            w->bitmap = (w->bitmap << advance) | 1ULL;
        }
        w->max_seq = seq;
        return MS_FRESH;
    }

    const uint64_t behind = w->max_seq - seq;
    if (behind >= MS_WINDOW_BITS) return MS_REPLAY;  /* older than the window */

    const uint64_t bit = 1ULL << behind;
    if (w->bitmap & bit) return MS_REPLAY;           /* already seen */

    w->bitmap |= bit;
    return MS_FRESH;
}
