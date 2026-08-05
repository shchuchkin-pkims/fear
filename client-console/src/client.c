/**
 * @file client.c
 * @brief F.E.A.R. console client implementation
 *
 * Handles all client-side functionality:
 * - Connecting to server and joining rooms
 * - Encrypting and sending messages
 * - Receiving and decrypting messages from other users
 * - File transfers with encryption and integrity checking
 * - User list updates from server
 *
 * Security model:
 * - All messages are encrypted with room key before transmission
 * - Server never sees plaintext (zero-knowledge architecture)
 * - AES-256-GCM provides confidentiality and authenticity
 * - File integrity verified with CRC32 checksums
 */

#include "client.h"
#include "network.h"
#include "identity.h"
#include "key_schedule.h"
#include "chat_frame.h"
#include "room_keys.h"
#include "rotation_bundle.h"
#include "call_invite.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <sodium.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>          /* _isatty, _fileno */
#else
#include <sys/select.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>      /* isatty */
#endif

/**
 * Line ending for file-transfer progress output.
 *
 * '\r' keeps the classic single-line live progress in a terminal. When
 * stdout is a pipe (the GUI wraps this CLI and reads line by line), every
 * update must be a complete '\n'-terminated line or the reader never sees
 * the progress at all and the transfer looks hung.
 */
static char progress_eol(void) {
    static int tty = -1;
#ifdef _WIN32
    if (tty < 0) tty = _isatty(_fileno(stdout));
#else
    if (tty < 0) tty = isatty(fileno(stdout));
#endif
    return tty ? '\r' : '\n';
}

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#endif

/* Create directory (no error if it already exists). Cross-platform. */
static int mkdir_p_one(const char *dir) {
#ifdef _WIN32
    int rc = _mkdir(dir);
#else
    int rc = mkdir(dir, 0755);
#endif
    if (rc != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Ensure the parent directory of `path` exists, creating intermediate dirs as
 * needed. Safe to call repeatedly. */
static void ensure_parent_dir(const char *path) {
    if (!path || !*path) return;
    char buf[512];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Find rightmost separator — that's the boundary between dir and filename. */
    char *last = strrchr(buf, '/');
#ifdef _WIN32
    char *last_bs = strrchr(buf, '\\');
    if (last_bs > last) last = last_bs;
#endif
    if (!last) return;       /* no directory component */
    *last = '\0';
    if (buf[0] == '\0') return;

    /* Walk through path components, mkdir each one. */
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/'
#ifdef _WIN32
            || *p == '\\'
#endif
            ) {
            *p = '\0';
            mkdir_p_one(buf);
            *p = '/';
        }
    }
    mkdir_p_one(buf);
}

/* Identity signing state (module-level) */
static int g_has_identity = 0;
static uint8_t g_identity_pk[IDENTITY_PK_BYTES];
static uint8_t g_identity_sk[IDENTITY_SK_BYTES];
static char g_known_keys_path[512];

/* Defined below with the sealing helpers; the file's first sender is above
 * it and needs the declaration. */
static void chat_keyring(const uint8_t *k_room, cf_key_t *out);

/* Forward declarations for signed message functions */
static int send_signed_file_message(sock_t s, const char *room, const char *name,
                                    const uint8_t *key, message_type_t type,
                                    const uint8_t *data, size_t data_len,
                                    const char *filename, size_t file_size, uint32_t crc,
                                    const uint8_t id_sk[IDENTITY_SK_BYTES],
                                    const uint8_t id_pk[IDENTITY_PK_BYTES]);

/* Module-level room key pointer (set in run_client, used by KEY_REQUEST handler) */
static const uint8_t *g_room_key = NULL;

/*
 * The generations of K_room we hold, and who is in the room.
 *
 * The roster exists because rotation has to address a bundle to every member
 * by identity key, and until now nothing kept one: identities were checked
 * against the TOFU store as they arrived and then forgotten. The store is on
 * disk and keyed by name; what rotation needs is who is here *now*.
 */
static room_keys_t g_rk;
static int g_rk_ready = 0;

/*
 * Rotation waits for the room to agree on who is in it.
 *
 * The server announces a membership change before the members involved have
 * said who they are, so for a moment every client holds a different roster -
 * and an election run on differing rosters elects everybody. That is not
 * hypothetical: run three clients without this and two of them rotate at
 * once, each sealing a bundle only it can open.
 *
 * So a membership change arms a rotation instead of performing one. The wait
 * is what lets the identity announcements land, after which every roster is
 * the same and the election has one answer. A member that never announces an
 * identity would otherwise hold the room forever, so the wait has an end.
 */
#define ROT_SETTLE_MS   1500   /**< quiet time after the last roster change */
#define ROT_DEADLINE_MS 6000   /**< stop waiting on a member that stays silent */

static int      g_rot_pending  = 0;
static uint64_t g_rot_settle_at = 0;
static uint64_t g_rot_deadline  = 0;

static uint64_t rot_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

#define ROSTER_MAX 64

typedef struct {
    char    name[MAX_NAME];
    uint8_t pk[IDENTITY_PK_BYTES];
    int     has_identity;
    int     present;
    int     was_present;   /**< here before the change now being handled */
} roster_entry_t;

static roster_entry_t g_roster[ROSTER_MAX];
static int g_roster_count = 0;
static int g_saw_first_user_list = 0;

/*
 * Whether we have a "before" to compare against.
 *
 * The list that greets us on arrival is not a change we witnessed - we have
 * no idea what the room looked like a moment earlier, so we cannot say who
 * was already in it, and the members who were will not count us either. Until
 * a change happens with us watching, we take no part in electing a rotator
 * and we accept the one the room picked.
 */
static int g_have_before = 0;

/** Freeze the present set as the "before" of the next membership change. */
static void roster_snapshot_present(void) {
    for (int i = 0; i < g_roster_count; i++) {
        g_roster[i].was_present = g_roster[i].present;
    }
}

/** Remember, or update, one member's identity key. */
static void roster_note_identity(const char *name, const uint8_t *pk) {
    if (!name || !pk) return;
    for (int i = 0; i < g_roster_count; i++) {
        if (strcmp(g_roster[i].name, name) != 0) continue;
        memcpy(g_roster[i].pk, pk, IDENTITY_PK_BYTES);
        g_roster[i].has_identity = 1;
        return;
    }
    if (g_roster_count >= ROSTER_MAX) return;
    snprintf(g_roster[g_roster_count].name, MAX_NAME, "%s", name);
    memcpy(g_roster[g_roster_count].pk, pk, IDENTITY_PK_BYTES);
    g_roster[g_roster_count].has_identity = 1;
    g_roster[g_roster_count].present = 1;
    g_roster_count++;
}

/** Mark who the server says is here. Returns 1 if the set changed. */
static int roster_set_present(char names[][MAX_NAME], int count) {
    int changed = 0;

    for (int i = 0; i < g_roster_count; i++) {
        int here = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(g_roster[i].name, names[j]) == 0) { here = 1; break; }
        }
        if (g_roster[i].present != here) { g_roster[i].present = here; changed = 1; }
    }

    for (int j = 0; j < count; j++) {
        int known = 0;
        for (int i = 0; i < g_roster_count; i++) {
            if (strcmp(g_roster[i].name, names[j]) == 0) { known = 1; break; }
        }
        if (known || g_roster_count >= ROSTER_MAX) continue;
        snprintf(g_roster[g_roster_count].name, MAX_NAME, "%s", names[j]);
        g_roster[g_roster_count].has_identity = 0;
        g_roster[g_roster_count].present = 1;
        g_roster_count++;
        changed = 1;
    }
    return changed;
}

/** True once every member the server lists has told us who they are. */
static int roster_identities_complete(void) {
    for (int i = 0; i < g_roster_count; i++) {
        if (g_roster[i].present && !g_roster[i].has_identity) return 0;
    }
    return 1;
}

/**
 * The members eligible to rotate: here before the change, and still here.
 *
 * A member that has just arrived must not be elected, and the reason is
 * arithmetic rather than principle. It holds generation zero and has no way
 * to know the room is on generation four, so the "next" generation it would
 * draw is one the room has already used - and everyone else discards it as a
 * replay while the newcomer installs it and stops being able to read
 * anything. A member that was already here knows what generation this is.
 *
 * Every continuing member computes the same set from the same sequence of
 * user lists, so the election still has exactly one answer.
 */
static size_t roster_continuing(rk_member_t *out, size_t cap) {
    size_t n = 0;
    for (int i = 0; i < g_roster_count && n < cap; i++) {
        if (!g_roster[i].present || !g_roster[i].was_present) continue;
        memcpy(out[n].pk, g_roster[i].pk, IDENTITY_PK_BYTES);
        out[n].has_identity = g_roster[i].has_identity;
        n++;
    }
    return n;
}


static sock_t g_sock = -1;
static const char *g_room = NULL;
static const char *g_name = NULL;

/* Phase B-8: heartbeat. The CLI runs an extra thread that sends a
 * MSG_TYPE_PING zero-nonce service frame every PING_INTERVAL_SEC. The
 * server bumps last_seen on every recv and kicks anyone silent for
 * IDLE_TIMEOUT_SEC (240s on the server), so 60s gives ~4 missed pings
 * of slack before a real network problem turns into a kick. */
#define PING_INTERVAL_SEC 60

/**
 * @brief Send a zero-nonce service frame (unencrypted payload)
 *
 * Used for KEY_REQUEST and KEY_RESPONSE messages that use the same
 * wire format as normal frames but with a zero nonce to indicate
 * they are service messages (not encrypted).
 */
static int send_service_frame(sock_t s, const char *room, const char *name,
                               uint8_t msg_type, const uint8_t *payload, size_t payload_len) {
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t zero_nonce[CRYPTO_NPUBBYTES];
    memset(zero_nonce, 0, sizeof zero_nonce);

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + payload_len;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) return -1;

    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, zero_nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = msg_type;
    wr_u32(w, (uint32_t)payload_len); w += 4;
    memcpy(w, payload, payload_len);

    int rc = send_all(s, frame, flen);
    free(frame);
    return rc;
}

/**
 * @brief Perform ECDH key exchange as a joiner
 *
 * Generates an ephemeral X25519 keypair, sends a KEY_REQUEST,
 * then waits for a KEY_RESPONSE containing the room key
 * encrypted with crypto_box.
 *
 * @param s Connected socket
 * @param room Room name
 * @param name Our username
 * @param key_out Buffer to receive 32-byte room key
 * @return 0 on success, -1 on failure/timeout
 */
static int ecdh_join_room(sock_t s, const char *room, const char *name, uint8_t key_out[32]) {
    unsigned char my_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(my_pk, my_sk);

    /* Send KEY_REQUEST with our ephemeral public key */
    if (send_service_frame(s, room, name, MSG_TYPE_KEY_REQUEST, my_pk, sizeof my_pk) < 0) {
        sodium_memzero(my_sk, sizeof my_sk);
        return -1;
    }
    printf("[join] Waiting for room key from existing member...\n");
    fflush(stdout);

    /* Blocking recv loop with 30s timeout */
#ifdef _WIN32
    DWORD tv = 30000;
#else
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    int result = -1;
    size_t my_name_len = strlen(name);

    while (1) {
        /* Read frame header: room */
        uint8_t hdr2[2];
        if (recv_all(s, hdr2, 2) < 0) break;
        uint16_t room_len = rd_u16(hdr2);
        if (room_len > MAX_ROOM) break;
        char *room_in = (char*)malloc(room_len + 1);
        if (!room_in) break;
        if (recv_all(s, room_in, room_len) < 0) { free(room_in); break; }
        room_in[room_len] = '\0';

        /* name */
        uint8_t nlenbuf[2];
        if (recv_all(s, nlenbuf, 2) < 0) { free(room_in); break; }
        uint16_t name_len = rd_u16(nlenbuf);
        if (name_len > MAX_NAME) { free(room_in); break; }
        char *sender = (char*)malloc(name_len + 1);
        if (!sender) { free(room_in); break; }
        if (recv_all(s, sender, name_len) < 0) { free(room_in); free(sender); break; }
        sender[name_len] = '\0';

        /* nonce */
        uint8_t npbuf[2];
        if (recv_all(s, npbuf, 2) < 0) { free(room_in); free(sender); break; }
        uint16_t nonce_len = rd_u16(npbuf);
        if (nonce_len != CRYPTO_NPUBBYTES) { free(room_in); free(sender); break; }
        uint8_t nonce[CRYPTO_NPUBBYTES];
        if (recv_all(s, nonce, nonce_len) < 0) { free(room_in); free(sender); break; }

        /* type + clen + cipher */
        uint8_t type_buf[1];
        if (recv_all(s, type_buf, 1) < 0) { free(room_in); free(sender); break; }
        uint8_t clenbuf[4];
        if (recv_all(s, clenbuf, 4) < 0) { free(room_in); free(sender); break; }
        uint32_t clen = rd_u32(clenbuf);
        if (clen > MAX_FRAME) { free(room_in); free(sender); break; }
        uint8_t *payload = (uint8_t*)malloc(clen);
        if (!payload) { free(room_in); free(sender); break; }
        if (recv_all(s, payload, clen) < 0) { free(room_in); free(sender); free(payload); break; }

        /* Check if this is a KEY_RESPONSE service message for us */
        int is_zero_nonce = 1;
        for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
            if (nonce[i] != 0) { is_zero_nonce = 0; break; }
        }

        if (type_buf[0] == MSG_TYPE_KEY_RESPONSE && is_zero_nonce &&
            strcmp(room_in, room) == 0) {
            /* Parse: [name_len(2)][name][eph_pk(32)][nonce(24)][cipher(48)]
             * Optional signed tail: [id_pk(32)][sig(64)] */
            size_t base_len = crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES +
                              (32 + crypto_box_MACBYTES);
            size_t min_len = 2 + 0 + base_len;
            if (clen >= min_len) {
                const uint8_t *p = payload;
                uint16_t target_len = rd_u16(p); p += 2;

                if (target_len <= clen - min_len &&
                    target_len == my_name_len &&
                    memcmp(p, name, target_len) == 0) {

                    p += target_len;
                    const uint8_t *responder_pk = p; p += crypto_box_PUBLICKEYBYTES;
                    const uint8_t *box_nonce = p; p += crypto_box_NONCEBYTES;
                    const uint8_t *box_cipher = p; p += (32 + crypto_box_MACBYTES);
                    size_t box_cipher_len = 32 + crypto_box_MACBYTES;

                    /* Identity signature (anti-MITM) - MANDATORY.
                     * The responder must prove ownership of an Ed25519 identity
                     * over its ephemeral X25519 key. Without this, a hostile relay
                     * - or any room member that answers KEY_REQUEST first - can
                     * hand us a room key it already knows and transparently MITM
                     * the whole conversation. This check previously "failed open":
                     * a missing or invalid signature only printed a warning and
                     * the key was accepted anyway. Anything short of a verified
                     * signature now aborts the join. */
                    size_t consumed = 2 + target_len + base_len;
                    size_t remaining = clen - consumed;
                    int sig_verified = 0;

                    if (remaining < IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
                        fprintf(stderr,
                                "[join] REJECTED: '%s' sent an unsigned key response.\n"
                                "[join] The room owner needs an identity key (do not use --no-sign).\n",
                                sender);
                    } else {
                        const uint8_t *id_pk = p;
                        const uint8_t *sig = p + IDENTITY_PK_BYTES;
                        if (identity_verify(responder_pk, crypto_box_PUBLICKEYBYTES,
                                            sig, id_pk) != 0) {
                            fprintf(stderr,
                                    "[join] REJECTED: signature verification FAILED for '%s'"
                                    " - possible MITM attack.\n", sender);
                        } else {
                            /* TOFU check the responder's identity */
                            tofu_result_t tofu = identity_tofu_check(
                                g_known_keys_path, sender, id_pk);
                            char fp_buf[IDENTITY_FINGERPRINT_LEN];
                            identity_pk_fingerprint(id_pk, fp_buf);
                            if (tofu == TOFU_KEY_MATCH || tofu == TOFU_KEY_MATCH_VERIFIED) {
                                printf("[join] Key exchange verified: %s [%s]\n",
                                       sender, fp_buf);
                                sig_verified = 1;
                            } else if (tofu == TOFU_NEW_KEY) {
                                printf("[join] New identity for '%s': %s (trusted on first use)\n",
                                       sender, fp_buf);
                                sig_verified = 1;
                            }
                            /* Into the roster, not just the TOFU store.
                             *
                             * This loop reads frames looking for a key
                             * response and drops everything else, so the
                             * announcement this member made when we arrived
                             * is gone. Without recording them here the first
                             * thing we do in the room is refuse their
                             * rotation, having no idea who else is in it. */
                            if (sig_verified) roster_note_identity(sender, id_pk); else if (tofu == TOFU_KEY_CONFLICT) {
                                /* Blocking: a changed identity key is exactly what an
                                 * active MITM looks like, so we must not proceed. */
                                fprintf(stderr,
                                    "\n*** REJECTED: identity key for '%s' has CHANGED! ***\n"
                                    "*** This could indicate a MITM attack. Fingerprint: %s ***\n"
                                    "*** Verify out of band, then remove the stale entry from\n"
                                    "*** %s if the change is expected. ***\n\n",
                                    sender, fp_buf, g_known_keys_path);
                            } else {
                                fprintf(stderr,
                                        "[join] REJECTED: could not check identity of '%s'.\n",
                                        sender);
                            }
                        }
                    }

                    if (!sig_verified) {
                        fprintf(stderr, "[join] Aborting key exchange - room key not accepted.\n");
                        fflush(stderr);
                        free(room_in); free(sender); free(payload);
                        break;
                    }

                    if (crypto_box_open_easy(key_out, box_cipher, box_cipher_len,
                                              box_nonce, responder_pk, my_sk) == 0) {
                        char *b64_key = b64_encode(key_out, 32);
                        printf("[join] Room key received from '%s' (identity verified)\n",
                               sender);
                        if (b64_key) {
                            printf("[join] Room key: %s\n", b64_key);
                            free(b64_key);
                        }
                        fflush(stdout);
                        result = 0;
                    } else {
                        fprintf(stderr, "[join] Failed to decrypt room key\n");
                    }
                    free(room_in); free(sender); free(payload);
                    break;
                }
            }
        }

        free(room_in);
        free(sender);
        free(payload);
    }

    /* Restore blocking mode (no timeout) */
#ifdef _WIN32
    tv = 0;
#else
    tv.tv_sec = 0;
    tv.tv_usec = 0;
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    sodium_memzero(my_sk, sizeof my_sk);
    return result;
}

/**
 * @brief Handle an incoming KEY_REQUEST by sending the room key
 *
 * Called from recv_and_decrypt when a KEY_REQUEST service message is received.
 * Generates an ephemeral X25519 keypair and encrypts the room key for the joiner.
 */
static void handle_key_request(sock_t s, const char *room, const char *myname,
                                const uint8_t *room_key, const char *joiner_name,
                                const uint8_t *joiner_pk) {
    unsigned char my_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(my_pk, my_sk);

    unsigned char box_nonce[crypto_box_NONCEBYTES];
    randombytes_buf(box_nonce, sizeof box_nonce);

    unsigned char box_cipher[32 + crypto_box_MACBYTES];
    if (crypto_box_easy(box_cipher, room_key, 32, box_nonce, joiner_pk, my_sk) != 0) {
        sodium_memzero(my_sk, sizeof my_sk);
        return;
    }

    /* If we have an identity key, sign our ephemeral X25519 public key
     * to prove we are who we claim (anti-MITM).
     * Payload: [name_len(2)][name][eph_pk(32)][nonce(24)][cipher(48)][id_pk(32)][sig(64)] */
    size_t jname_len = strlen(joiner_name);
    size_t sig_extra = g_has_identity ? (IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) : 0;
    size_t payload_len = 2 + jname_len + crypto_box_PUBLICKEYBYTES +
                          crypto_box_NONCEBYTES + sizeof box_cipher + sig_extra;
    uint8_t *payload = (uint8_t*)malloc(payload_len);
    if (!payload) { sodium_memzero(my_sk, sizeof my_sk); return; }

    uint8_t *w = payload;
    wr_u16(w, (uint16_t)jname_len); w += 2;
    memcpy(w, joiner_name, jname_len); w += jname_len;
    memcpy(w, my_pk, crypto_box_PUBLICKEYBYTES); w += crypto_box_PUBLICKEYBYTES;
    memcpy(w, box_nonce, crypto_box_NONCEBYTES); w += crypto_box_NONCEBYTES;
    memcpy(w, box_cipher, sizeof box_cipher); w += sizeof box_cipher;

    if (g_has_identity) {
        memcpy(w, g_identity_pk, IDENTITY_PK_BYTES); w += IDENTITY_PK_BYTES;
        /* Sign the ephemeral public key with our Ed25519 identity key */
        if (identity_sign(my_pk, crypto_box_PUBLICKEYBYTES, g_identity_sk, w) != 0) {
            fprintf(stderr, "[key-exchange] Failed to sign ephemeral key - aborting.\n");
            sodium_memzero(my_sk, sizeof my_sk);
            free(payload);
            return;
        }
    } else {
        /* Joiners now reject unsigned responses (anti-MITM), so warn loudly
         * instead of silently producing a room nobody can join. */
        fprintf(stderr,
                "[key-exchange] WARNING: no identity key available - this response is\n"
                "[key-exchange] unsigned and joining clients will REJECT it.\n");
    }

    send_service_frame(s, room, myname, MSG_TYPE_KEY_RESPONSE, payload, payload_len);

    sodium_memzero(my_sk, sizeof my_sk);
    free(payload);
    printf("[key-exchange] Sent room key to '%s'%s\n", joiner_name,
           g_has_identity ? " (signed)" : " (UNSIGNED - will be rejected)");
    fflush(stdout);
}

typedef struct {
    FILE *fp;
    size_t total_size;
    size_t received;
    uint32_t expected_crc;
    uint32_t current_crc;
    char filename[MAX_FILENAME];       /* final save path (after accept) */
    char temp_filename[MAX_FILENAME];  /* temp path during transfer */
    char orig_filename[MAX_FILENAME];  /* original filename from sender */
    char sender_name[MAX_NAME];        /* who sent the file */
    int pending_acceptance;            /* 1 = waiting for /accept or /reject */
    int rejected;                      /* 1 = user rejected this transfer */
    int completed;                     /* 1 = all data received, awaiting decision */
} file_transfer_t;

static file_transfer_t current_transfer = {0};

int send_file_message(sock_t s, const char *room, const char *name,
                     const uint8_t *key, message_type_t type,
                     const uint8_t *data, size_t data_len,
                     const char *filename, size_t file_size, uint32_t crc) {
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Собираем payload (plain), в котором будут метаданные + данные
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (type == MSG_TYPE_FILE_START) {
        uint16_t fn_len = (uint16_t)strlen(filename);
        payload_len = 2 + fn_len + 4 + 4; // fn_len + filename + file_size + crc
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;

        uint8_t *w = payload;
        wr_u16(w, fn_len); w += 2;
        memcpy(w, filename, fn_len); w += fn_len;
        wr_u32(w, (uint32_t)file_size); w += 4;
        wr_u32(w, crc); w += 4;
    }
    else if (type == MSG_TYPE_FILE_CHUNK) {
        payload_len = 4 + data_len; // chunk_crc + chunk_data
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;

        uint8_t *w = payload;
        wr_u32(w, crc); w += 4;
        memcpy(w, data, data_len);
    }
    else if (type == MSG_TYPE_FILE_END) {
        payload_len = 4; // финальный CRC
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;

        wr_u32(payload, crc);
    }

    // Шифруем
    size_t cmax = payload_len + CF_OVERHEAD_BYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(payload); return -1; }
    
    size_t clen = 0;
    cf_key_t ck;
    chat_keyring(key, &ck);
    if (cf_seal(&ck, room, name, payload, payload_len, nonce, cipher, cmax, &clen) != CF_OK) {
        free(cipher); free(payload);
        return -1;
    }

    // Формируем финальный frame
    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(cipher); free(payload); return -1; }

    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2; memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)type;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(cipher);
    free(payload);
    free(frame);
    return rc;
}


void handle_file_transfer(const char *filename, const uint8_t key[32],
                         const char *room, const char *name, sock_t s) {
    /* Extract basename to avoid leaking directory structure */
    char *tmp = strdup(filename);
    const char *base_name;
#ifdef _WIN32
    const char *bs = strrchr(tmp, '\\');
    const char *fs = strrchr(tmp, '/');
    const char *sep = (bs > fs) ? bs : fs;
    base_name = sep ? sep + 1 : tmp;
#else
    base_name = basename(tmp);
#endif

    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Cannot open file: %s\n", filename);
        free(tmp);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size == 0) {
        fclose(file);
        printf("File is empty: %s\n", filename);
        free(tmp);
        return;
    }

    // Вычисляем CRC всего файла
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        fclose(file);
        printf("Memory error\n");
        free(tmp);
        return;
    }

    size_t bytes_read = fread(file_data, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        printf("File read error: expected %zu bytes, got %zu\n", file_size, bytes_read);
        sodium_memzero(file_data, file_size);
        free(file_data);
        free(tmp);
        return;
    }

    uint32_t file_crc = crc32(file_data, file_size);

    // Отправляем начало файла
    int file_rc;
    if (g_has_identity) {
        file_rc = send_signed_file_message(s, room, name, key, MSG_TYPE_FILE_START,
                                           NULL, 0, base_name, file_size, file_crc,
                                           g_identity_sk, g_identity_pk);
    } else {
        file_rc = send_file_message(s, room, name, key, MSG_TYPE_FILE_START,
                                    NULL, 0, base_name, file_size, file_crc);
    }
    if (file_rc < 0) {
        sodium_memzero(file_data, file_size);
        free(file_data);
        free(tmp);
        printf("Failed to send file start\n");
        return;
    }

    printf("Sending file: %s (%zu bytes)\n", filename, file_size);

    // Отправляем chunks
    size_t offset = 0;
    while (offset < file_size) {
        size_t chunk_size = (file_size - offset) > FILE_CHUNK_SIZE ?
                           FILE_CHUNK_SIZE : (file_size - offset);

        uint32_t chunk_crc = crc32(file_data + offset, chunk_size);

        if (g_has_identity) {
            file_rc = send_signed_file_message(s, room, name, key, MSG_TYPE_FILE_CHUNK,
                                               file_data + offset, chunk_size, NULL, 0, chunk_crc,
                                               g_identity_sk, g_identity_pk);
        } else {
            file_rc = send_file_message(s, room, name, key, MSG_TYPE_FILE_CHUNK,
                                        file_data + offset, chunk_size, NULL, 0, chunk_crc);
        }
        if (file_rc < 0) {
            printf("File transfer failed\n");
            break;
        }

        offset += chunk_size;
        printf("Progress: %zu/%zu bytes (%.1f%%)%c", offset, file_size,
               (float)offset/file_size*100, progress_eol());
        fflush(stdout);
    }

    // Отправляем конец файла
    if (g_has_identity) {
        send_signed_file_message(s, room, name, key, MSG_TYPE_FILE_END,
                                 NULL, 0, NULL, 0, file_crc,
                                 g_identity_sk, g_identity_pk);
    } else {
        send_file_message(s, room, name, key, MSG_TYPE_FILE_END, NULL, 0, NULL, 0, file_crc);
    }
    printf("\nFile sent successfully: %s\n", filename);

    sodium_memzero(file_data, file_size);
    free(file_data);
    free(tmp);
}

void receive_file(const char *temp_path, size_t total_size,
                 const uint8_t *data, size_t data_len) {
    if (current_transfer.fp == NULL) {
        ensure_parent_dir(temp_path);   /* mkdir -p Downloads */
        current_transfer.fp = fopen(temp_path, "wb");
        if (!current_transfer.fp) {
            printf("Cannot create temp file: %s\n", temp_path);
            return;
        }
        current_transfer.total_size = total_size;
        current_transfer.received = 0;
        current_transfer.current_crc = 0xFFFFFFFF;
        strncpy(current_transfer.temp_filename, temp_path, MAX_FILENAME - 1);
    }

    if (current_transfer.fp && data && data_len > 0) {
        fwrite(data, 1, data_len, current_transfer.fp);
        current_transfer.received += data_len;

        for (size_t i = 0; i < data_len; i++) {
            current_transfer.current_crc ^= data[i];
            for (int j = 0; j < 8; j++) {
                current_transfer.current_crc = (current_transfer.current_crc >> 1) ^
                    (0xEDB88320 & -(current_transfer.current_crc & 1));
            }
        }

        printf("Progress: %zu/%zu bytes (%.1f%%)%c",
               current_transfer.received, current_transfer.total_size,
               (float)current_transfer.received/current_transfer.total_size*100,
               progress_eol());
        fflush(stdout);

        if (current_transfer.received >= current_transfer.total_size) {
            fclose(current_transfer.fp);
            current_transfer.fp = NULL;

            current_transfer.current_crc = ~current_transfer.current_crc;

            if (current_transfer.current_crc != current_transfer.expected_crc) {
                printf("\nFile corrupted: CRC mismatch, deleting temp file\n");
                remove(temp_path);
                current_transfer.rejected = 1;
            } else {
                current_transfer.completed = 1;
                if (current_transfer.pending_acceptance) {
                    printf("\nFile fully received. Waiting for your decision (/accept or /reject).\n");
                    fflush(stdout);
                } else {
                    /* Auto-accepted or already accepted */
                    if (current_transfer.filename[0] != '\0') {
                        rename(current_transfer.temp_filename, current_transfer.filename);
                        printf("\nFile saved: %s\n", current_transfer.filename);
                    }
                }
            }
        }
    }
}

/**
 * Handle /accept [path] command from user input.
 * Moves received temp file to final location.
 */
static void handle_accept_command(const char *arg) {
    if (!current_transfer.pending_acceptance && !current_transfer.completed) {
        printf("No pending file transfer to accept.\n");
        fflush(stdout);
        return;
    }

    char final_path[MAX_FILENAME];
    if (arg && strlen(arg) > 0) {
        strncpy(final_path, arg, MAX_FILENAME - 1);
        final_path[MAX_FILENAME - 1] = '\0';
    } else {
        snprintf(final_path, sizeof(final_path), "Downloads/%s",
                 current_transfer.orig_filename);
    }

    current_transfer.pending_acceptance = 0;
    strncpy(current_transfer.filename, final_path, MAX_FILENAME - 1);

    if (current_transfer.completed) {
        /* File already fully received - move from temp */
        ensure_parent_dir(final_path);   /* user-picked path may target a fresh dir */
        if (rename(current_transfer.temp_filename, final_path) == 0) {
            printf("File saved: %s\n", final_path);
        } else {
            printf("Failed to save file to %s (trying copy)\n", final_path);
            /* Fallback: copy + delete */
            FILE *src = fopen(current_transfer.temp_filename, "rb");
            FILE *dst = fopen(final_path, "wb");
            if (src && dst) {
                uint8_t buf[8192];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                    fwrite(buf, 1, n, dst);
                }
                fclose(src);
                fclose(dst);
                remove(current_transfer.temp_filename);
                printf("File saved: %s\n", final_path);
            } else {
                if (src) fclose(src);
                if (dst) fclose(dst);
                printf("Failed to save file\n");
            }
        }
        memset(&current_transfer, 0, sizeof(current_transfer));
    }
    /* else: still receiving, will be moved when complete */
    fflush(stdout);
}

/**
 * Handle /reject command from user input.
 */
static void handle_reject_command(void) {
    if (!current_transfer.pending_acceptance && !current_transfer.completed &&
        current_transfer.temp_filename[0] == '\0') {
        printf("No pending file transfer to reject.\n");
        fflush(stdout);
        return;
    }

    current_transfer.rejected = 1;
    current_transfer.pending_acceptance = 0;

    if (current_transfer.fp) {
        fclose(current_transfer.fp);
        current_transfer.fp = NULL;
    }
    if (current_transfer.temp_filename[0] != '\0') {
        remove(current_transfer.temp_filename);
    }
    printf("File transfer rejected.\n");
    fflush(stdout);
    memset(&current_transfer, 0, sizeof(current_transfer));
}


/**
 * @brief Replace C0 control bytes (and DEL) in a display string, in place.
 *
 * Everything this CLI prints is parsed line by line by the Qt GUI, which trusts
 * the leading markers ([V]/[T]/[?]/[!], [TOFU], [FILE_OFFER]) as a control
 * channel. A peer that embeds a raw newline in its display name, message body
 * or file name could therefore forge an entire line and fake a "verified"
 * badge or impersonate another participant. Neutralising control bytes keeps
 * one message on exactly one line, defuses terminal escape sequences, and also
 * stops newlines from being written into the line-based known_keys store.
 * UTF-8 (>= 0x80) is preserved untouched.
 */
static void sanitize_display_inplace(char *s, size_t len) {
    if (!s) return;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F) s[i] = '?';
    }
}

void handle_file_message(const uint8_t *plain, size_t plen, message_type_t type,
                        const char *room_in, const char *sender_name,
                        const uint8_t *key, const char *my_name) {
    (void)room_in;
    (void)key;

    if (strcmp(sender_name, my_name) == 0) return;

    /* If user already rejected this transfer, discard chunks */
    if (current_transfer.rejected && type != MSG_TYPE_FILE_START) {
        if (type == MSG_TYPE_FILE_END) {
            memset(&current_transfer, 0, sizeof(current_transfer));
        }
        return;
    }

    switch (type) {
        case MSG_TYPE_FILE_START: {
            const uint8_t *p = plain;
            /* Bounds-check every field against plen before reading it. fn_len is
             * attacker-controlled (up to 65535) and used to be memcpy'd straight
             * into this 1024-byte stack buffer by any room participant, which
             * smashed the stack. The trailing check also covers the file_size
             * and crc reads below. */
            if (plen < 2) return;
            uint16_t fn_len = rd_u16(p); p += 2;
            if (fn_len >= MAX_FILENAME) return;
            if (plen < (size_t)2 + fn_len + 4 + 4) return;
            char orig_filename[MAX_FILENAME];
            memcpy(orig_filename, p, fn_len); p += fn_len;
            orig_filename[fn_len] = '\0';
            /* Printed in the [FILE_OFFER] line the GUI parses - see above. */
            sanitize_display_inplace(orig_filename, fn_len);

            const char *basename = strrchr(orig_filename, '\\');
            if (!basename) basename = strrchr(orig_filename, '/');
            if (basename) basename++;
            else basename = orig_filename;

            size_t file_size = rd_u32(p); p += 4;
            uint32_t expected_crc = rd_u32(p);

            /* Reset transfer state */
            memset(&current_transfer, 0, sizeof(current_transfer));
            current_transfer.expected_crc = expected_crc;
            current_transfer.pending_acceptance = 1;
            strncpy(current_transfer.orig_filename, basename, MAX_FILENAME - 1);
            strncpy(current_transfer.sender_name, sender_name, MAX_NAME - 1);

            /* Save to temp file while waiting for acceptance */
            char temp_path[MAX_FILENAME];
            snprintf(temp_path, sizeof(temp_path), "Downloads/.fear_temp_%s", basename);

            /* Print offer for user (console) and GUI parsing */
            char size_str[64];
            if (file_size >= 1048576) {
                snprintf(size_str, sizeof(size_str), "%.1f MB", (double)file_size / 1048576.0);
            } else if (file_size >= 1024) {
                snprintf(size_str, sizeof(size_str), "%.1f KB", (double)file_size / 1024.0);
            } else {
                snprintf(size_str, sizeof(size_str), "%zu B", file_size);
            }
            printf("[FILE_OFFER] %s wants to send \"%s\" (%s). Type /accept [path] or /reject\n",
                   sender_name, basename, size_str);
            fflush(stdout);

            receive_file(temp_path, file_size, NULL, 0);
            break;
        }
        case MSG_TYPE_FILE_CHUNK: {
            if (plen < 4) return;
            uint32_t chunk_crc = rd_u32(plain);
            const uint8_t *chunk_data = plain + 4;
            size_t chunk_len = plen - 4;

            if (crc32(chunk_data, chunk_len) != chunk_crc) {
                printf("Chunk CRC error\n");
                return;
            }

            receive_file(current_transfer.temp_filename, 0, chunk_data, chunk_len);
            break;
        }
        case MSG_TYPE_FILE_END: {
            if (plen < 4) return;
            uint32_t final_crc = rd_u32(plain);
            (void)final_crc; /* CRC check is done inside receive_file */

            if (!current_transfer.pending_acceptance && !current_transfer.rejected) {
                /* Already accepted - file was saved in receive_file */
                printf("\nFile transfer completed: %s\n", current_transfer.filename);
                memset(&current_transfer, 0, sizeof(current_transfer));
            }
            /* else: still pending, receive_file handles the completion message */
            break;
        }
        default:
            break;
    }
}

/* Defined below; declared here because the invite helper needs it. */
int send_ciphertext_typed(sock_t s, const char *room, const char *name,
                          const uint8_t *key, const uint8_t *plaintext,
                          size_t plen, uint8_t msg_type);

/**
 * Announce a call to the room.
 *
 * The initiator draws the call_id here. Every media key is bound to it, so
 * it has to be fresh per call: a value derived from the room key would be
 * the same for every call in that room and a recording of one would replay
 * into the next. It is printed on stdout because the caller - a person or
 * the GUI - has to hand it to the media binary as --call-id.
 *
 * `arg` is "[host] [port] [video]", all optional. Without a host the invite
 * carries no direct hint and the call goes through the relay, which is also
 * the group case.
 */
static void handle_invite_command(const char *arg, sock_t s,
                                  const char *room, const char *name,
                                  const uint8_t *key) {
    ci_invite_t inv;
    memset(&inv, 0, sizeof inv);
    inv.flags = CI_FLAG_AUDIO;

    char host[CI_MAX_HOST + 1] = {0};
    unsigned port = 0;
    char extra[16] = {0};
    int have_id = 0;

    /* An explicit id may come first. The GUI needs it: it has to hand the
     * same value to the media process, and waiting for this command to
     * report one back would be a race against the call starting. */
    if (arg && *arg) {
        char maybe_id[64] = {0};
        if (sscanf(arg, "%63s", maybe_id) == 1 &&
            mk_call_id_parse(maybe_id, inv.call_id) == 0) {
            have_id = 1;
            arg += strlen(maybe_id);
            while (*arg == ' ') arg++;
        }
    }

    if (arg && *arg) {
        int n = sscanf(arg, "%255s %u %15s", host, &port, extra);
        if (n >= 1 && strcmp(host, "video") == 0) {
            inv.flags |= CI_FLAG_VIDEO;
            host[0] = '\0';
        }
        if (strcmp(extra, "video") == 0) inv.flags |= CI_FLAG_VIDEO;
        if (port > 65535) {
            printf("[invite] port out of range\n");
            fflush(stdout);
            return;
        }
    }
    inv.port = (uint16_t)port;
    snprintf(inv.host, sizeof inv.host, "%s", host);

    if (!have_id) randombytes_buf(inv.call_id, sizeof inv.call_id);

    uint8_t payload[CI_MAX_BYTES];
    size_t plen = 0;
    ci_status_t st = ci_build(&inv, payload, sizeof payload, &plen);
    if (st != CI_OK) {
        printf("[invite] cannot build invite: %s\n", ci_strerror(st));
        fflush(stdout);
        return;
    }

    if (send_ciphertext_typed(s, room, name, key, payload, plen,
                              (uint8_t)MSG_TYPE_CALL_INVITE) < 0) {
        printf("[invite] send failed\n");
        fflush(stdout);
        return;
    }

    char hex[2 * MK_CALLID_BYTES + 1];
    for (size_t i = 0; i < MK_CALLID_BYTES; i++)
        snprintf(hex + 2 * i, 3, "%02x", inv.call_id[i]);
    printf("[CALL_INVITE_SENT] %s %s %u %s\n", hex,
           inv.host[0] ? inv.host : "-", inv.port,
           (inv.flags & CI_FLAG_VIDEO) ? "video" : "audio");
    fflush(stdout);
}

/**
 * The room key as a generation. There is one for now and its version is zero;
 * rotation is what will make this a real lookup, and everything that reads a
 * frame already takes a set rather than a key so that day changes callers
 * here and nothing below them.
 */
/**
 * Draw a new K_room and hand it to everyone present.
 *
 * The bundle is sealed under the generation being replaced, not the new one:
 * nobody has the new key yet, and a message nobody can open is not a way to
 * distribute it. Installing ours therefore happens after the bundle is on
 * the wire, so that we are still able to seal it.
 *
 * A member present without an identity gets no entry - there is no key to
 * address one to. They keep reading under the old generation until it
 * expires, and then they are out of the room, which is what having no
 * identity in a room that rotates means.
 */
static void rotation_rotate_now(sock_t s, const char *room, const char *myname,
                                const uint8_t *active_key) {
    if (!g_has_identity || !g_rk_ready) return;

    uint8_t recipients[ROSTER_MAX][32];
    size_t nrec = 0;
    for (int i = 0; i < g_roster_count && nrec < ROSTER_MAX; i++) {
        if (!g_roster[i].present || !g_roster[i].has_identity) continue;
        memcpy(recipients[nrec++], g_roster[i].pk, 32);
    }
    if (nrec == 0) return;

    uint8_t k_new[ROTATION_KEY_BYTES];
    randombytes_buf(k_new, sizeof k_new);

    uint16_t next = (uint16_t)(g_rk.current_version + 1);
    /* The version is what tells a rotation from a replay, so wrapping it
     * would make an old bundle look current. Sixty-five thousand membership
     * changes in one room is somebody else's problem, and refusing is the
     * honest answer to it. */
    if (next < g_rk.current_version) {
        fprintf(stderr, "[rotation] generation counter exhausted; not rotating\n");
        sodium_memzero(k_new, sizeof k_new);
        return;
    }

    uint8_t bundle[RB_HEADER_BYTES + ROSTER_MAX * ROTATION_ENTRY_BYTES];
    size_t blen = 0;
    rb_status_t rs = rb_build(room, next, k_new, g_identity_sk, g_identity_pk,
                              (const uint8_t (*)[32])recipients, nrec,
                              bundle, sizeof bundle, &blen);
    if (rs != RB_OK) {
        fprintf(stderr, "[rotation] could not build a bundle: %s\n", rb_strerror(rs));
        sodium_memzero(k_new, sizeof k_new);
        return;
    }

    /* Broadcast, not sealed under K_room. Every entry is already sealed to
     * one member's identity key, so there is nothing here the server could
     * read - and a member who has just joined has no current K_room to open
     * an envelope with, which is exactly the member a rotation has to
     * reach. */
    (void)active_key;
    if (send_service_frame(s, room, myname, (uint8_t)MSG_TYPE_ROTATION,
                           bundle, blen) < 0) {
        fprintf(stderr, "[rotation] could not send the bundle\n");
        sodium_memzero(k_new, sizeof k_new);
        return;
    }

    rk_install(&g_rk, next, k_new, (uint64_t)time(NULL));
    sodium_memzero(k_new, sizeof k_new);
    printf("[rotation] room key is now generation %u, sealed for %zu member(s)\n",
           (unsigned)next, nrec);
    fflush(stdout);
}

/**
 * Rotate if a membership change is waiting and the room has settled.
 *
 * Called from the receive loop, so it costs nothing when nothing is pending.
 */
static void rotation_tick(sock_t s, const char *room, const char *myname,
                          const uint8_t *active_key) {
    if (!g_rot_pending || !g_has_identity || !g_rk_ready) return;

    uint64_t now = rot_now_ms();
    if (now < g_rot_settle_at) return;
    if (!roster_identities_complete() && now < g_rot_deadline) return;

    g_rot_pending = 0;

    rk_member_t members[ROSTER_MAX];
    size_t nmem = roster_continuing(members, ROSTER_MAX);
    /* Every member reaches this same answer from the same roster, so exactly
     * one of them goes on. */
    if (rk_is_rotator(members, nmem, g_identity_pk)) {
        rotation_rotate_now(s, room, myname, active_key);
    }
}

/** Take in a rotation somebody else sent. */
static void rotation_handle_bundle(const char *room, const char *sender,
                                   const uint8_t *payload, size_t plen) {
    if (!g_has_identity || !g_rk_ready) return;

    rb_view_t view;
    rb_status_t rs = rb_parse(payload, plen, &view);
    if (rs != RB_OK) {
        fprintf(stderr, "[rotation] ignoring a bundle from %s: %s\n",
                sender, rb_strerror(rs));
        return;
    }

    /* Whoever sealed it has to be the member this room expects to rotate.
     * Without this check any member could rotate at any time, which is a
     * denial of service dressed as a key update - and with two members
     * rotating at once the room would split. rb_open_for authenticates the
     * sender; this decides whether that sender had the right. */
    /* An election needs a roster, and a member who has just arrived may not
     * have one yet - the announcements that build it can have been made
     * before it was listening. Refusing then would lock it out of the room it
     * has just joined, so the check is made only when we actually know who is
     * in the room. Until then the entry being sealed to our identity key and
     * authenticated as coming from its sender is what we have, and the only
     * thing going unchecked is whether that sender was the member the room
     * elected - which is not something we are in any position to check. */
    rk_member_t members[ROSTER_MAX];
    size_t nmem = roster_continuing(members, ROSTER_MAX);
    if (g_have_before && roster_identities_complete() &&
        !rk_is_rotator(members, nmem, view.sender_pk)) {
        fprintf(stderr, "[rotation] ignoring a bundle from %s: not this room's rotator\n",
                sender);
        return;
    }

    /* Only ever forward. An older generation arriving late is a replay. */
    if (view.key_version <= g_rk.current_version) return;

    uint8_t k_new[ROTATION_KEY_BYTES];
    rs = rb_open_for(&view, room, g_identity_sk, g_identity_pk, k_new);
    if (rs != RB_OK) {
        fprintf(stderr, "[rotation] could not open our entry from %s: %s\n",
                sender, rb_strerror(rs));
        return;
    }

    rk_install(&g_rk, view.key_version, k_new, (uint64_t)time(NULL));
    sodium_memzero(k_new, sizeof k_new);
    printf("[rotation] room key is now generation %u, from %s\n",
           (unsigned)view.key_version, sender);
    fflush(stdout);
}

static void chat_keyring(const uint8_t *k_room, cf_key_t *out) {
    /* Before the first rotation - and in the GUI's short-lived helper
     * processes, which never see one - the room key is generation zero and
     * the store is empty. */
    if (g_rk_ready) {
        const cf_key_t *cur = rk_current(&g_rk);
        if (cur) { *out = *cur; return; }
    }
    out->version = 0;
    memcpy(out->key, k_room, KS_KEY_BYTES);
}

/**
 * Every generation still readable, current first.
 *
 * A rotation does not stop what was already in flight under the generation
 * it replaces, so the receive path asks for the set rather than the key.
 */
static size_t chat_keyring_all(const uint8_t *k_room, cf_key_t *out, size_t cap) {
    if (g_rk_ready) {
        rk_expire(&g_rk, (uint64_t)time(NULL));
        size_t n = rk_ring(&g_rk, out, cap);
        if (n > 0) return n;
    }
    if (cap == 0) return 0;
    chat_keyring(k_room, &out[0]);
    return 1;
}

int send_ciphertext_typed(sock_t s, const char *room, const char *name, const uint8_t *key,
                   const uint8_t *plaintext, size_t plen, uint8_t msg_type) {
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);


    /* Room for the epoch header the seal puts in front of the ciphertext. */
    size_t cmax = plen + CF_OVERHEAD_BYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) return -1;

    size_t clen = 0;
    cf_key_t ck;
    chat_keyring(key, &ck);
    if (cf_seal(&ck, room, name, plaintext, plen, nonce, cipher, cmax, &clen) != CF_OK) {
        free(cipher);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(cipher); return -1; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;

    *w++ = msg_type;

    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(cipher);
    free(frame);
    return rc;
}

/** Ordinary chat text. Kept so the call sites that predate typed sends do
 *  not have to name a type they never vary. */
int send_ciphertext(sock_t s, const char *room, const char *name, const uint8_t *key,
                    const uint8_t *plaintext, size_t plen) {
    return send_ciphertext_typed(s, room, name, key, plaintext, plen, (uint8_t)MSG_TYPE_TEXT);
}

/**
 * Send a signed encrypted text message.
 * Plaintext layout: [pk(32)][sig(64)][message]
 * Signature covers the original message bytes.
 */
static int send_signed_ciphertext(sock_t s, const char *room, const char *name,
                                  const uint8_t *key,
                                  const uint8_t *plaintext, size_t plen,
                                  const uint8_t id_sk[IDENTITY_SK_BYTES],
                                  const uint8_t id_pk[IDENTITY_PK_BYTES]) {
    size_t signed_plen = IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES + plen;
    uint8_t *signed_plain = (uint8_t*)malloc(signed_plen);
    if (!signed_plain) return -1;

    /* [pk(32)] */
    memcpy(signed_plain, id_pk, IDENTITY_PK_BYTES);

    /* [sig(64)] over original plaintext */
    if (identity_sign(plaintext, plen, id_sk,
                      signed_plain + IDENTITY_PK_BYTES) != 0) {
        free(signed_plain);
        return -1;
    }

    /* [message(N)] */
    memcpy(signed_plain + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES, plaintext, plen);

    /* Encrypt and send as MSG_TYPE_SIGNED_TEXT */
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t cmax = signed_plen + CF_OVERHEAD_BYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(signed_plain); return -1; }

    size_t clen = 0;
    cf_key_t ck;
    chat_keyring(key, &ck);
    if (cf_seal(&ck, room, name, signed_plain, signed_plen, nonce, cipher, cmax, &clen) != CF_OK) {
        free(cipher); free(signed_plain);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(cipher); free(signed_plain); return -1; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_SIGNED_TEXT;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(cipher);
    free(frame);
    free(signed_plain);
    return rc;
}

/**
 * Send identity announcement on room join.
 * Plaintext layout: [pk(32)][sig_over_name(64)]
 */
static int send_identity_announce(sock_t s, const char *room, const char *name,
                                  const uint8_t *key,
                                  const uint8_t id_sk[IDENTITY_SK_BYTES],
                                  const uint8_t id_pk[IDENTITY_PK_BYTES]) {
    uint8_t plain[IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES];
    memcpy(plain, id_pk, IDENTITY_PK_BYTES);
    if (identity_sign((const uint8_t*)name, strlen(name), id_sk,
                      plain + IDENTITY_PK_BYTES) != 0) {
        return -1;
    }

    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t plen = sizeof(plain);
    size_t cmax = plen + CF_OVERHEAD_BYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { return -1; }

    size_t clen = 0;
    /* The founding key, not whatever generation is current.
     *
     * A member who has just joined holds nothing else, and cannot be handed
     * the current key until the room knows who they are - which is what this
     * message is for. Sealing it under the current generation would make
     * joining a room that has ever rotated impossible.
     *
     * It costs nothing to secrecy: the contents are a public key and a
     * signature over a name. Sealing it at all is so that the server does
     * not get a list of who is in the room. */
    cf_key_t ck;
    ck.version = 0;
    memcpy(ck.key, key, KS_KEY_BYTES);
    if (cf_seal(&ck, room, name, plain, plen, nonce, cipher, cmax, &clen) != CF_OK) {
        free(cipher);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(cipher); return -1; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_IDENTITY_ANNOUNCE;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(cipher);
    free(frame);
    return rc;
}

/**
 * Send a signed file message. Wraps send_file_message by prepending [pk][sig] to payload.
 */
static int send_signed_file_message(sock_t s, const char *room, const char *name,
                                    const uint8_t *key, message_type_t type,
                                    const uint8_t *data, size_t data_len,
                                    const char *filename, size_t file_size, uint32_t crc,
                                    const uint8_t id_sk[IDENTITY_SK_BYTES],
                                    const uint8_t id_pk[IDENTITY_PK_BYTES]) {
    /* Map unsigned type to signed type */
    message_type_t signed_type;
    switch (type) {
        case MSG_TYPE_FILE_START: signed_type = MSG_TYPE_SIGNED_FILE_START; break;
        case MSG_TYPE_FILE_CHUNK: signed_type = MSG_TYPE_SIGNED_FILE_CHUNK; break;
        case MSG_TYPE_FILE_END:   signed_type = MSG_TYPE_SIGNED_FILE_END;   break;
        default: return -1;
    }

    /* Build original payload (same logic as send_file_message) */
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (type == MSG_TYPE_FILE_START) {
        uint16_t fn_len = (uint16_t)strlen(filename);
        payload_len = 2 + fn_len + 4 + 4;
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        uint8_t *w = payload;
        wr_u16(w, fn_len); w += 2;
        memcpy(w, filename, fn_len); w += fn_len;
        wr_u32(w, (uint32_t)file_size); w += 4;
        wr_u32(w, crc);
    } else if (type == MSG_TYPE_FILE_CHUNK) {
        payload_len = 4 + data_len;
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        wr_u32(payload, crc);
        memcpy(payload + 4, data, data_len);
    } else if (type == MSG_TYPE_FILE_END) {
        payload_len = 4;
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        wr_u32(payload, crc);
    }

    /* Build signed payload: [pk(32)][sig(64)][original_payload] */
    size_t signed_plen = IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES + payload_len;
    uint8_t *signed_plain = (uint8_t*)malloc(signed_plen);
    if (!signed_plain) { free(payload); return -1; }

    memcpy(signed_plain, id_pk, IDENTITY_PK_BYTES);
    identity_sign(payload, payload_len, id_sk, signed_plain + IDENTITY_PK_BYTES);
    memcpy(signed_plain + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES, payload, payload_len);
    free(payload);

    /* Encrypt and send */
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t cmax = signed_plen + CF_OVERHEAD_BYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(signed_plain); return -1; }

    size_t clen = 0;
    cf_key_t ck;
    chat_keyring(key, &ck);
    if (cf_seal(&ck, room, name, signed_plain, signed_plen, nonce, cipher, cmax, &clen) != CF_OK) {
        free(cipher); free(signed_plain);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(cipher); free(signed_plain); return -1; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)signed_type;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(cipher);
    free(frame);
    free(signed_plain);
    return rc;
}

int recv_and_decrypt(sock_t s, const char *room, const uint8_t *key, const char *myname) {
    uint8_t hdr2[2];
    if (recv_all(s, hdr2, 2) < 0) return -1;
    uint16_t room_len = rd_u16(hdr2);
    if (room_len > MAX_ROOM) return -1;
    char *room_in = (char*)malloc(room_len + 1);
    if (!room_in) return -1;
    if (recv_all(s, room_in, room_len) < 0) { free(room_in); return -1; }
    room_in[room_len] = '\0';

    uint8_t nlenbuf[2];
    if (recv_all(s, nlenbuf, 2) < 0) { free(room_in); return -1; }
    uint16_t name_len = rd_u16(nlenbuf);
    if (name_len > MAX_NAME) { free(room_in); return -1; }
    char *name = (char*)malloc(name_len + 1);
    if (!name) { free(room_in); return -1; }
    if (recv_all(s, name, name_len) < 0) { free(room_in); free(name); return -1; }
    name[name_len] = '\0';

    uint8_t npbuf[2];
    if (recv_all(s, npbuf, 2) < 0) { free(room_in); free(name); return -1; }
    uint16_t nonce_len = rd_u16(npbuf);
    if (nonce_len != CRYPTO_NPUBBYTES) { free(room_in); free(name); return -1; }
    uint8_t nonce[CRYPTO_NPUBBYTES];
    if (recv_all(s, nonce, nonce_len) < 0) { free(room_in); free(name); return -1; }

    // type
    uint8_t type_buf[1];
    if (recv_all(s, type_buf, 1) < 0) { free(room_in); free(name); return -1; }
    message_type_t msg_type = (message_type_t)type_buf[0];

    // clen (4 байта)
    uint8_t clenbuf[4];
    if (recv_all(s, clenbuf, 4) < 0) { free(room_in); free(name); return -1; }
    uint32_t clen = rd_u32(clenbuf);
    if (clen > MAX_FRAME) { free(room_in); free(name); return -1; }
    uint8_t *cipher = (uint8_t*)malloc(clen);
    if (!cipher) { free(room_in); free(name); return -1; }
    if (recv_all(s, cipher, clen) < 0) { free(room_in); free(name); free(cipher); return -1; }

    int same_room = (strcmp(room, room_in) == 0);

    // Проверяем, является ли это служебным сообщением (nonce заполнен нулями)
    int is_service_message = 1;
    for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
        if (nonce[i] != 0) {
            is_service_message = 0;
            break;
        }
    }

    uint8_t *plain = (uint8_t*)malloc(clen);
    if (!plain) { free(room_in); free(name); free(cipher); return -1; }

    unsigned long long plen = 0;
    int ok = -1;

    if (is_service_message && same_room && msg_type == MSG_TYPE_ROTATION) {
        rotation_handle_bundle(room_in, name, cipher, clen);
        free(room_in); free(name); free(cipher); free(plain);
        return 0;
    } else if (is_service_message && same_room && msg_type == MSG_TYPE_USER_LIST) {
        // Служебное сообщение USER_LIST - не шифруется, просто копируем
        memcpy(plain, cipher, clen);
        plen = clen;
        ok = 0;
    } else if (is_service_message && same_room && msg_type == MSG_TYPE_KEY_REQUEST) {
        /* KEY_REQUEST from a joiner — auto-respond with room key */
        if (clen == crypto_box_PUBLICKEYBYTES && g_room_key != NULL &&
            strcmp(name, myname) != 0) {
            handle_key_request(s, room, myname, g_room_key, name, cipher);
        }
        free(room_in); free(name); free(cipher); free(plain);
        return 0;
    } else if (is_service_message && same_room && msg_type == MSG_TYPE_KEY_RESPONSE) {
        /* KEY_RESPONSE — ignore in normal recv loop (handled by ecdh_join_room) */
        free(room_in); free(name); free(cipher); free(plain);
        return 0;
    } else if (same_room && !is_service_message) {
        // Обычное зашифрованное сообщение
        /* Sealed: [key_version(2)][epoch(4)][AEAD]. chat_open reads the
         * header, refuses an epoch too far from ours before deriving
         * anything, and binds those six bytes into the additional data so a
         * relay cannot move the message to another epoch. */
        size_t opened = 0;
        cf_key_t ring[CF_MAX_KEYS];
        size_t nring;
        if (msg_type == MSG_TYPE_IDENTITY_ANNOUNCE) {
            /* Sealed under the founding key - see send_identity_announce.
             * Only this type: letting chat fall back to it would leave every
             * message readable to anyone who ever held the room key, which is
             * the thing rotation exists to prevent. */
            ring[0].version = 0;
            memcpy(ring[0].key, key, KS_KEY_BYTES);
            nring = 1;
        } else {
            nring = chat_keyring_all(key, ring, CF_MAX_KEYS);
        }
        cf_status_t st = cf_open(ring, nring, room_in, name, cipher, clen, nonce,
                                 plain, clen, &opened);
        ok = (st == CF_OK) ? 0 : -1;
        plen = (unsigned long long)opened;
    }

    if (!same_room || ok != 0 || strcmp(name, myname) == 0) {
        free(room_in); free(name); free(cipher); free(plain);
        return 0;
    }

    /* The sender name is attacker-controlled and is echoed into stdout, into the
     * known_keys store and into GUI labels. Neutralise control bytes now that the
     * AEAD check (which authenticates the raw name) is already done. */
    sanitize_display_inplace(name, strlen(name));

    if (msg_type == MSG_TYPE_CALL_INVITE) {
        /* Already authenticated: this arrived inside the room AEAD, so only
         * a room member could have produced it and the relay cannot forge
         * one. What is still untrusted is the content, which ci_parse
         * checks - in particular the host, which would otherwise reach a
         * connect call straight from another party. */
        ci_invite_t inv;
        ci_status_t st = ci_parse(plain, (size_t)plen, &inv);
        if (st != CI_OK) {
            printf("[invite] dropped an invite from %s: %s\n", name, ci_strerror(st));
        } else {
            char hex[2 * MK_CALLID_BYTES + 1];
            for (size_t i = 0; i < MK_CALLID_BYTES; i++)
                snprintf(hex + 2 * i, 3, "%02x", inv.call_id[i]);
            printf("[CALL_INVITE] %s %s %s %u %s\n", name, hex,
                   inv.host[0] ? inv.host : "-", inv.port,
                   (inv.flags & CI_FLAG_VIDEO) ? "video" : "audio");
        }
        fflush(stdout);
        /* Same exit as every other branch. The bare return here leaked all
         * five buffers on every invitation, and invitations repeat every few
         * seconds for as long as somebody is waiting to be answered - and it
         * did not compile at all on a toolchain where a valueless return from
         * an int function is an error rather than a warning, which is what
         * had the Windows build red. */
        free(room_in); free(name); free(cipher); free(plain);
        return 0;
    }

    if (msg_type == MSG_TYPE_TEXT) {
        // Пропускаем пустые сообщения (регистрационные)
        if (plen > 0) {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            char tbuf[32];
            strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm);
            sanitize_display_inplace((char*)plain, (size_t)plen);
            printf("[%s] [?] %s: %.*s\n", tbuf, name, (int)plen, (char*)plain);
            fflush(stdout);
        }
    } else if (msg_type == MSG_TYPE_SIGNED_TEXT) {
        /* Signed text: [pk(32)][sig(64)][message] */
        if (plen > IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
            const uint8_t *peer_pk = plain;
            const uint8_t *sig = plain + IDENTITY_PK_BYTES;
            const uint8_t *actual_msg = plain + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES;
            size_t actual_len = (size_t)plen - IDENTITY_PK_BYTES - IDENTITY_SIG_BYTES;

            int sig_ok = identity_verify(actual_msg, actual_len, sig, peer_pk);
            tofu_result_t tofu = identity_tofu_check(g_known_keys_path, name, peer_pk);

            const char *prefix = "[!]";
            if (sig_ok == 0) {
                if (tofu == TOFU_KEY_MATCH_VERIFIED) {
                    prefix = "[V]";  /* Verified (manually confirmed) */
                } else if (tofu != TOFU_KEY_CONFLICT) {
                    prefix = "[T]";  /* TOFU trusted (not manually verified) */
                }
            }

            if (tofu == TOFU_NEW_KEY && sig_ok == 0) {
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                printf("[TOFU] New identity for \"%s\": %s\n", name, fp);
                fflush(stdout);
            } else if (tofu == TOFU_KEY_CONFLICT) {
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                printf("[WARNING] KEY CHANGED for \"%s\"! Fingerprint: %s\n", name, fp);
                fflush(stdout);
            }

            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            char tbuf[32];
            strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm);
            /* Signature already verified over the raw bytes above, so it is safe
             * to neutralise control bytes before display. */
            sanitize_display_inplace((char*)plain + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES,
                                     actual_len);
            printf("[%s] %s %s: %.*s\n", tbuf, prefix, name,
                   (int)actual_len, (char*)actual_msg);
            fflush(stdout);
        }
    } else if (msg_type == MSG_TYPE_IDENTITY_ANNOUNCE) {
        /* Identity announcement: [pk(32)][sig_over_name(64)] */
        if (plen >= IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
            const uint8_t *peer_pk = plain;
            const uint8_t *sig = plain + IDENTITY_PK_BYTES;
            uint16_t recv_name_len = (uint16_t)strlen(name);
            int sig_ok = identity_verify((const uint8_t*)name, recv_name_len, sig, peer_pk);
            if (sig_ok == 0) {
                tofu_result_t tofu = identity_tofu_check(g_known_keys_path, name, peer_pk);
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                /* Rotation addresses a bundle to identity keys, so it needs
                 * to know who is here now - the TOFU store is on disk and
                 * says who was ever seen. A conflicting key is not recorded:
                 * it is the case where we do not know who this is. */
                if (tofu != TOFU_KEY_CONFLICT) roster_note_identity(name, peer_pk);
                if (tofu == TOFU_NEW_KEY) {
                    printf("[TOFU] New identity for \"%s\": %s\n", name, fp);
                } else if (tofu == TOFU_KEY_MATCH) {
                    printf("[IDENTITY] \"%s\" trusted (TOFU): %s\n", name, fp);
                } else if (tofu == TOFU_KEY_MATCH_VERIFIED) {
                    printf("[VERIFIED] \"%s\" verified: %s\n", name, fp);
                } else if (tofu == TOFU_KEY_CONFLICT) {
                    printf("[WARNING] KEY CHANGED for \"%s\"! Fingerprint: %s\n", name, fp);
                }
                fflush(stdout);
            }
        }
    } else if (msg_type == MSG_TYPE_USER_LIST) {
        // Обрабатываем список участников
        if (plen >= 2) {
            uint16_t count = rd_u16(plain);
            const uint8_t *p = plain + 2;
            size_t remaining = plen - 2;

            static char names[ROSTER_MAX][MAX_NAME];
            int nnames = 0;

            printf("[USERS] Room participants (%u):", count);
            for (uint16_t i = 0; i < count && remaining >= 2; i++) {
                uint16_t uname_len = rd_u16(p);
                p += 2;
                remaining -= 2;

                if (uname_len > remaining) break;

                printf(" %.*s", (int)uname_len, (char*)p);
                if (i < count - 1) printf(",");

                if (nnames < ROSTER_MAX && uname_len < MAX_NAME) {
                    memcpy(names[nnames], p, uname_len);
                    names[nnames][uname_len] = '\0';
                    nnames++;
                }

                p += uname_len;
                remaining -= uname_len;
            }
            printf("\n");
            fflush(stdout);

            /* A membership change is the whole trigger: somebody joined, so
             * they must not read what came before, or somebody left, so they
             * must not read what comes after. Only the member the room agrees
             * on rotates, and every member reaches that answer from this same
             * list, so there is nothing to coordinate. */
            /* Taken before the new list is applied, and not again while a
             * rotation is already pending - a burst of arrivals is one
             * change, from the room as it stood before any of them. */
            if (g_saw_first_user_list && !g_rot_pending) {
                roster_snapshot_present();
                g_have_before = 1;
            }

            int changed = roster_set_present(names, nnames);

            if (!g_saw_first_user_list) {
                /* Our own arrival. Somebody who was already here rotates for
                 * it; we take this list as our starting point and leave the
                 * "before" set empty, because we did not see one. Marking
                 * ourselves as having been here would put us in an election
                 * the members who really were here are running without us -
                 * and two members rotating at once splits the room. */
                g_saw_first_user_list = 1;
            } else if (changed && g_has_identity && g_rk_ready) {
                /* Say who we are again. A member that just joined has never
                 * heard our announcement - it was sent before they arrived -
                 * and rotation has to address a bundle to them by identity
                 * key. This is the same thing the call beacon does, for the
                 * same reason. */
                send_identity_announce(s, room, myname, key,
                                       g_identity_sk, g_identity_pk);

                uint64_t now = rot_now_ms();
                g_rot_settle_at = now + ROT_SETTLE_MS;
                /* The deadline is set once per pending rotation, not on every
                 * change: a room somebody keeps joining and leaving would
                 * otherwise never reach it. */
                if (!g_rot_pending) g_rot_deadline = now + ROT_DEADLINE_MS;
                g_rot_pending = 1;
            }
        }
    } else if (msg_type >= MSG_TYPE_FILE_START && msg_type <= MSG_TYPE_FILE_END) {
        handle_file_message(plain, (size_t)plen, msg_type, room_in, name, key, myname);
    } else if (msg_type >= MSG_TYPE_SIGNED_FILE_START && msg_type <= MSG_TYPE_SIGNED_FILE_END) {
        /* Signed file messages: strip [pk(32)][sig(64)] prefix, verify, handle as normal */
        if (plen > IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
            const uint8_t *peer_pk = plain;
            const uint8_t *sig = plain + IDENTITY_PK_BYTES;
            const uint8_t *file_plain = plain + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES;
            size_t file_plen = (size_t)plen - IDENTITY_PK_BYTES - IDENTITY_SIG_BYTES;

            int sig_ok = identity_verify(file_plain, file_plen, sig, peer_pk);
            if (sig_ok != 0) {
                printf("[!] File message signature verification failed from %s\n", name);
                fflush(stdout);
            } else {
                identity_tofu_check(g_known_keys_path, name, peer_pk);
            }

            /* Map signed type back to unsigned for handler */
            message_type_t orig_type;
            switch (msg_type) {
                case MSG_TYPE_SIGNED_FILE_START: orig_type = MSG_TYPE_FILE_START; break;
                case MSG_TYPE_SIGNED_FILE_CHUNK: orig_type = MSG_TYPE_FILE_CHUNK; break;
                case MSG_TYPE_SIGNED_FILE_END:   orig_type = MSG_TYPE_FILE_END;   break;
                default: orig_type = msg_type; break;
            }
            handle_file_message(file_plain, file_plen, orig_type, room_in, name, key, myname);
        }
    } else {
        printf("[%s] unknown message type %d\n", name, (int)msg_type);
    }

    free(room_in);
    free(name);
    free(cipher);
   
    free(plain);
    return 1;
}


void print_local_message(const char *name, const char *msg) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char tbuf[9];
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm_info);
    if (g_has_identity) {
        /* Own messages: check if our own key is verified in known_keys */
        tofu_result_t self_tofu = identity_tofu_check(g_known_keys_path,
                                                       name, g_identity_pk);
        const char *prefix = (self_tofu == TOFU_KEY_MATCH_VERIFIED) ? "[V]" : "[T]";
        printf("[%s] %s %s: %s\n", tbuf, prefix, name, msg);
    } else {
        printf("[%s] [?] %s: %s\n", tbuf, name, msg);
    }
    fflush(stdout);
}

#ifdef _WIN32
typedef struct {
    SOCKET s;
    const char *room;
    const char *name;
    const uint8_t *key;
} input_ctx_t;

DWORD WINAPI input_thread(LPVOID param) {
    input_ctx_t *ctx = (input_ctx_t*)param;
    char line[4096];
    for (;;) {
        if (!fgets(line, sizeof line, stdin)) break;
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;

        // File transfer commands
        if (strncmp(line, "/sendfile ", 10) == 0) {
            handle_file_transfer(line + 10, ctx->key, ctx->room, ctx->name, ctx->s);
            continue;
        }
        if (strncmp(line, "/accept", 7) == 0) {
            const char *arg = (strlen(line) > 8) ? line + 8 : NULL;
            handle_accept_command(arg);
            continue;
        }
        if (strncmp(line, "/invite", 7) == 0) {
            const char *arg = (strlen(line) > 8) ? line + 8 : NULL;
            handle_invite_command(arg, ctx->s, ctx->room, ctx->name, ctx->key);
            continue;
        }
        if (strcmp(line, "/reject") == 0) {
            handle_reject_command();
            continue;
        }
        if (strcmp(line, "/reload-identity") == 0) {
            char id_path[512];
            identity_default_path(id_path, sizeof(id_path));
            uint8_t new_pk[IDENTITY_PK_BYTES], new_sk[IDENTITY_SK_BYTES];
            if (identity_load(id_path, new_pk, new_sk) == 0) {
                memcpy(g_identity_pk, new_pk, IDENTITY_PK_BYTES);
                memcpy(g_identity_sk, new_sk, IDENTITY_SK_BYTES);
                g_has_identity = 1;
                sodium_memzero(new_sk, IDENTITY_SK_BYTES);
                send_identity_announce(ctx->s, ctx->room, ctx->name, ctx->key,
                                       g_identity_sk, g_identity_pk);
                printf("[identity] Reloaded. New fingerprint sent to room.\n");
            } else {
                printf("[identity] Failed to reload identity.\n");
            }
            continue;
        }

        int rc;
        if (g_has_identity) {
            rc = send_signed_ciphertext(ctx->s, ctx->room, ctx->name, ctx->key,
                                        (uint8_t*)line, len,
                                        g_identity_sk, g_identity_pk);
        } else {
            rc = send_ciphertext(ctx->s, ctx->room, ctx->name, ctx->key,
                                (uint8_t*)line, len);
        }
        if (rc < 0) {
            printf("send failed (connection lost?)\n");
            break;
        }
        print_local_message(ctx->name, line);
    }
    return 0;
}
#endif

/**
 * AUTO probe: open a short-lived TCP connection and ask the server how many
 * non-media members are in `room`. See client.h for caller contract.
 *
 * The probe runs against a freshly-opened socket because we want to know
 * the room state *before* dial_tcp() inside run_client() commits us to a
 * specific JOIN/CREATE flow.
 */
int probe_room_info(const char *host, uint16_t port, const char *room,
                    int timeout_ms) {
    sock_t s = dial_tcp(host, port);
    if (s < 0) return -1;

#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    if (send_service_frame(s, room, "probe",
                           MSG_TYPE_ROOM_INFO_REQUEST, NULL, 0) < 0) {
        close_socket(s);
        return -1;
    }

    int result = -1;
    /* Read up to 8 frames; skip anything that isn't ROOM_INFO_RESULT. */
    for (int i = 0; i < 8; i++) {
        uint8_t hdr[2];
        if (recv_all(s, hdr, 2) < 0) break;
        uint16_t room_len = rd_u16(hdr);
        if (room_len > MAX_ROOM) break;
        char rbuf[MAX_ROOM];
        if (recv_all(s, rbuf, room_len) < 0) break;

        uint8_t nlb[2];
        if (recv_all(s, nlb, 2) < 0) break;
        uint16_t name_len = rd_u16(nlb);
        if (name_len > MAX_NAME) break;
        char nbuf[MAX_NAME];
        if (recv_all(s, nbuf, name_len) < 0) break;

        uint8_t nplb[2];
        if (recv_all(s, nplb, 2) < 0) break;
        uint16_t nonce_len = rd_u16(nplb);
        if (nonce_len != CRYPTO_NPUBBYTES) break;
        uint8_t nonce[CRYPTO_NPUBBYTES];
        if (recv_all(s, nonce, nonce_len) < 0) break;

        uint8_t tb;
        if (recv_all(s, &tb, 1) < 0) break;
        uint8_t clenbuf[4];
        if (recv_all(s, clenbuf, 4) < 0) break;
        uint32_t clen = rd_u32(clenbuf);
        if (clen > MAX_FRAME) break;

        uint8_t *payload = (uint8_t *)malloc(clen ? clen : 1);
        if (!payload) break;
        if (clen > 0 && recv_all(s, payload, clen) < 0) {
            free(payload); break;
        }
        if (tb == MSG_TYPE_ROOM_INFO_RESULT && clen >= 5) {
            result = (int)rd_u32(payload + 1);
            free(payload);
            break;
        }
        free(payload);
    }

    close_socket(s);
    return result;
}

/* Background heartbeat: send MSG_TYPE_PING every PING_INTERVAL_SEC while
 * g_sock matches the socket the thread was started with. Exits as soon as
 * the socket is replaced (reconnect) or closed. */
#ifdef _WIN32
static DWORD WINAPI ping_thread_fn(LPVOID arg) {
    sock_t my_sock = (sock_t)(intptr_t)arg;
    while (g_sock == my_sock) {
        Sleep(PING_INTERVAL_SEC * 1000);
        if (g_sock != my_sock) break;
        send_service_frame(my_sock, g_room, g_name, MSG_TYPE_PING, NULL, 0);
    }
    return 0;
}
#else
static void *ping_thread_fn(void *arg) {
    sock_t my_sock = (sock_t)(intptr_t)arg;
    while (g_sock == my_sock) {
        sleep(PING_INTERVAL_SEC);
        if (g_sock != my_sock) break;
        send_service_frame(my_sock, g_room, g_name, MSG_TYPE_PING, NULL, 0);
    }
    return NULL;
}
#endif

void run_client(const char *host, uint16_t port, const char *room, const char *name,
                const uint8_t key[32], const uint8_t *id_pk, const uint8_t *id_sk,
                int join_mode) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); exit(1); }

    /* Store identity in module globals */
    if (id_pk && id_sk) {
        g_has_identity = 1;
        memcpy(g_identity_pk, id_pk, IDENTITY_PK_BYTES);
        memcpy(g_identity_sk, id_sk, IDENTITY_SK_BYTES);
    } else {
        g_has_identity = 0;
    }
    identity_default_known_keys_path(g_known_keys_path, sizeof(g_known_keys_path));

    // Set UTF-8 encoding for console output
    #ifdef _WIN32
        // Set console code page to UTF-8
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        _mkdir("Downloads");
    #else
        // Set locale to UTF-8 for Linux/Android
        setlocale(LC_ALL, "");
        mkdir("Downloads", 0755);
    #endif
    sock_t s = dial_tcp(host, port);
    printf("[client] connected to %s:%u, Room name: %s\n", host, port, room);

    /* Use a local copy of the key so we can overwrite it in join mode */
    uint8_t active_key[CRYPTO_KEYBYTES];
    memcpy(active_key, key, CRYPTO_KEYBYTES);

    if (join_mode) {
        /* ECDH key exchange: get room key from existing member */
        if (ecdh_join_room(s, room, name, active_key) != 0) {
            fprintf(stderr, "[join] Key exchange failed (timeout or error)\n");
            close_socket(s);
            return;
        }
    }

    /* Store globals for KEY_REQUEST handler */
    g_room_key = active_key;
    g_sock = s;
    g_room = room;
    g_name = name;

    // Отправляем пустое сообщение для регистрации на сервере
    const char *join_msg = "";
    if (send_ciphertext(s, room, name, active_key, (uint8_t*)join_msg, strlen(join_msg)) < 0) {
        fprintf(stderr, "[client] failed to register with server\n");
        close_socket(s);
        return;
    }

    // Send identity announcement if we have an identity
    /* Generation zero: what the room key exchange produced. Everything after
     * it arrives in a rotation bundle. */
    rk_init(&g_rk, 0, active_key);
    g_rk_ready = 1;
    if (g_has_identity) {
        roster_note_identity(name, g_identity_pk);
        send_identity_announce(s, room, name, active_key, g_identity_sk, g_identity_pk);
    }

    /* Phase B-8: start the heartbeat thread now that g_sock/g_room/g_name
     * are set. The thread polls g_sock against its captured socket so it
     * exits cleanly when run_client returns and the caller closes s. */
#ifdef _WIN32
    HANDLE hPing = CreateThread(NULL, 0, ping_thread_fn,
                                (LPVOID)(intptr_t)s, 0, NULL);
    if (!hPing) fprintf(stderr, "[client] warning: could not start heartbeat thread\n");
#else
    pthread_t ping_tid;
    if (pthread_create(&ping_tid, NULL, ping_thread_fn,
                       (void *)(intptr_t)s) != 0) {
        fprintf(stderr, "[client] warning: could not start heartbeat thread\n");
    } else {
        pthread_detach(ping_tid);
    }
#endif

    printf("Commands: /sendfile <path>, /accept [save_path], /reject. Ctrl+C to exit.\n");

#ifdef _WIN32
    input_ctx_t ctx;
    ctx.s = s;
    ctx.room = room;
    ctx.name = name;
    ctx.key = active_key;
    HANDLE hThread = CreateThread(NULL, 0, input_thread, &ctx, 0, NULL);
    if (!hThread) { fprintf(stderr, "thread create failed\n"); exit(1); }
    for (;;) {
        /* A timeout rather than a blocking read, so a pending rotation still
         * fires in a room where nobody is saying anything. */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.s, &rfds);
        struct timeval tv = { 0, 250000 };
        int r = select(0, &rfds, NULL, NULL, &tv);
        if (r == SOCKET_ERROR) { printf("[client] disconnected\n"); break; }
        if (r > 0) {
            int rc = recv_and_decrypt(ctx.s, ctx.room, ctx.key, ctx.name);
            if (rc < 0) {
                printf("[client] disconnected\n");
                break;
            }
        }
        rotation_tick(ctx.s, ctx.room, ctx.name, ctx.key);
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
#else
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = (s > STDIN_FILENO ? s : STDIN_FILENO) + 1;
        struct timeval tv = { 0, 250000 };
        int r = select(maxfd, &rfds, NULL, NULL, &tv);
        if (r < 0) { if (errno == EINTR) continue; break; }
        rotation_tick(s, room, name, active_key);
        if (FD_ISSET(s, &rfds)) {
            int rc = recv_and_decrypt(s, room, active_key, name);
            if (rc < 0) { printf("[client] disconnected\n"); break; }
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            char *line = NULL;
            size_t cap = 0;
            ssize_t n = getline(&line, &cap, stdin);
            if (n <= 0) { free(line); break; }
            size_t len = (size_t)n;
            if (len && line[len - 1] == '\n') line[--len] = '\0';
            if (len == 0) { free(line); continue; }

            // File transfer commands
            if (strncmp(line, "/sendfile ", 10) == 0) {
                handle_file_transfer(line + 10, active_key, room, name, s);
                free(line);
                continue;
            }
            if (strncmp(line, "/invite", 7) == 0) {
                const char *arg = (strlen(line) > 8) ? line + 8 : NULL;
                handle_invite_command(arg, s, room, name, active_key);
                continue;
            }
            if (strncmp(line, "/accept", 7) == 0) {
                const char *arg = (len > 8) ? line + 8 : NULL;
                handle_accept_command(arg);
                free(line);
                continue;
            }
            if (strcmp(line, "/reject") == 0) {
                handle_reject_command();
                free(line);
                continue;
            }
            if (strcmp(line, "/reload-identity") == 0) {
                char id_path[512];
                identity_default_path(id_path, sizeof(id_path));
                uint8_t new_pk[IDENTITY_PK_BYTES], new_sk[IDENTITY_SK_BYTES];
                if (identity_load(id_path, new_pk, new_sk) == 0) {
                    memcpy(g_identity_pk, new_pk, IDENTITY_PK_BYTES);
                    memcpy(g_identity_sk, new_sk, IDENTITY_SK_BYTES);
                    g_has_identity = 1;
                    sodium_memzero(new_sk, IDENTITY_SK_BYTES);
                    send_identity_announce(s, room, name, active_key, g_identity_sk, g_identity_pk);
                    printf("[identity] Reloaded. New fingerprint sent to room.\n");
                } else {
                    printf("[identity] Failed to reload identity.\n");
                }
                free(line);
                continue;
            }

            int rc;
            if (g_has_identity) {
                rc = send_signed_ciphertext(s, room, name, active_key,
                                            (uint8_t*)line, len,
                                            g_identity_sk, g_identity_pk);
            } else {
                rc = send_ciphertext(s, room, name, active_key, (uint8_t*)line, len);
            }
            if (rc < 0) {
                printf("send failed\n");
                free(line);
                break;
            }
            print_local_message(name, line);
            free(line);
        }
    }
#endif
    sodium_memzero(active_key, sizeof active_key);
    g_room_key = NULL;
    close_socket(s);
}