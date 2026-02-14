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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <sodium.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <errno.h>
#endif

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/* Identity signing state (module-level) */
static int g_has_identity = 0;
static uint8_t g_identity_pk[IDENTITY_PK_BYTES];
static uint8_t g_identity_sk[IDENTITY_SK_BYTES];
static char g_known_keys_path[512];

/* Forward declarations for signed message functions */
static int send_signed_file_message(sock_t s, const char *room, const char *name,
                                    const uint8_t *key, message_type_t type,
                                    const uint8_t *data, size_t data_len,
                                    const char *filename, size_t file_size, uint32_t crc,
                                    const uint8_t id_sk[IDENTITY_SK_BYTES],
                                    const uint8_t id_pk[IDENTITY_PK_BYTES]);

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

    // Associated Data = только room + name
    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) { free(payload); return -1; }
    uint8_t *aw = ad;
    wr_u16(aw, room_len); aw += 2; memcpy(aw, room, room_len); aw += room_len;
    wr_u16(aw, name_len); aw += 2; memcpy(aw, name, name_len);

    // Шифруем
    size_t cmax = payload_len + CRYPTO_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); free(payload); return -1; }
    
    unsigned long long clen = 0;
    if (aes_gcm_encrypt(payload, payload_len, ad, ad_len, nonce, key, cipher, &clen) != 0) {
        free(ad); free(cipher); free(payload);
        return -1;
    }

    // Формируем финальный frame
    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); free(payload); return -1; }

    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2; memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)type;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(ad);
    free(cipher);
    free(payload);
    free(frame);
    return rc;
}


void handle_file_transfer(const char *filename, const uint8_t key[32], 
                         const char *room, const char *name, sock_t s) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Cannot open file: %s\n", filename);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size == 0) {
        fclose(file);
        printf("File is empty: %s\n", filename);
        return;
    }

    // Вычисляем CRC всего файла
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        fclose(file);
        printf("Memory error\n");
        return;
    }

    size_t bytes_read = fread(file_data, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        printf("File read error: expected %zu bytes, got %zu\n", file_size, bytes_read);
        free(file_data);
        return;
    }

    uint32_t file_crc = crc32(file_data, file_size);

    // Отправляем начало файла
    int file_rc;
    if (g_has_identity) {
        file_rc = send_signed_file_message(s, room, name, key, MSG_TYPE_FILE_START,
                                           NULL, 0, filename, file_size, file_crc,
                                           g_identity_sk, g_identity_pk);
    } else {
        file_rc = send_file_message(s, room, name, key, MSG_TYPE_FILE_START,
                                    NULL, 0, filename, file_size, file_crc);
    }
    if (file_rc < 0) {
        free(file_data);
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
        printf("Progress: %zu/%zu bytes (%.1f%%)\r", offset, file_size,
               (float)offset/file_size*100);
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

    free(file_data);
}

void receive_file(const char *temp_path, size_t total_size,
                 const uint8_t *data, size_t data_len) {
    if (current_transfer.fp == NULL) {
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

        printf("Progress: %zu/%zu bytes (%.1f%%)\r",
               current_transfer.received, current_transfer.total_size,
               (float)current_transfer.received/current_transfer.total_size*100);
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
            uint16_t fn_len = rd_u16(p); p += 2;
            char orig_filename[MAX_FILENAME];
            memcpy(orig_filename, p, fn_len); p += fn_len;
            orig_filename[fn_len] = '\0';

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

int send_ciphertext(sock_t s, const char *room, const char *name, const uint8_t *key,
                   const uint8_t *plaintext, size_t plen) {
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[CRYPTO_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) return -1;
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    size_t cmax = plen + CRYPTO_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); return -1; }
    
    unsigned long long clen = 0;
    if (aes_gcm_encrypt(plaintext, plen, ad, ad_len, nonce, key, cipher, &clen) != 0) {
        free(ad); free(cipher);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); return -1; }
    w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;

    *w++ = (uint8_t)MSG_TYPE_TEXT;

    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(ad);
    free(cipher);
    free(frame);
    return rc;
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

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) { free(signed_plain); return -1; }
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    size_t cmax = signed_plen + CRYPTO_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); free(signed_plain); return -1; }

    unsigned long long clen = 0;
    if (aes_gcm_encrypt(signed_plain, signed_plen, ad, ad_len, nonce, key, cipher, &clen) != 0) {
        free(ad); free(cipher); free(signed_plain);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); free(signed_plain); return -1; }
    w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_SIGNED_TEXT;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(ad);
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

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) return -1;
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    size_t plen = sizeof(plain);
    size_t cmax = plen + CRYPTO_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); return -1; }

    unsigned long long clen = 0;
    if (aes_gcm_encrypt(plain, plen, ad, ad_len, nonce, key, cipher, &clen) != 0) {
        free(ad); free(cipher);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); return -1; }
    w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_IDENTITY_ANNOUNCE;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(ad);
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

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) { free(signed_plain); return -1; }
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    size_t cmax = signed_plen + CRYPTO_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); free(signed_plain); return -1; }

    unsigned long long clen = 0;
    if (aes_gcm_encrypt(signed_plain, signed_plen, ad, ad_len, nonce, key, cipher, &clen) != 0) {
        free(ad); free(cipher); free(signed_plain);
        return -1;
    }

    size_t flen = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); free(signed_plain); return -1; }
    w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)signed_type;
    wr_u32(w, (uint32_t)clen); w += 4;
    memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);

    free(ad);
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

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) { free(room_in); free(name); free(cipher); return -1; }
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room_in, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

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
    if (!plain) { free(room_in); free(name); free(cipher); free(ad); return -1; }

    unsigned long long plen = 0;
    int ok = -1;

    if (is_service_message && same_room && msg_type == MSG_TYPE_USER_LIST) {
        // Служебное сообщение USER_LIST - не шифруется, просто копируем
        memcpy(plain, cipher, clen);
        plen = clen;
        ok = 0;
    } else if (same_room && !is_service_message) {
        // Обычное зашифрованное сообщение
        ok = aes_gcm_decrypt(cipher, clen, ad, ad_len, nonce, key, plain, &plen);
    }

    if (!same_room || ok != 0 || strcmp(name, myname) == 0) {
        free(room_in); free(name); free(cipher); free(ad); free(plain);
        return 0;
    }

    if (msg_type == MSG_TYPE_TEXT) {
        // Пропускаем пустые сообщения (регистрационные)
        if (plen > 0) {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            char tbuf[32];
            strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm);
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

            printf("[USERS] Room participants (%u):", count);
            for (uint16_t i = 0; i < count && remaining >= 2; i++) {
                uint16_t uname_len = rd_u16(p);
                p += 2;
                remaining -= 2;

                if (uname_len > remaining) break;

                printf(" %.*s", (int)uname_len, (char*)p);
                if (i < count - 1) printf(",");

                p += uname_len;
                remaining -= uname_len;
            }
            printf("\n");
            fflush(stdout);
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
    free(ad);
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

void run_client(const char *host, uint16_t port, const char *room, const char *name,
                const uint8_t key[32], const uint8_t *id_pk, const uint8_t *id_sk) {
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

    // Отправляем пустое сообщение для регистрации на сервере
    const char *join_msg = "";
    if (send_ciphertext(s, room, name, key, (uint8_t*)join_msg, strlen(join_msg)) < 0) {
        fprintf(stderr, "[client] failed to register with server\n");
        close_socket(s);
        exit(1);
    }

    // Send identity announcement if we have an identity
    if (g_has_identity) {
        send_identity_announce(s, room, name, key, g_identity_sk, g_identity_pk);
    }

    printf("Commands: /sendfile <path>, /accept [save_path], /reject. Ctrl+C to exit.\n");

#ifdef _WIN32
    input_ctx_t ctx;
    ctx.s = s;
    ctx.room = room;
    ctx.name = name;
    ctx.key = key;
    HANDLE hThread = CreateThread(NULL, 0, input_thread, &ctx, 0, NULL);
    if (!hThread) { fprintf(stderr, "thread create failed\n"); exit(1); }
    for (;;) {
        int rc = recv_and_decrypt(ctx.s, ctx.room, ctx.key, ctx.name);
        if (rc < 0) {
            printf("[client] disconnected\n");
            break;
        }
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
        int r = select(maxfd, &rfds, NULL, NULL, NULL);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (FD_ISSET(s, &rfds)) {
            int rc = recv_and_decrypt(s, room, key, name);
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
                handle_file_transfer(line + 10, key, room, name, s);
                free(line);
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
                    send_identity_announce(s, room, name, key, g_identity_sk, g_identity_pk);
                    printf("[identity] Reloaded. New fingerprint sent to room.\n");
                } else {
                    printf("[identity] Failed to reload identity.\n");
                }
                free(line);
                continue;
            }

            int rc;
            if (g_has_identity) {
                rc = send_signed_ciphertext(s, room, name, key,
                                            (uint8_t*)line, len,
                                            g_identity_sk, g_identity_pk);
            } else {
                rc = send_ciphertext(s, room, name, key, (uint8_t*)line, len);
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
    close_socket(s);
}