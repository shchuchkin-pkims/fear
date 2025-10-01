#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>  // Добавлено
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <errno.h>   // Добавлено для errno
#endif

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

static sock_t dial_tcp(const char *host, uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    sock_t s = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int e = getaddrinfo(host, portstr, &hints, &res);
    if (e != 0) { 
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e)); 
        exit(1); 
    }
    
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) break;
        close_socket(s);
        s = -1;
    }
    freeaddrinfo(res);
    
    if (s < 0) die("connect");
    return s;
}

typedef struct {
    FILE *fp;
    size_t total_size;
    size_t received;
    uint32_t expected_crc;
    uint32_t current_crc;
    char filename[MAX_FILENAME];
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
    if (send_file_message(s, room, name, key, MSG_TYPE_FILE_START, 
                         NULL, 0, filename, file_size, file_crc) < 0) {
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
        
        if (send_file_message(s, room, name, key, MSG_TYPE_FILE_CHUNK, 
                             file_data + offset, chunk_size, NULL, 0, chunk_crc) < 0) {
            printf("File transfer failed\n");
            break;
        }

        offset += chunk_size;
        printf("Progress: %zu/%zu bytes (%.1f%%)\r", offset, file_size, 
               (float)offset/file_size*100);
        fflush(stdout);
    }

    // Отправляем конец файла
    send_file_message(s, room, name, key, MSG_TYPE_FILE_END, NULL, 0, NULL, 0, file_crc);
    printf("\nFile sent successfully: %s\n", filename);

    free(file_data);
}

void receive_file(const char *filename, size_t total_size, 
                 const uint8_t *data, size_t data_len) {
    if (current_transfer.fp == NULL) {
        current_transfer.fp = fopen(filename, "wb");
        if (!current_transfer.fp) {
            printf("Cannot create file: %s\n", filename);
            return;
        }
        current_transfer.total_size = total_size;
        current_transfer.received = 0;
        current_transfer.current_crc = 0xFFFFFFFF; // начальное значение
        strncpy(current_transfer.filename, filename, MAX_FILENAME - 1);
        printf("Receiving file: %s (%zu bytes)\n", filename, total_size);
    }

    if (current_transfer.fp && data && data_len > 0) {
        fwrite(data, 1, data_len, current_transfer.fp);
        current_transfer.received += data_len;

        // инкрементное обновление CRC
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

            current_transfer.current_crc = ~current_transfer.current_crc; // финализируем

            if (current_transfer.current_crc == current_transfer.expected_crc) {
                printf("\nFile received successfully: %s\n", filename);
            } else {
                printf("\nFile corrupted: %s (CRC mismatch)\n", filename);
                remove(filename);
            }
        }
    }
}


void handle_file_message(const uint8_t *plain, size_t plen, message_type_t type,
                        const char *room_in, const char *sender_name,
                        const uint8_t *key, const char *my_name) {
    // Помечаем неиспользуемые параметры чтобы избежать warnings
    (void)room_in;
    (void)key;
    
    if (strcmp(sender_name, my_name) == 0) return; // свои пропускаем

    switch (type) {
        case MSG_TYPE_FILE_START: {
            const uint8_t *p = plain;
            uint16_t fn_len = rd_u16(p); p += 2;
            char orig_filename[MAX_FILENAME];
            memcpy(orig_filename, p, fn_len); p += fn_len;
            orig_filename[fn_len] = '\0';

            // вырезаем только имя файла
            const char *basename = strrchr(orig_filename, '\\');
            if (!basename) basename = strrchr(orig_filename, '/');
            if (basename) basename++;
            else basename = orig_filename;

            // сохраняем всегда в Downloads
            char save_path[MAX_FILENAME];
            snprintf(save_path, sizeof(save_path), "Downloads/%s", basename);

            size_t file_size = rd_u32(p); p += 4;
            uint32_t expected_crc = rd_u32(p);

            current_transfer.expected_crc = expected_crc;
            receive_file(save_path, file_size, NULL, 0);
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

            receive_file(current_transfer.filename, 0, chunk_data, chunk_len);
            break;
        }
        case MSG_TYPE_FILE_END: {
            if (plen < 4) return;
            uint32_t final_crc = rd_u32(plain);

            if (current_transfer.current_crc == final_crc) {
                printf("\nFile transfer completed: %s\n", current_transfer.filename);
            } else {
                printf("\nFile transfer failed: CRC mismatch\n");
                remove(current_transfer.filename);
            }
            memset(&current_transfer, 0, sizeof(current_transfer));
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
    uint8_t *plain = (uint8_t*)malloc(clen);
    if (!plain) { free(room_in); free(name); free(cipher); free(ad); return -1; }
    
    unsigned long long plen = 0;
    int ok = -1;
    if (same_room) {
        ok = aes_gcm_decrypt(cipher, clen, ad, ad_len, nonce, key, plain, &plen);
    }

    if (!same_room || ok != 0 || strcmp(name, myname) == 0) {
        free(room_in); free(name); free(cipher); free(ad); free(plain);
        return 0;
    }

    if (msg_type == MSG_TYPE_TEXT) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char tbuf[32];
        strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm);
        printf("[%s] %s: %.*s\n", tbuf, name, (int)plen, (char*)plain);
        fflush(stdout);
    } else if (msg_type >= MSG_TYPE_FILE_START && msg_type <= MSG_TYPE_FILE_END) {
        handle_file_message(plain, (size_t)plen, msg_type, room_in, name, key, myname);
    } else {
        printf("[%s] %s: unknown message type %d\n", name, (int)msg_type);
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
    printf("[%s] %s: %s\n", tbuf, name, msg);
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
        
        // Проверяем команду передачи файла
        if (strncmp(line, "/sendfile ", 10) == 0) {
            const char *filename = line + 10;
            handle_file_transfer(filename, ctx->key, ctx->room, ctx->name, ctx->s);
            continue;
        }
        
        if (send_ciphertext(ctx->s, ctx->room, ctx->name, ctx->key, 
                           (uint8_t*)line, len) < 0) {
            printf("send failed (connection lost?)\n");
            break;
        }
        print_local_message(ctx->name, line);
    }
    return 0;
}
#endif

void run_client(const char *host, uint16_t port, const char *room, const char *name, const uint8_t key[32]) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); exit(1); }
    // ensure Downloads folder exists
    #ifdef _WIN32
        _mkdir("Downloads");
    #else
        mkdir("Downloads", 0755);
    #endif
    sock_t s = dial_tcp(host, port);
    printf("[client] connected to %s:%u, room=\"%s\"\n", host, port, room);
    printf("Type messages and press Enter. Use '/sendfile filename' to send files. Ctrl+C to exit.\n");

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
            if (send_ciphertext(s, room, name, key, (uint8_t*)line, len) < 0) {
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