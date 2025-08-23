#include "common.h"
#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define PROGRAM_VERSION "0.1.0"

/**
 * @brief Print usage into console
 * 
 * @param prog 
 */
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --version\n"
        "  %s genkey\n"
        "  %s server [--port N]\n"
        "  %s client --host HOST --port N --room ROOM --key BASE64 [--name NAME]\n"
        
        "\nNotes:\n"
        "  * Generate a key once per conference with 'genkey'. Share it out-of-band.\n"
        "  * The server sees only metadata (room/name), never plaintext.\n"
        "  * For NAT traversal, port-forward the server's TCP port or host it publicly.\n",
        prog, prog, prog, prog);
}
/**
 * @brief Program version print into console
 * 
 * @return * void 
 */
static void print_version() {
    printf("Program version: %s\n", PROGRAM_VERSION);
    printf("libsodium version: %s\n", sodium_version_string());
}

int main(int argc, char **argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    // --version processing before other commands
    if (strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }
    if (strcmp(argv[1], "genkey") == 0) {
        if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
        uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        randombytes_buf(key, sizeof key);
        char *b64 = b64_encode(key, sizeof key);
        if (!b64) { fprintf(stderr, "oom\n"); return 1; }
        printf("Room key (base64 urlsafe, save/share securely):\n%s\n", b64);
        free(b64);
        return 0;
    }
    if (strcmp(argv[1], "server") == 0) {
        uint16_t port = DEFAULT_PORT;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) { port = (uint16_t)atoi(argv[++i]); }
        }
        run_server(port);
        return 0;
    }
    if (strcmp(argv[1], "client") == 0) {
        const char *host = NULL, *room = NULL, *b64 = NULL, *name = NULL;
        uint16_t port = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
            else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
            else if (strcmp(argv[i], "--room") == 0 && i + 1 < argc) room = argv[++i];
            else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) b64 = argv[++i];
            else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
        }
        if (!host || !port || !room || !b64) { print_usage(argv[0]); return 1; }
        if (!name) name = "anon";
        if (strlen(room) > MAX_ROOM - 1) { fprintf(stderr, "room too long (max %d)\n", MAX_ROOM - 1); return 1; }
        if (strlen(name) > MAX_NAME - 1) { fprintf(stderr, "name too long (max %d)\n", MAX_NAME - 1); return 1; }
        uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        int klen = b64_decode(b64, key, sizeof key);
        if (klen != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            fprintf(stderr, "invalid key (must be 32 bytes base64 urlsafe)\n");
            return 1;
        }
        run_client(host, port, room, name, key);
        return 0;
    }
    print_usage(argv[0]);
    return 1;
}