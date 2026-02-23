/**
 * @file main.c
 * @brief Main entry point for F.E.A.R. console client/server
 *
 * Provides command-line interface for:
 * - Generating room keys (genkey)
 * - Running server (server --port N)
 * - Running client (client --host HOST --port N --room ROOM ...)
 * - Displaying version information (--version)
 *
 * Security features:
 * - Keys generated with cryptographically secure RNG
 * - Keys output to stdout (not auto-saved to files)
 * - Secure key input via stdin or --key-file
 * - Warning for insecure --key argument (visible in process list)
 */

#include "common.h"
#include "server.h"
#include "client.h"
#include "identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#define PROGRAM_VERSION "0.4.3"

/**
 * @brief Print command-line usage information
 *
 * Displays help text showing all available commands and their arguments.
 * Includes security notes about key input methods and their priority.
 *
 * @param prog Program name (argv[0])
 */
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --version\n"
        "  %s genkey\n"
        "  %s gen-identity\n"
        "  %s server [--port N]\n"
        "  %s client --host HOST --port N --room ROOM [--key-file FILE] [--name NAME]\n"
        "           [--identity-file FILE] [--no-sign] [--create] [--join]\n"

        "\nKey input methods (in order of priority):\n"
        "  1. --create           Auto-generate room key (first person in room)\n"
        "  2. --join             Request room key via ECDH exchange (join existing room)\n"
        "  3. --key-file FILE    Read key from file (recommended for scripts)\n"
        "  4. stdin              Read key from standard input (interactive or piped)\n"
        "  5. --key BASE64       Direct key argument (DEPRECATED - insecure, visible in process list)\n"

        "\nIdentity (optional Ed25519 signing):\n"
        "  gen-identity          Generate identity keypair (~/.fear/identity)\n"
        "  --identity-file FILE  Path to identity key (default: ~/.fear/identity)\n"
        "  --no-sign             Disable message signing even if identity exists\n"

        "\nNotes:\n"
        "  * Generate a key once per conference with 'genkey'. Share it out-of-band.\n"
        "  * The server sees only metadata (room/name), never plaintext.\n"
        "  * For NAT traversal, port-forward the server's TCP port or host it publicly.\n",
        prog, prog, prog, prog, prog);
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

/**
 * @brief Read key from file securely
 *
 * @param filename Path to key file
 * @param buffer Buffer to store key
 * @param bufsize Size of buffer
 * @return 0 on success, -1 on error
 */
static int read_key_from_file(const char *filename, char *buffer, size_t bufsize) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open key file '%s'\n", filename);
        return -1;
    }

    // Read first line from file
    if (!fgets(buffer, (int)bufsize, f)) {
        fprintf(stderr, "Error: Cannot read from key file '%s'\n", filename);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Remove newline
    buffer[strcspn(buffer, "\r\n")] = '\0';

    if (strlen(buffer) == 0) {
        fprintf(stderr, "Error: Key file is empty\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Read key from stdin securely
 *
 * @param buffer Buffer to store key
 * @param bufsize Size of buffer
 * @param interactive Show prompt if true
 * @return 0 on success, -1 on error
 */
static int read_key_from_stdin(char *buffer, size_t bufsize, int interactive) {
    if (interactive) {
        fprintf(stderr, "Enter room key: ");
        fflush(stderr);
    }

    if (!fgets(buffer, (int)bufsize, stdin)) {
        fprintf(stderr, "Error: Failed to read key from stdin\n");
        return -1;
    }

    // Remove newline
    buffer[strcspn(buffer, "\r\n")] = '\0';

    if (strlen(buffer) == 0) {
        fprintf(stderr, "Error: Empty key provided\n");
        return -1;
    }

    return 0;
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
        uint8_t key[CRYPTO_KEYBYTES];
        randombytes_buf(key, sizeof key);
        char *b64 = b64_encode(key, sizeof key);
        if (!b64) { fprintf(stderr, "oom\n"); return 1; }

        // SECURITY: Output key to stdout for clipboard copy
        // The GUI or user can copy it to clipboard directly
        // DO NOT save to file automatically (user can redirect output if needed)
        printf("%s\n", b64);
        fprintf(stderr, "Room key generated successfully.\n");
        fprintf(stderr, "IMPORTANT: Copy the key above to clipboard and share it securely.\n");
        fprintf(stderr, "           The key is NOT saved to disk for security reasons.\n");
        free(b64);
        return 0;
    }
    if (strcmp(argv[1], "gen-identity") == 0) {
        if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }

        /* Determine output path */
        char id_path[512];
        if (argc >= 3) {
            strncpy(id_path, argv[2], sizeof(id_path) - 1);
            id_path[sizeof(id_path) - 1] = '\0';
        } else {
            if (identity_default_path(id_path, sizeof(id_path)) != 0) {
                fprintf(stderr, "Cannot determine default identity path\n");
                return 1;
            }
        }

        if (identity_generate(id_path) != 0) {
            fprintf(stderr, "Failed to generate identity key at %s\n", id_path);
            return 1;
        }

        /* Load and print public key fingerprint */
        uint8_t pk[IDENTITY_PK_BYTES];
        if (identity_load_pk(id_path, pk) == 0) {
            char fp[IDENTITY_FINGERPRINT_LEN];
            identity_pk_fingerprint(pk, fp);
            fprintf(stderr, "Identity key generated: %s\n", id_path);
            fprintf(stderr, "Fingerprint: %s\n", fp);

            /* Output public key to stdout (for clipboard/sharing) */
            char pk_b64[128];
            sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING);
            printf("%s\n", pk_b64);
        }
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
        const char *keyfile = NULL;
        const char *identity_file = NULL;
        int no_sign = 0;
        int create_mode = 0;
        int join_mode = 0;
        uint16_t port = 0;
        int using_deprecated_key_arg = 0;

        // Parse command line arguments
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
            else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
            else if (strcmp(argv[i], "--room") == 0 && i + 1 < argc) room = argv[++i];
            else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) keyfile = argv[++i];
            else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                b64 = argv[++i];
                using_deprecated_key_arg = 1;
            }
            else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
            else if (strcmp(argv[i], "--identity-file") == 0 && i + 1 < argc) identity_file = argv[++i];
            else if (strcmp(argv[i], "--no-sign") == 0) no_sign = 1;
            else if (strcmp(argv[i], "--create") == 0) create_mode = 1;
            else if (strcmp(argv[i], "--join") == 0) join_mode = 1;
        }

        if (!host || !port || !room) { print_usage(argv[0]); return 1; }
        if (!name) name = "anon";
        if (strlen(room) > MAX_ROOM - 1) { fprintf(stderr, "room too long (max %d)\n", MAX_ROOM - 1); return 1; }
        if (strlen(name) > MAX_NAME - 1) { fprintf(stderr, "name too long (max %d)\n", MAX_NAME - 1); return 1; }

        uint8_t key[CRYPTO_KEYBYTES];
        memset(key, 0, sizeof(key));

        if (create_mode) {
            // Auto-generate room key
            if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
            randombytes_buf(key, sizeof key);
            char *b64_key = b64_encode(key, sizeof key);
            fprintf(stderr, "[create] Room key generated: %s\n", b64_key);
            free(b64_key);
        } else if (join_mode) {
            // Key stays zeroed — run_client will do ECDH exchange
            fprintf(stderr, "[join] Will request room key via ECDH exchange\n");
        } else {
            // Buffer for key storage
            static char key_buffer[512];
            memset(key_buffer, 0, sizeof(key_buffer));

            // Priority 1: Read from --key-file
            if (keyfile) {
                if (read_key_from_file(keyfile, key_buffer, sizeof(key_buffer)) != 0) {
                    return 1;
                }
                b64 = key_buffer;
            }
            // Priority 2: Read from stdin (interactive or piped)
            else if (!b64) {
                int is_interactive = isatty(fileno(stdin));
                if (read_key_from_stdin(key_buffer, sizeof(key_buffer), is_interactive) != 0) {
                    return 1;
                }
                b64 = key_buffer;
            }
            // Priority 3: --key argument (deprecated, with security warning)
            else if (using_deprecated_key_arg) {
                fprintf(stderr, "\n");
                fprintf(stderr, "WARNING: Using --key argument is insecure!\n");
                fprintf(stderr, "         The key is visible in process lists (ps, top, Task Manager).\n");
                fprintf(stderr, "         Use --key-file or stdin instead.\n");
                fprintf(stderr, "\n");
            }

            // Decode and validate key
            int klen = b64_decode(b64, key, sizeof key);
            if (klen != CRYPTO_KEYBYTES) {
                fprintf(stderr, "invalid key (must be 32 bytes base64 urlsafe)\n");
                sodium_memzero(key_buffer, sizeof(key_buffer));
                return 1;
            }

            // Clear key buffer before running client
            sodium_memzero(key_buffer, sizeof(key_buffer));
        }

        // Load identity for signing (optional)
        uint8_t id_pk[IDENTITY_PK_BYTES], id_sk[IDENTITY_SK_BYTES];
        int has_identity = 0;
        if (!no_sign) {
            char id_path[512];
            if (identity_file) {
                strncpy(id_path, identity_file, sizeof(id_path) - 1);
                id_path[sizeof(id_path) - 1] = '\0';
            } else {
                identity_default_path(id_path, sizeof(id_path));
            }
            if (identity_load(id_path, id_pk, id_sk) == 0) {
                has_identity = 1;
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(id_pk, fp);
                fprintf(stderr, "Identity loaded: %s\n", fp);
            }
        }

        // Run client
        run_client(host, port, room, name, key,
                   has_identity ? id_pk : NULL,
                   has_identity ? id_sk : NULL,
                   join_mode);

        // Clear sensitive data from memory
        sodium_memzero(key, sizeof(key));
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
        return 0;
    }
    print_usage(argv[0]);
    return 1;
}