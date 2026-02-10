/**
 * @file key-exchange.c
 * @author Evgeny Shchuchkin (shchuchkin-pkims@yandex.ru)
 * @brief Secure key exchange using libsodium (Curve25519) for F.E.A.R. project messenger
 * @version 0.2
 * @date 2025-10-16
 *
 * @copyright Copyright (c) 2025
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// ANSI color codes for better terminal UI
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RED     "\033[31m"
#define COLOR_CYAN    "\033[36m"

// Box drawing characters (ASCII-compatible for Windows)
#ifdef _WIN32
#define BOX_TOP_LEFT     "+"
#define BOX_TOP_RIGHT    "+"
#define BOX_BOTTOM_LEFT  "+"
#define BOX_BOTTOM_RIGHT "+"
#define BOX_HORIZONTAL   "="
#define BOX_VERTICAL     "|"
#define BOX_SEPARATOR    "-"
#define ICON_SUCCESS     "[OK]"
#define ICON_ERROR       "[X]"
#define ICON_WARNING     "[!]"
#define ICON_INFO        "[i]"
#else
#define BOX_TOP_LEFT     "╔"
#define BOX_TOP_RIGHT    "╗"
#define BOX_BOTTOM_LEFT  "╚"
#define BOX_BOTTOM_RIGHT "╝"
#define BOX_HORIZONTAL   "═"
#define BOX_VERTICAL     "║"
#define BOX_SEPARATOR    "━"
#define ICON_SUCCESS     "✓"
#define ICON_ERROR       "✗"
#define ICON_WARNING     "⚠"
#define ICON_INFO        "ℹ"
#endif

// Key storage structure
typedef struct {
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    bool keys_generated;
} KeyPair;

/**
 * @brief Function prototypes for key exchange utility
 *
 * This utility implements secure key exchange using Curve25519 elliptic curve
 * cryptography (via libsodium). It provides both interactive CLI and command-line
 * modes for generating keypairs and exchanging encrypted messages.
 */

/* UI Functions */
void clear_screen(void);
void print_header(void);
void print_separator(void);

/* Utility Functions */
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex);
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t expected_len);
void secure_input(char *buffer, size_t size);

/* Key Management Functions */
void generate_keypair_mode(KeyPair *kp);
void encrypt_message_mode(KeyPair *kp);
void decrypt_message_mode(KeyPair *kp);
void export_keys_mode(KeyPair *kp);
void import_keys_mode(KeyPair *kp);

/* Menu */
void print_menu(void);

/**
 * @brief Clear terminal screen (cross-platform)
 *
 * Uses system("cls") on Windows, ANSI escape codes on Unix-like systems
 */
void clear_screen(void) {
    #ifdef _WIN32
    system("cls");
    #else
    printf("\033[2J\033[H");
    #endif
}

/**
 * @brief Print horizontal separator line for UI formatting
 */
void print_separator(void) {
    printf(COLOR_BLUE);
    for (int i = 0; i < 50; i++) printf(BOX_SEPARATOR);
    printf(COLOR_RESET "\n");
}

/**
 * @brief Print application header with ASCII box drawing
 *
 * Creates a centered title box using platform-specific box drawing characters.
 * Uses UTF-8 box drawing on Unix, ASCII fallback on Windows.
 */
void print_header(void) {
    const char *title = "F.E.A.R. Secure Key Exchange";
    int box_width = 50;
    int title_len = strlen(title);
    int padding = (box_width - title_len - 2) / 2; // -2 for side borders

    // Top border
    printf(COLOR_BOLD COLOR_CYAN);
    printf("%s", BOX_TOP_LEFT);
    for (int i = 0; i < box_width - 2; i++) printf(BOX_HORIZONTAL);
    printf("%s\n", BOX_TOP_RIGHT);

    // Title line with centering
    printf("%s", BOX_VERTICAL);
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", title);
    for (int i = 0; i < box_width - title_len - padding - 2; i++) printf(" ");
    printf("%s\n", BOX_VERTICAL);

    // Bottom border
    printf("%s", BOX_BOTTOM_LEFT);
    for (int i = 0; i < box_width - 2; i++) printf(BOX_HORIZONTAL);
    printf("%s\n", BOX_BOTTOM_RIGHT);
    printf(COLOR_RESET);
}


/**
 * @brief Convert binary data to hexadecimal string
 *
 * Converts raw bytes to lowercase hexadecimal representation.
 * Output buffer must be at least (bytes_len * 2 + 1) bytes.
 *
 * @param bytes Input binary data
 * @param bytes_len Length of input data
 * @param hex Output buffer for hex string (null-terminated)
 *
 * @example
 * unsigned char data[] = {0x12, 0xAB};
 * char hex[5];
 * bytes_to_hex(data, 2, hex);  // hex = "12ab"
 */
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex) {
    static const char hex_table[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes_len; i++) {
    hex[i * 2] = hex_table[(bytes[i] >> 4) & 0xF];
    hex[i * 2 + 1] = hex_table[bytes[i] & 0xF];
    }
    hex[bytes_len * 2] = '\0';
}

/**
 * @brief Convert hexadecimal string to binary data
 *
 * Parses hex string and converts to raw bytes. Validates input length
 * and hex character validity.
 *
 * @param hex Input hex string (case-insensitive)
 * @param bytes Output buffer for binary data
 * @param expected_len Expected number of output bytes
 * @return true on success, false if hex string is invalid or wrong length
 *
 * @note Hex string must be exactly (expected_len * 2) characters long
 */
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t expected_len) {
    size_t len = strlen(hex);
    if (len != expected_len * 2) return false;
    for (size_t i = 0; i < expected_len; i++) {
    unsigned int value;
    if (sscanf(hex + i * 2, "%2x", &value) != 1) return false;
    bytes[i] = (unsigned char)value;
    }
    return true;
}

/**
 * @brief Securely read line from stdin
 *
 * Reads user input with automatic newline trimming.
 * Handles EOF gracefully by returning empty string.
 *
 * @param buffer Output buffer for input string
 * @param size Maximum buffer size (including null terminator)
 *
 * @note Removes trailing newline if present
 * @note Buffer is always null-terminated
 */
void secure_input(char *buffer, size_t size) {
    if (!fgets(buffer, size, stdin)) {
    buffer[0] = '\0';
    return;
    }
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
}

/**
 * @brief Generate new Curve25519 keypair
 *
 * Creates a new public/private keypair using libsodium's crypto_box_keypair().
 * The keypair uses Curve25519 elliptic curve cryptography (X25519 key exchange).
 *
 * CRYPTOGRAPHIC DETAILS:
 * - Algorithm: Curve25519 (elliptic curve Diffie-Hellman)
 * - Public key: 32 bytes (256 bits)
 * - Secret key: 32 bytes (256 bits)
 * - Security level: ~128-bit (quantum-resistant: ~85-bit)
 *
 * SECURITY NOTES:
 * - Secret key MUST be kept confidential
 * - Public key can be freely shared
 * - Keys are displayed in hexadecimal format for easy copying
 * - This function does NOT save keys to disk (user must export manually)
 *
 * @param kp Pointer to KeyPair structure to populate
 *
 * @post kp->keys_generated is set to true
 * @post kp->public_key and kp->secret_key contain valid key material
 */
void generate_keypair_mode(KeyPair *kp) {
    clear_screen();
    print_header();
    printf(COLOR_BOLD COLOR_GREEN "\n[1] GENERATE NEW KEY PAIR\n\n" COLOR_RESET);


    crypto_box_keypair(kp->public_key, kp->secret_key);
    kp->keys_generated = true;


    char public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char secret_hex[crypto_box_SECRETKEYBYTES * 2 + 1];


    bytes_to_hex(kp->public_key, crypto_box_PUBLICKEYBYTES, public_hex);
    bytes_to_hex(kp->secret_key, crypto_box_SECRETKEYBYTES, secret_hex);


    printf(COLOR_CYAN "Your keys were generated successfully!\n" COLOR_RESET);
    print_separator();
    printf(COLOR_BOLD "PUBLIC KEY:\n" COLOR_RESET "%s\n", public_hex);
    printf(COLOR_BOLD "SECRET KEY:\n" COLOR_RESET "%s\n", secret_hex);
    print_separator();
}

/**
 * @brief Encrypt message using authenticated encryption
 *
 * Encrypts a plaintext message for a specific recipient using their public key.
 * Uses libsodium's crypto_box_easy() which implements authenticated encryption
 * with Curve25519, XSalsa20, and Poly1305.
 *
 * ENCRYPTION PROTOCOL:
 * 1. User enters recipient's public key (hex format)
 * 2. User enters plaintext message
 * 3. Random nonce is generated (24 bytes)
 * 4. Message is encrypted with: crypto_box_easy(message, nonce, recipient_pk, sender_sk)
 * 5. Output format: [nonce (48 hex chars)][ciphertext (variable)]
 *
 * CRYPTOGRAPHIC DETAILS:
 * - Key agreement: X25519 (ECDH on Curve25519)
 * - Cipher: XSalsa20 stream cipher
 * - Authentication: Poly1305 MAC (16-byte tag)
 * - Nonce: 24 bytes (randomly generated per message)
 *
 * SECURITY GUARANTEES:
 * - Confidentiality: Only recipient can decrypt (has matching secret key)
 * - Authentication: Recipient knows message is from sender (sender's secret key used)
 * - Integrity: Any tampering detected by Poly1305 MAC
 *
 * @param kp Pointer to sender's KeyPair (must have keys_generated = true)
 *
 * @warning Requires keypair to be generated or imported first
 * @note Nonce is prepended to ciphertext for easy decryption
 */
void encrypt_message_mode(KeyPair *kp) {
    clear_screen();
    print_header();
    printf(COLOR_BOLD COLOR_GREEN "\n[2] ENCRYPT MESSAGE\n\n" COLOR_RESET);


    if (!kp->keys_generated) {
    printf(COLOR_RED "%s Error: No keys generated! Please generate or import keys first.\n" COLOR_RESET, ICON_ERROR);
    return;
    }


    char recipient_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];


    printf("Enter recipient's PUBLIC KEY (hex): ");
    secure_input(recipient_hex, sizeof(recipient_hex));


    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);


    if (!hex_to_bytes(recipient_hex, recipient_pk, crypto_box_PUBLICKEYBYTES)) {
    printf(COLOR_RED "%s Error: Invalid public key format!\n" COLOR_RESET, ICON_ERROR);
    return;
    }


    char message[1024];
    printf("Enter message to encrypt: ");
    secure_input(message, sizeof(message));


    if (strlen(message) == 0) {
    printf(COLOR_RED "[X] Error: Message cannot be empty!\n" COLOR_RESET);
    return;
    }


    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));


    size_t ciphertext_len = crypto_box_MACBYTES + strlen(message);
    unsigned char *ciphertext = malloc(ciphertext_len);


    crypto_box_easy(ciphertext, (const unsigned char *)message, strlen(message), nonce, recipient_pk, kp->secret_key);


    char hex_nonce[crypto_box_NONCEBYTES * 2 + 1];
    char hex_cipher[ciphertext_len * 2 + 1];


    bytes_to_hex(nonce, crypto_box_NONCEBYTES, hex_nonce);
    bytes_to_hex(ciphertext, ciphertext_len, hex_cipher);

    // Get your public key to share
    char your_public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    bytes_to_hex(kp->public_key, crypto_box_PUBLICKEYBYTES, your_public_hex);

    printf(COLOR_GREEN "\n%s Message encrypted successfully!\n\n" COLOR_RESET, ICON_SUCCESS);
    print_separator();
    printf(COLOR_BOLD "Share Your PUBLIC KEY with recipient (hex):\n" COLOR_RESET);
    printf(COLOR_CYAN "%s\n\n" COLOR_RESET, your_public_hex);
    printf(COLOR_BOLD "ENCRYPTED MESSAGE (hex):\n" COLOR_RESET);
    printf(COLOR_YELLOW "%s%s\n" COLOR_RESET, hex_nonce, hex_cipher);
    print_separator();


free(ciphertext);
}

// Decrypt message
/**
 * @brief Decrypt authenticated encrypted message
 *
 * Decrypts a ciphertext that was encrypted with encrypt_message_mode().
 * Uses crypto_box_open_easy() to verify authentication and decrypt.
 *
 * DECRYPTION PROTOCOL:
 * 1. User enters sender's public key (hex format)
 * 2. User enters encrypted message (hex: nonce + ciphertext)
 * 3. Nonce extracted from first 48 hex characters (24 bytes)
 * 4. Message decrypted with: crypto_box_open_easy(ciphertext, nonce, sender_pk, recipient_sk)
 * 5. Plaintext displayed if decryption succeeds
 *
 * SECURITY FEATURES:
 * - Verifies message came from claimed sender (authentication)
 * - Detects any tampering via Poly1305 MAC verification
 * - Returns error if MAC check fails (message modified or wrong keys)
 *
 * @param kp Pointer to recipient's KeyPair (must have keys_generated = true)
 *
 * @warning Requires keypair to be generated or imported first
 * @warning Will fail if ciphertext was modified or wrong sender key provided
 */
void decrypt_message_mode(KeyPair *kp) {
    clear_screen();
    print_header();
    printf(COLOR_BOLD COLOR_GREEN "\n[3] DECRYPT MESSAGE\n\n" COLOR_RESET);

    if (!kp->keys_generated) {
        printf(COLOR_RED "%s Error: No keys generated! Please generate or import keys first.\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    /* Show your public key to share with sender */
    char your_public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    bytes_to_hex(kp->public_key, crypto_box_PUBLICKEYBYTES, your_public_hex);
    printf(COLOR_BOLD "Your public key to share: " COLOR_RESET);
    printf(COLOR_CYAN "%s\n\n" COLOR_RESET, your_public_hex);

    // Get sender's public key
    char sender_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];

    printf("Enter sender's PUBLIC KEY (hex): ");
    secure_input(sender_hex, sizeof(sender_hex));

    // Clear input buffer
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);

    if (!hex_to_bytes(sender_hex, sender_pk, crypto_box_PUBLICKEYBYTES)) {
        printf(COLOR_RED "\n%s Error: Invalid public key format!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    // Get ciphertext
    char *hex_ciphertext = malloc(4096);
    if (!hex_ciphertext) {
        printf(COLOR_RED "\n%s Error: Memory allocation failed!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    printf("\nEnter ENCRYPTED MESSAGE (hex): ");
    secure_input(hex_ciphertext, 4096);

    size_t hex_len = strlen(hex_ciphertext);
    size_t min_len = (crypto_box_NONCEBYTES + crypto_box_MACBYTES) * 2;
    if (hex_len < min_len) {
        printf(COLOR_RED "\n%s Error: Ciphertext too short!\n" COLOR_RESET, ICON_ERROR);
        printf(COLOR_YELLOW "   Expected at least %zu hex characters, but got %zu\n" COLOR_RESET, min_len, hex_len);
        printf(COLOR_CYAN "   Hint: Make sure you paste the complete encrypted message\n" COLOR_RESET);
        free(hex_ciphertext);
        return;
    }

    // Convert hex to bytes
    size_t ciphertext_len = hex_len / 2;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        printf(COLOR_RED "\n%s Error: Memory allocation failed!\n" COLOR_RESET, ICON_ERROR);
        free(hex_ciphertext);
        return;
    }

    if (!hex_to_bytes(hex_ciphertext, ciphertext, ciphertext_len)) {
        printf(COLOR_RED "\n%s Error: Invalid ciphertext format!\n" COLOR_RESET, ICON_ERROR);
        free(hex_ciphertext);
        free(ciphertext);
        return;
    }

    // Extract nonce
    unsigned char nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, ciphertext, crypto_box_NONCEBYTES);

    // Prepare decrypted message buffer
    size_t message_len = ciphertext_len - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
    unsigned char *decrypted = malloc(message_len + 1);
    if (!decrypted) {
        printf(COLOR_RED "\n%s Error: Memory allocation failed!\n" COLOR_RESET, ICON_ERROR);
        free(hex_ciphertext);
        free(ciphertext);
        return;
    }

    // Decrypt the message
    if (crypto_box_open_easy(decrypted,
                            ciphertext + crypto_box_NONCEBYTES,
                            ciphertext_len - crypto_box_NONCEBYTES,
                            nonce, sender_pk, kp->secret_key) != 0) {
        printf(COLOR_RED "\n%s Error: Decryption failed! Wrong key or corrupted message.\n" COLOR_RESET, ICON_ERROR);
        free(hex_ciphertext);
        free(ciphertext);
        free(decrypted);
        return;
    }

    // Null-terminate the decrypted message
    decrypted[message_len] = '\0';

    printf(COLOR_GREEN "\n%s Message decrypted successfully!\n\n" COLOR_RESET, ICON_SUCCESS);
    print_separator();
    printf(COLOR_BOLD "DECRYPTED MESSAGE:\n" COLOR_RESET);
    printf(COLOR_YELLOW "%s\n" COLOR_RESET, decrypted);
    print_separator();

    // Clean up
    sodium_memzero(decrypted, message_len);
    sodium_memzero(ciphertext, ciphertext_len);
    free(hex_ciphertext);
    free(ciphertext);
    free(decrypted);
}

// Export keys to file
void export_keys_mode(KeyPair *kp) {
    clear_screen();
    print_header();
    printf(COLOR_BOLD COLOR_GREEN "\n[4] EXPORT KEYS TO FILE\n\n" COLOR_RESET);

    if (!kp->keys_generated) {
        printf(COLOR_RED "%s Error: No keys generated! Please generate or import keys first.\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    char filename[256];
    printf("Enter filename to save keys (e.g., my_keys.txt): ");
    secure_input(filename, sizeof(filename));

    FILE *file = fopen(filename, "w");
    if (!file) {
        printf(COLOR_RED "\n%s Error: Cannot create file!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    char public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char secret_hex[crypto_box_SECRETKEYBYTES * 2 + 1];

    bytes_to_hex(kp->public_key, crypto_box_PUBLICKEYBYTES, public_hex);
    bytes_to_hex(kp->secret_key, crypto_box_SECRETKEYBYTES, secret_hex);

    fprintf(file, "# F.E.A.R. Key Exchange Keys\n");
    fprintf(file, "# WARNING: Keep this file secure!\n\n");
    fprintf(file, "PUBLIC_KEY=%s\n", public_hex);
    fprintf(file, "SECRET_KEY=%s\n", secret_hex);

    fclose(file);

    printf(COLOR_GREEN "\n%s Keys exported successfully to '%s'!\n" COLOR_RESET, ICON_SUCCESS, filename);
    printf(COLOR_YELLOW "%s Keep this file secure and never share your secret key!\n" COLOR_RESET, ICON_WARNING);
}

// Import keys from file
void import_keys_mode(KeyPair *kp) {
    clear_screen();
    print_header();
    printf(COLOR_BOLD COLOR_GREEN "\n[5] IMPORT KEYS FROM FILE\n\n" COLOR_RESET);

    char filename[256];
    printf("Enter filename to load keys from: ");
    secure_input(filename, sizeof(filename));

    FILE *file = fopen(filename, "r");
    if (!file) {
        printf(COLOR_RED "\n%s Error: Cannot open file!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    char line[256];
    char public_hex[crypto_box_PUBLICKEYBYTES * 2 + 1] = {0};
    char secret_hex[crypto_box_SECRETKEYBYTES * 2 + 1] = {0};

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "PUBLIC_KEY=", 11) == 0) {
            strncpy(public_hex, line + 11, crypto_box_PUBLICKEYBYTES * 2);
            public_hex[crypto_box_PUBLICKEYBYTES * 2] = '\0';
        } else if (strncmp(line, "SECRET_KEY=", 11) == 0) {
            strncpy(secret_hex, line + 11, crypto_box_SECRETKEYBYTES * 2);
            secret_hex[crypto_box_SECRETKEYBYTES * 2] = '\0';
        }
    }

    fclose(file);

    if (strlen(public_hex) != crypto_box_PUBLICKEYBYTES * 2 ||
        strlen(secret_hex) != crypto_box_SECRETKEYBYTES * 2) {
        printf(COLOR_RED "\n%s Error: Invalid key file format!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    if (!hex_to_bytes(public_hex, kp->public_key, crypto_box_PUBLICKEYBYTES) ||
        !hex_to_bytes(secret_hex, kp->secret_key, crypto_box_SECRETKEYBYTES)) {
        printf(COLOR_RED "\n%s Error: Invalid key data in file!\n" COLOR_RESET, ICON_ERROR);
        return;
    }

    kp->keys_generated = true;

    printf(COLOR_GREEN "\n%s Keys imported successfully from '%s'!\n" COLOR_RESET, ICON_SUCCESS, filename);
    printf(COLOR_CYAN "\n%s Your keys are now loaded and ready to use.\n" COLOR_RESET, ICON_INFO);
}

// Print main menu
void print_menu(void) {
    printf("\n");
    print_separator();
    printf(COLOR_BOLD "MAIN MENU:\n" COLOR_RESET);
    printf("  [1] Generate new key pair\n");
    printf("  [2] Encrypt message\n");
    printf("  [3] Decrypt message\n");
    printf("  [4] Export keys to file\n");
    printf("  [5] Import keys from file\n");
    printf("  [0] Exit\n");
    print_separator();
    printf("Your choice: ");
}

int main(void) {
#ifdef _WIN32
    // Enable UTF-8 support for Windows Console (Windows 10+)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Enable ANSI color codes support
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif

    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Fatal error: Failed to initialize libsodium!\n");
        return 1;
    }

    KeyPair kp = {0};
    kp.keys_generated = false;

    int choice;
    char input[10];

    clear_screen();
    print_header();
    printf("\n" COLOR_GREEN "%s libsodium initialized successfully!\n" COLOR_RESET, ICON_SUCCESS);
    printf(COLOR_CYAN "%s This utility uses Curve25519 for secure key exchange.\n" COLOR_RESET, ICON_INFO);

    do {
        print_menu();
        secure_input(input, sizeof(input));
        choice = atoi(input);

        switch (choice) {
            case 1:
                generate_keypair_mode(&kp);
                break;
            case 2:
                encrypt_message_mode(&kp);
                break;
            case 3:
                decrypt_message_mode(&kp);
                break;
            case 4:
                export_keys_mode(&kp);
                break;
            case 5:
                import_keys_mode(&kp);
                break;
            case 0:
                clear_screen();
                print_header();
                printf("\n" COLOR_GREEN "Goodbye! Stay secure.\n" COLOR_RESET);
                break;
            default:
                printf(COLOR_RED "\n%s Invalid choice. Please try again.\n" COLOR_RESET, ICON_ERROR);
        }

        if (choice != 0) {
            printf("\n" COLOR_CYAN "Press Enter to continue..." COLOR_RESET);
            char dummy[2];
            secure_input(dummy, sizeof(dummy));
        }

    } while (choice != 0);

    // Clear sensitive data from memory
    if (kp.keys_generated) {
        sodium_memzero(kp.secret_key, sizeof(kp.secret_key));
    }

    return 0;
}
