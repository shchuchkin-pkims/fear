/**
 * @file key-exchange.c
 * @author Evgeny Shchuchkin (shchuchkin-pkims@yandex.ru)
 * @brief Diffie-Hellman algorithm for secret key exchange between 2 persons for F.E.A.R. project messager
 * @version 0.1
 * @date 2025-08-22
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>

// Function to check if a number is prime
bool is_prime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}

// Generate a large prime number
int generate_large_prime(int min, int max) {
    int candidate;
    do {
        candidate = min + rand() % (max - min + 1);
        // Ensure the number is odd (except 2)
        if (candidate % 2 == 0 && candidate != 2) candidate++;
    } while (!is_prime(candidate));
    return candidate;
}

// Find a primitive root modulo p
int find_primitive_root(int p) {
    if (p == 2) return 1;
    
    int phi = p - 1;
    int factors[100];
    int factor_count = 0;
    
    int temp = phi;
    for (int i = 2; i <= temp; i++) {
        while (temp % i == 0) {
            factors[factor_count++] = i;
            temp /= i;
        }
    }
    
    for (int r = 2; r <= p; r++) {
        bool is_primitive = true;
        for (int i = 0; i < factor_count; i++) {
            if (i == 0 || factors[i] != factors[i-1]) {
                int exponent = phi / factors[i];
                long long result = 1;
                long long base = r;
                
                // Fast exponentiation modulo
                while (exponent > 0) {
                    if (exponent % 2 == 1) {
                        result = (result * base) % p;
                    }
                    base = (base * base) % p;
                    exponent /= 2;
                }
                
                if (result == 1) {
                    is_primitive = false;
                    break;
                }
            }
        }
        if (is_primitive) {
            return r;
        }
    }
    return 2; // Return 2 as a simple option
}

// Fast exponentiation modulo
long long mod_pow(long long base, long long exponent, long long mod) {
    long long result = 1;
    base = base % mod;
    
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % mod;
        }
        exponent = exponent >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Generate a random number
int generate_random_number(int min, int max) {
    return min + rand() % (max - min + 1);
}

// XOR encryption/decryption function
void xor_encrypt_decrypt(const char *input, char *output, long long key, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ (char)(key >> (8 * (i % 8)));
    }
    output[length] = '\0';
}

// Convert hex to binary
void hex_to_binary(const char *hex, char *binary, int length) {
    for (int i = 0; i < length; i += 2) {
        char hex_byte[3] = {hex[i], hex[i+1], '\0'};
        binary[i/2] = (char)strtol(hex_byte, NULL, 16);
    }
}

// Convert binary to hex
void binary_to_hex(const char *binary, char *hex, int length) {
    for (int i = 0; i < length; i++) {
        sprintf(hex + i*2, "%02x", (unsigned char)binary[i]);
    }
    hex[length*2] = '\0';
}

// Sender mode
void sender_mode() {
    printf("\n=== SENDER MODE ===\n\n");
    
    srand(time(NULL));
    
    // Automatically generate a large prime number
    int p = generate_large_prime(10000, 50000);
    int g = find_primitive_root(p);
    
    printf("Generated parameters:\n");
    printf("- Prime number (p): %d\n", p);
    printf("- Primitive root (g): %d\n", g);
    
    // Generate secret key
    int private_key = generate_random_number(2, p-2);
    printf("Your secret key: %d (keep secret!)\n", private_key);
    
    // Calculate public key
    long long public_key = mod_pow(g, private_key, p);
    printf("Your public key: %lld\n", public_key);
    
    // Get the key to transfer
    char original_key[100];
    printf("\nEnter the key you want to transfer: ");
    fgets(original_key, sizeof(original_key), stdin);
    original_key[strcspn(original_key, "\n")] = '\0';
    
    printf("Key to transfer: '%s'\n", original_key);
    printf("Key length: %zu characters\n", strlen(original_key));
    
    // Get friend's public key
    long long friend_public_key;
    printf("\nEnter your friend's public key: ");
    scanf("%lld", &friend_public_key);
    getchar();
    
    // Calculate shared secret
    long long shared_secret = mod_pow(friend_public_key, private_key, p);
    printf("Shared secret key: %lld\n", shared_secret);
    
    // Encrypt the key
    char encrypted_key[100];
    xor_encrypt_decrypt(original_key, encrypted_key, shared_secret, strlen(original_key));
    
    // Convert to hex for easier transfer
    char hex_encrypted[200];
    binary_to_hex(encrypted_key, hex_encrypted, strlen(original_key));
    
    printf("\n=== DATA TO SEND TO YOUR FRIEND ===\n\n");
    printf("1. Prime number (p): %d\n", p);
    printf("2. Primitive root (g): %d\n", g);
    printf("3. Your public key: %lld\n", public_key);
    printf("4. Encrypted key (hex): %s\n", hex_encrypted);
    printf("\nSend this data to your friend!\n");
}

// Public key generation mode
void get_public_key_mode() {
    printf("\n=== PUBLIC KEY GENERATION MODE ===\n\n");
    
    srand(time(NULL));
    
    // Get parameters from sender
    int p, g;
    printf("Enter prime number (p) from sender: ");
    scanf("%d", &p);
    getchar();
    
    printf("Enter primitive root (g) from sender: ");
    scanf("%d", &g);
    getchar();
    
    // Generate own secret key
    int private_key = generate_random_number(2, p-2);
    printf("Your secret key: %d (keep secret!)\n", private_key);
    
    // Calculate own public key
    long long public_key = mod_pow(g, private_key, p);
    printf("\n=== YOUR PUBLIC KEY TO SEND ===\n\n");
    printf("%lld\n\n", public_key);
    printf("Send this key to the sender!\n");
    
    // Save parameters for future use
    printf("\nRemember these parameters for decryption:\n");
    printf("- p: %d\n", p);
    printf("- g: %d\n", g);
    printf("- Your secret key: %d\n", private_key);
    printf("- Sender's public key: (to be received later)\n");
}

// Receiver mode
void receiver_mode() {
    printf("\n=== RECEIVER MODE ===\n\n");
    
    // Get parameters from sender
    int p, g;
    long long sender_public_key;
    char hex_encrypted[200];
    
    printf("Enter prime number (p): ");
    scanf("%d", &p);
    getchar();
    
    printf("Enter primitive root (g): ");
    scanf("%d", &g);
    getchar();
    
    printf("Enter sender's public key: ");
    scanf("%lld", &sender_public_key);
    getchar();
    
    printf("Enter encrypted key (hex): ");
    scanf("%s", hex_encrypted);
    getchar();
    
    // Enter own secret key
    int private_key;
    printf("Enter your secret key: ");
    scanf("%d", &private_key);
    getchar();
    
    // Calculate shared secret
    long long shared_secret = mod_pow(sender_public_key, private_key, p);
    printf("Shared secret key: %lld\n", shared_secret);
    
    // Convert hex back to binary
    int encrypted_length = strlen(hex_encrypted) / 2;
    char encrypted_key[100];
    hex_to_binary(hex_encrypted, encrypted_key, strlen(hex_encrypted));
    
    // Decrypt the key
    char decrypted_key[100];
    xor_encrypt_decrypt(encrypted_key, decrypted_key, shared_secret, encrypted_length);
    decrypted_key[encrypted_length] = '\0';
    
    printf("\n=== RESULT ===\n\n");
    printf("Decrypted key: '%s'\n", decrypted_key);
    printf("Key length: %zu characters\n", strlen(decrypted_key));
}

int main() {
    printf("=== DIFFIE-HELLMAN KEY EXCHANGE PROGRAM ===\n\n");
    
    srand(time(NULL));
    
    int choice;
    do {
        printf("Select mode:\n");
        printf("1 - I am sender (want to send a key)\n");
        printf("2 - Generate public key (for receiver)\n");
        printf("3 - I am receiver (want to decrypt a key)\n");
        printf("0 - Exit\n");
        printf("Your choice: ");
        scanf("%d", &choice);
        getchar();
        
        switch (choice) {
            case 1:
                sender_mode();
                break;
            case 2:
                get_public_key_mode();
                break;
            case 3:
                receiver_mode();
                break;
            case 0:
                printf("Exiting program.\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
        
        if (choice != 0) {
            printf("\nPress Enter to continue...");
            getchar();
        }
        
    } while (choice != 0);
    
    return 0;
}