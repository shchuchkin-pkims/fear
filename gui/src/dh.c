#include "dh.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

bool dh_is_prime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;

    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}

int dh_generate_large_prime(int min, int max) {
    int candidate;
    do {
        candidate = min + rand() % (max - min + 1);
        if (candidate % 2 == 0 && candidate != 2) candidate++;
    } while (!dh_is_prime(candidate));
    return candidate;
}

int dh_find_primitive_root(int p) {
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
    return 2;
}

long long dh_mod_pow(long long base, long long exponent, long long mod) {
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

int dh_generate_random_number(int min, int max) {
    return min + rand() % (max - min + 1);
}

void dh_xor_encrypt_decrypt(const char *input, char *output, long long key, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ (char)(key >> (8 * (i % 8)));
    }
    output[length] = '\0';
}

void dh_binary_to_hex(const char *binary, char *hex, int length) {
    for (int i = 0; i < length; i++) {
        sprintf(hex + i*2, "%02x", (unsigned char)binary[i]);
    }
    hex[length*2] = '\0';
}

void dh_hex_to_binary(const char *hex, char *binary, int length) {
    for (int i = 0; i < length; i += 2) {
        char hex_byte[3] = {hex[i], hex[i+1], '\0'};
        binary[i/2] = (char)strtol(hex_byte, NULL, 16);
    }
}
