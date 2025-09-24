#ifndef DH_H
#define DH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool dh_is_prime(int n);
int dh_generate_large_prime(int min, int max);
int dh_find_primitive_root(int p);
long long dh_mod_pow(long long base, long long exponent, long long mod);
int dh_generate_random_number(int min, int max);

void dh_xor_encrypt_decrypt(const char *input, char *output, long long key, int length);
void dh_binary_to_hex(const char *binary, char *hex, int length);
void dh_hex_to_binary(const char *hex, char *binary, int length);

#ifdef __cplusplus
}
#endif

#endif // DH_H
