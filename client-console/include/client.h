#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>      // Добавлено для getaddrinfo, freeaddrinfo
#include <unistd.h>     // Добавлено для close
#endif

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

// Function declarations
int send_ciphertext(sock_t s, const char *room, const char *name, const uint8_t *key,
                   const uint8_t *plaintext, size_t plen);
int recv_and_decrypt(sock_t s, const char *room, const uint8_t *key, const char *myname);
void run_client(const char *host, uint16_t port, const char *room, const char *name, const uint8_t key[32]);
void print_local_message(const char *name, const char *msg);

#endif