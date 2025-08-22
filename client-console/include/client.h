#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

void run_client(const char *host, uint16_t port, const char *room, const char *name, const uint8_t key[32]);
void print_local_message(const char *name, const char *msg);

#endif