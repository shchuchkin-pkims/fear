#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

void run_client(const char *host, uint16_t port, const char *room, const char *name, const uint8_t key[32]);
void print_local_message(const char *name, const char *msg);

void handle_file_transfer(const char *filename, const uint8_t key[32], 
                         const char *room, const char *name, sock_t s);
void receive_file(const char *filename, size_t total_size, 
                 const uint8_t *data, size_t data_len);
#endif