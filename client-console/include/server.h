#ifndef SERVER_H
#define SERVER_H

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
#include <netinet/in.h>
#include <unistd.h>     // Добавлено для close
#endif

// Function declaration
void run_server(uint16_t port);

#endif