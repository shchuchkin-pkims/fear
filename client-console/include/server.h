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
/** Срок хранения по умолчанию: тридцать суток.
 *
 * Неполученное письмо ценно ровно до возвращения адресата. Месяц покрывает
 * отпуск, болезнь и смену телефона; больше - и ретранслятор из трубы
 * превращается в архив, а архив имеет смысл красть. */
#define INBOX_TTL_DEFAULT (30 * 24 * 3600)

void run_server(uint16_t port);

/** То же, но со сроком хранения почты; 0 - не хранить ничего. */
void run_server_opts(uint16_t port, int64_t inbox_ttl);

#endif