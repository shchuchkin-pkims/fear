/**
 * @file stun_net.c
 * @brief Запрос STUN по сети
 *
 * Отделено от разбора намеренно: разбор - чистая работа с байтами, его
 * гоняет тест без всякой сети. Здесь же живут сокеты и платформенные
 * заголовки, которых тесту знать незачем.
 *
 * Главное здесь одно, и его легко упустить: спрашивать надо с того самого
 * сокета, который потом понесёт голос. NAT выдаёт отображение не машине, а
 * паре «внутренний адрес и порт»; узнав адрес на другом сокете, мы сообщим
 * собеседнику отображение, которого для голоса не существует, и он будет
 * стучаться в закрытую дверь. Поэтому функция принимает уже готовый сокет,
 * а не заводит свой.
 */

#include "stun.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef int socklen_t;
#  define STUN_POLL_ERR SOCKET_ERROR
#else
#  include <sys/socket.h>
#  include <sys/select.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <unistd.h>
#  include <errno.h>
#  define STUN_POLL_ERR (-1)
#endif

/* Сколько раз повторить вопрос. UDP теряет пакеты молча, и один
 * потерянный запрос выглядел бы как «сервер не отвечает». */
#define STUN_ATTEMPTS 3

/* Сколько ждать каждого ответа. Полсекунды - примерно вдвое больше, чем
 * обратный путь до любого публичного сервера STUN, и достаточно мало,
 * чтобы три попытки не задержали начало звонка заметно для человека. */
#define STUN_WAIT_MS 500

stun_status_t stun_query_on_socket(int sock,
                                   const char *server_host, uint16_t server_port,
                                   char addr[STUN_MAX_ADDR], uint16_t *port) {
    if (sock < 0 || !server_host || !addr || !port) return STUN_ERR_ARGS;

    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)server_port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server_host, portstr, &hints, &res) != 0 || !res) {
        return STUN_ERR_ARGS;
    }

    stun_status_t result = STUN_ERR_ARGS;

    for (int attempt = 0; attempt < STUN_ATTEMPTS; attempt++) {
        uint8_t req[STUN_HEADER_BYTES];
        uint8_t txid[STUN_TXID_BYTES];
        if (stun_build_request(req, txid) != STUN_OK) break;

        if (sendto(sock, (const char *)req, sizeof req, 0,
                   res->ai_addr, (socklen_t)res->ai_addrlen) < 0) {
            result = STUN_ERR_ARGS;
            continue;
        }

        /* Ждём ответ, попутно пропуская чужие пакеты: сокет тот же, что для
         * голоса, и на него в это время может прилететь что угодно. Чужое
         * отсеет проверка идентификатора запроса. */
        for (;;) {
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET((unsigned)sock, &rf);
            struct timeval tv;
            tv.tv_sec  = STUN_WAIT_MS / 1000;
            tv.tv_usec = (STUN_WAIT_MS % 1000) * 1000;

            int r = select(sock + 1, &rf, NULL, NULL, &tv);
            if (r == STUN_POLL_ERR) {
#ifndef _WIN32
                if (errno == EINTR) continue;
#endif
                result = STUN_ERR_ARGS;
                break;
            }
            if (r == 0) {           /* тишина - попробуем ещё раз */
                result = STUN_ERR_TOO_SHORT;
                break;
            }

            uint8_t buf[1024];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof from;
            int n = (int)recvfrom(sock, (char *)buf, sizeof buf, 0,
                                  (struct sockaddr *)&from, &fromlen);
            if (n <= 0) continue;

            stun_status_t st = stun_parse_response(buf, (size_t)n, txid, addr, port);
            if (st == STUN_OK) {
                freeaddrinfo(res);
                return STUN_OK;
            }
            /* Не наш пакет - ждём дальше в пределах того же окна. Голосовой
             * трафик собеседника, прилетевший раньше ответа, не должен
             * считаться неудачей. */
            if (st == STUN_ERR_TXID || st == STUN_ERR_NOT_STUN) continue;
            result = st;
            break;
        }
    }

    freeaddrinfo(res);
    return result;
}
