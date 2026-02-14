/**
 * @file network.c
 * @brief Implementation of network communication utilities
 *
 * Provides platform-independent TCP/IP networking functions for
 * client-server communication in the F.E.A.R. messenger.
 */

#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Establish a TCP connection to a remote host
 *
 * Uses getaddrinfo() for DNS resolution and supports both IPv4 and IPv6.
 * Tries all resolved addresses until successful connection.
 *
 * @param host Hostname or IP address (e.g., "example.com" or "192.168.1.1")
 * @param port Port number in host byte order (e.g., 8888)
 * @return Valid socket descriptor on success
 *
 * @note Exits program on failure (via die())
 * @note On Windows, initializes Winsock2 library
 */
sock_t dial_tcp(const char *host, uint16_t port) {
#ifdef _WIN32
    /* Initialize Winsock2 library (required on Windows) */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* Convert port to string for getaddrinfo */
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);

    /* Prepare hints for address resolution */
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    sock_t s = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */

    /* Resolve hostname to address(es) */
    int e = getaddrinfo(host, portstr, &hints, &res);
    if (e != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));
        exit(1);
    }

    /* Try each address until we successfully connect */
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) {
            continue; /* Try next address */
        }

        if (connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
            break; /* Connection successful */
        }

        close_socket(s);
        s = -1;
    }

    freeaddrinfo(res);

    if (s < 0) {
        die("connect");
    }

    return s;
}

/**
 * @brief Create a listening TCP socket for server mode
 *
 * Creates, binds, and puts a socket into listen state on the specified port.
 * Binds to INADDR_ANY (0.0.0.0) to accept connections on all interfaces.
 *
 * @param port Port number to listen on (host byte order)
 * @return Listening socket descriptor on success
 *
 * @note Sets SO_REUSEADDR to allow rapid server restarts
 * @note Exits program on any failure (via die())
 */
sock_t server_listen(uint16_t port) {
    /* Create TCP socket */
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        die("socket");
    }

    /* Set SO_REUSEADDR to allow quick restart of server */
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    /* Prepare address structure */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; /* Bind to all interfaces */
    addr.sin_port = htons(port);       /* Convert port to network byte order */

    /* Bind socket to address */
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        die("bind");
    }

    /* Put socket into listening mode (allow up to 16 pending connections) */
    if (listen(s, 16) < 0) {
        die("listen");
    }

    return s;
}
