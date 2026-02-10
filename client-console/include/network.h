/**
 * @file network.h
 * @brief Network communication utilities for F.E.A.R. messenger
 *
 * This module provides low-level TCP/IP networking functions for
 * establishing connections and managing sockets across platforms.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

/**
 * @brief Establish a TCP connection to a remote host
 *
 * This function uses getaddrinfo() to resolve the hostname and attempts
 * to connect to the specified host:port combination. It supports both
 * IPv4 and IPv6.
 *
 * @param host Hostname or IP address to connect to
 * @param port Port number (in host byte order)
 * @return Socket descriptor on success, exits on failure
 *
 * @note This function will exit the program if connection fails
 * @note On Windows, this initializes Winsock2 (WSAStartup)
 */
sock_t dial_tcp(const char *host, uint16_t port);

/**
 * @brief Create a listening TCP socket for server mode
 *
 * Creates a socket, binds it to INADDR_ANY on the specified port,
 * and puts it into listening mode.
 *
 * @param port Port number to listen on (in host byte order)
 * @return Listening socket descriptor on success, exits on failure
 *
 * @note Sets SO_REUSEADDR option to allow quick restarts
 * @note Exits program on failure (via die())
 */
sock_t server_listen(uint16_t port);

#endif /* NETWORK_H */
