/**
 * @file audio_network.c
 * @brief Network utility implementations for F.E.A.R. audio calls
 *
 * Provides platform-independent network helper functions and
 * byte order conversion for the audio protocol.
 */

#include "audio_network.h"
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#endif

/**
 * @brief Convert 64-bit unsigned integer to network byte order (big-endian)
 *
 * On little-endian systems, swaps bytes to big-endian.
 * On big-endian systems, returns value unchanged.
 *
 * @param v Value in host byte order
 * @return Value in network byte order
 */
uint64_t htonll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    /* Swap bytes on little-endian systems */
    return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) |
            htonl((uint32_t)(v >> 32));
#else
    /* Already big-endian, no conversion needed */
    return v;
#endif
}

/**
 * @brief Convert 64-bit unsigned integer from network to host byte order
 *
 * Inverse of htonll_u64(). On little-endian systems, swaps bytes.
 *
 * @param v Value in network byte order
 * @return Value in host byte order
 */
uint64_t ntohll_u64(uint64_t v) {
    /* Same operation as htonll due to symmetry */
    return htonll_u64(v);
}

/**
 * @brief Platform-independent millisecond sleep
 *
 * Suspends execution for specified number of milliseconds.
 *
 * @param ms Milliseconds to sleep
 */
void msleep(unsigned ms) {
#ifdef _WIN32
    /* Windows: use Sleep() from windows.h */
    Sleep(ms);
#else
    /* POSIX: use nanosleep() for precise timing */
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000UL;
    nanosleep(&ts, NULL);
#endif
}

/**
 * @brief Initialize network subsystem
 *
 * On Windows, initializes Winsock2 (WSAStartup).
 * On POSIX systems, this is a no-op.
 *
 * @return 0 on success, -1 on failure
 * @note Safe to call multiple times (Winsock will return success)
 * @note Must be called before any socket operations on Windows
 */
int net_init_once(void) {
#ifdef _WIN32
    WSADATA wsa;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (result != 0) {
        return -1; /* WSAStartup failed */
    }
    return 0;
#else
    /* POSIX: no initialization needed */
    return 0;
#endif
}
