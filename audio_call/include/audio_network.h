/**
 * @file audio_network.h
 * @brief Network utilities for F.E.A.R. audio calls
 *
 * Provides platform-independent network helper functions:
 * - Byte order conversion for network protocol
 * - Socket initialization (Windows/POSIX)
 * - UDP socket operations
 */

#ifndef AUDIO_NETWORK_H
#define AUDIO_NETWORK_H

#include "audio_types.h"
#include <stdint.h>

/**
 * @brief Convert 64-bit integer to network byte order (big-endian)
 * @param v Value in host byte order
 * @return Value in network byte order
 */
uint64_t htonll_u64(uint64_t v);

/**
 * @brief Convert 64-bit integer from network to host byte order
 * @param v Value in network byte order
 * @return Value in host byte order
 */
uint64_t ntohll_u64(uint64_t v);

/**
 * @brief Initialize network subsystem (Windows: WSAStartup, POSIX: no-op)
 * @return 0 on success, -1 on failure
 * @note On Windows, must be called before any socket operations
 * @note Safe to call multiple times
 */
int net_init_once(void);

/**
 * @brief Platform-independent sleep function
 * @param ms Milliseconds to sleep
 */
void msleep(unsigned ms);

#endif /* AUDIO_NETWORK_H */
