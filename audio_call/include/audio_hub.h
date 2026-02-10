/**
 * @file audio_hub.h
 * @brief Multi-user audio conference hub for F.E.A.R.
 *
 * Implements a central hub for group audio calls:
 * - Tracks multiple participants by IP/port
 * - Forwards encrypted audio to all participants
 * - Handles participant timeouts
 * - UDP-based communication
 */

#ifndef AUDIO_HUB_H
#define AUDIO_HUB_H

#include "audio_types.h"
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

/**
 * @struct HubClient
 * @brief Information about a hub participant
 */
typedef struct {
    struct sockaddr_in addr;  /**< Client's IP address and port */
    uint64_t last_seen;       /**< Timestamp of last packet (seconds) */
} HubClient;

/**
 * @struct Hub
 * @brief Audio conference hub state
 */
typedef struct {
    socket_t sock;                       /**< UDP socket for communication */
    HubClient clients[MAX_HUB_CLIENTS];  /**< Connected participants */
    int client_count;                     /**< Number of active clients */
} Hub;

/**
 * @brief Initialize audio hub
 * @param h Pointer to Hub structure
 * @param sock UDP socket (must be bound to port)
 */
void hub_init(Hub *h, socket_t sock);

/**
 * @brief Find or add client to hub
 *
 * Searches for existing client by address. If not found and space
 * available, adds new client.
 *
 * @param h Pointer to Hub structure
 * @param src Client's address
 * @return Client index (0 to MAX_HUB_CLIENTS-1), or -1 if full
 */
int hub_find_or_add(Hub *h, const struct sockaddr_in *src);

/**
 * @brief Remove inactive clients
 *
 * Removes clients that haven't sent packets within HUB_TIMEOUT_SEC.
 * Called periodically to clean up disconnected participants.
 *
 * @param h Pointer to Hub structure
 */
void hub_prune(Hub *h);

/**
 * @brief Get number of active clients
 * @param h Pointer to Hub structure
 * @return Number of connected clients
 */
int hub_count(Hub *h);

/**
 * @brief Forward audio packet to all clients except sender
 *
 * Broadcasts encrypted audio packet to all connected clients,
 * excluding the original sender.
 *
 * @param h Pointer to Hub structure
 * @param buf Packet data to forward
 * @param len Packet length
 * @param src Sender's address (excluded from broadcast)
 */
void hub_forward(Hub *h, const uint8_t *buf, size_t len,
                 const struct sockaddr_in *src);

/**
 * @brief Run hub server (blocking)
 *
 * Main hub loop that:
 * 1. Receives packets from clients
 * 2. Forwards to other participants
 * 3. Prunes inactive clients
 *
 * @param bind_port UDP port to listen on
 * @return 0 on success, -1 on error
 * @note Runs until interrupted (Ctrl+C)
 */
int hub_main(uint16_t bind_port);

#endif /* AUDIO_HUB_H */
