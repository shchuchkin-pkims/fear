/**
 * @file audio_hub.c
 * @brief Multi-user audio conference hub for F.E.A.R.
 *
 * Implements a UDP packet relay server for group audio calls.
 * The hub forwards encrypted audio packets between participants
 * without decrypting them (zero-knowledge forwarding).
 */

#include "audio_hub.h"
#include "audio_network.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define THREAD_RET DWORD WINAPI
typedef HANDLE thread_handle_t;
#else
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#define THREAD_RET void*
typedef pthread_t thread_handle_t;
#endif

/* Constants */
#define HUB_CLIENT_TIMEOUT_SEC 180  /**< Remove clients after 180s of inactivity */
#define HUB_RECV_BUFSZ 1500        /**< UDP receive buffer size */

/* Internal hub structure with threading support */
typedef struct {
    socket_t sock;
    HubClient clients[MAX_HUB_CLIENTS];
    atomic_int running;
    thread_handle_t thread;
} HubInternal;

/**
 * @brief Initialize audio hub
 *
 * Clears all client slots and prepares hub for operation.
 *
 * @param h Pointer to Hub structure
 * @param sock UDP socket (must be bound to port)
 */
void hub_init(Hub *h, socket_t sock) {
    if (!h) {
        return;
    }

    memset(h, 0, sizeof(*h));
    h->sock = sock;
    h->client_count = 0;

    /* Initialize all client slots as inactive */
    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        memset(&h->clients[i], 0, sizeof(h->clients[i]));
    }
}

/**
 * @brief Find or add client to hub
 *
 * Searches for existing client by IP address and port.
 * If found, updates last_seen timestamp.
 * If not found and space available, adds new client.
 *
 * @param h Pointer to Hub structure
 * @param src Client's address
 * @return Client index (0 to MAX_HUB_CLIENTS-1), or -1 if full
 */
int hub_find_or_add(Hub *h, const struct sockaddr_in *src) {
    if (!h || !src) {
        return -1;
    }

    time_t now = time(NULL);

    /* Search for existing client */
    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        if (h->clients[i].last_seen > 0) {  /* Active slot */
            if (h->clients[i].addr.sin_addr.s_addr == src->sin_addr.s_addr &&
                h->clients[i].addr.sin_port == src->sin_port) {
                /* Found - update timestamp */
                h->clients[i].last_seen = (uint64_t)now;
                return i;
            }
        }
    }

    /* Not found - add new client in first available slot */
    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        if (h->clients[i].last_seen == 0) {  /* Free slot */
            h->clients[i].addr = *src;
            h->clients[i].last_seen = (uint64_t)now;
            h->client_count++;

            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src->sin_addr, buf, sizeof(buf));
            fprintf(stderr, "[hub] new client %s:%u (slot %d, total: %d)\n",
                    buf, ntohs(src->sin_port), i, h->client_count);
            return i;
        }
    }

    /* Hub is full */
    fprintf(stderr, "[hub] WARNING: hub full (%d clients), rejecting new connection\n",
            MAX_HUB_CLIENTS);
    return -1;
}

/**
 * @brief Remove inactive clients
 *
 * Removes clients that haven't sent packets within HUB_CLIENT_TIMEOUT_SEC.
 * Called periodically to clean up disconnected participants.
 *
 * @param h Pointer to Hub structure
 */
void hub_prune(Hub *h) {
    if (!h) {
        return;
    }

    time_t now = time(NULL);

    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        if (h->clients[i].last_seen > 0) {  /* Active client */
            if ((time_t)h->clients[i].last_seen + HUB_CLIENT_TIMEOUT_SEC < now) {
                /* Timeout - remove client */
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &h->clients[i].addr.sin_addr, buf, sizeof(buf));
                fprintf(stderr, "[hub] remove client %s:%u (slot %d) due to timeout\n",
                        buf, ntohs(h->clients[i].addr.sin_port), i);

                h->clients[i].last_seen = 0;  /* Mark slot as free */
                h->client_count--;
            }
        }
    }
}

/**
 * @brief Get number of active clients
 *
 * @param h Pointer to Hub structure
 * @return Number of connected clients
 */
int hub_count(Hub *h) {
    if (!h) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        if (h->clients[i].last_seen > 0) {
            count++;
        }
    }

    return count;
}

/**
 * @brief Forward audio packet to all clients except sender
 *
 * Broadcasts encrypted audio packet to all connected clients,
 * excluding the original sender (no echo).
 *
 * @param h Pointer to Hub structure
 * @param buf Packet data to forward
 * @param len Packet length
 * @param src Sender's address (excluded from broadcast)
 *
 * @note Packets are forwarded without decryption (zero-knowledge relay)
 */
void hub_forward(Hub *h, const uint8_t *buf, size_t len,
                 const struct sockaddr_in *src) {
    if (!h || !buf || !src) {
        return;
    }

    /* Forward to all clients except the sender */
    int forwarded = 0;
    for (int i = 0; i < MAX_HUB_CLIENTS; ++i) {
        if (h->clients[i].last_seen == 0) {
            continue;  /* Inactive slot */
        }

        /* Skip sender (no echo) */
        if (h->clients[i].addr.sin_addr.s_addr == src->sin_addr.s_addr &&
            h->clients[i].addr.sin_port == src->sin_port) {
            continue;
        }

        /* Forward packet */
        sendto(h->sock, (const char*)buf, (int)len, 0,
               (struct sockaddr*)&h->clients[i].addr,
               sizeof(h->clients[i].addr));
        forwarded++;
    }
}

/**
 * @brief Hub receive thread
 *
 * Continuously receives UDP packets and forwards them to other clients.
 * Runs until hub.running is set to 0.
 *
 * @param arg Pointer to HubInternal structure
 * @return Thread return value (platform-specific)
 */
static THREAD_RET hub_thread(void *arg) {
    HubInternal *hi = (HubInternal*)arg;
    Hub h;
    h.sock = hi->sock;
    memcpy(h.clients, hi->clients, sizeof(h.clients));
    h.client_count = 0;

    uint8_t rbuf[HUB_RECV_BUFSZ];

    while (atomic_load(&hi->running)) {
        struct sockaddr_in src;
#ifdef _WIN32
        int slen = sizeof(src);
#else
        socklen_t slen = sizeof(src);
#endif

        /* Receive packet from any client */
        int n = recvfrom(hi->sock, (char*)rbuf, (int)sizeof(rbuf), 0,
                         (struct sockaddr*)&src, &slen);

        if (n <= 0) {
            msleep(5);
            hub_prune(&h);
            memcpy(hi->clients, h.clients, sizeof(h.clients));
            continue;
        }

        /* Register client (or update timestamp) */
        int idx = hub_find_or_add(&h, &src);
        if (idx < 0) {
            continue;  /* Hub full */
        }

        /* Forward to all other clients */
        hub_forward(&h, rbuf, (size_t)n, &src);

        /* Update shared client list */
        memcpy(hi->clients, h.clients, sizeof(h.clients));
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/**
 * @brief Run hub server (blocking)
 *
 * Main hub loop:
 * 1. Binds to UDP port
 * 2. Receives packets from clients
 * 3. Forwards packets to other participants
 * 4. Prunes inactive clients
 *
 * @param bind_port UDP port to listen on
 * @return 0 on success, -1 on error
 *
 * @note Runs until interrupted (Ctrl+C or Esc on Windows)
 * @note This is a blocking call - it won't return until stopped
 */
int hub_main(uint16_t bind_port) {
    /* Initialize network stack */
    if (net_init_once() != 0) {
        return -1;
    }

    /* Create UDP socket */
    socket_t sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "[hub] ERROR: socket() failed\n");
        return -1;
    }

    /* Bind to port */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(bind_port);

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "[hub] ERROR: bind() failed (port %u)\n", bind_port);
        CLOSESOCK(sock);
        return -1;
    }

    /* Initialize hub */
    HubInternal hi;
    memset(&hi, 0, sizeof(hi));
    hi.sock = sock;
    atomic_store(&hi.running, 1);

    fprintf(stderr, "[hub] Listening on *:%u\n", bind_port);
    fprintf(stderr, "[hub] Max clients: %d\n", MAX_HUB_CLIENTS);
    fprintf(stderr, "[hub] Timeout: %d seconds\n", HUB_CLIENT_TIMEOUT_SEC);

    /* Start receive thread */
#ifdef _WIN32
    hi.thread = CreateThread(NULL, 0, hub_thread, &hi, 0, NULL);
    if (!hi.thread) {
        fprintf(stderr, "[hub] ERROR: CreateThread() failed\n");
        CLOSESOCK(sock);
        return -1;
    }
#else
    if (pthread_create(&hi.thread, NULL, hub_thread, &hi) != 0) {
        fprintf(stderr, "[hub] ERROR: pthread_create() failed\n");
        CLOSESOCK(sock);
        return -1;
    }
#endif

    fprintf(stderr, "[hub] Running. Press Ctrl+C to stop.\n");

    /* Main loop - wait for stop signal */
    while (atomic_load(&hi.running)) {
#ifdef _WIN32
        if (GetAsyncKeyState(VK_CANCEL) || GetAsyncKeyState(VK_ESCAPE)) {
            break;
        }
        msleep(100);
#else
        /* On POSIX, wait for Ctrl+C (signal handler should set running=0) */
        msleep(100);
#endif
    }

    /* Shutdown */
    fprintf(stderr, "\n[hub] Shutting down...\n");
    atomic_store(&hi.running, 0);

#ifdef _WIN32
    WaitForSingleObject(hi.thread, INFINITE);
    CloseHandle(hi.thread);
#else
    pthread_join(hi.thread, NULL);
#endif

    CLOSESOCK(sock);
    fprintf(stderr, "[hub] Stopped.\n");

    return 0;
}
