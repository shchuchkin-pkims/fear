/**
 * @file crypto_message.h
 * @brief Encrypted messaging protocol for F.E.A.R. messenger
 *
 * This module handles encryption, decryption, and transmission of messages
 * using AES-256-GCM authenticated encryption. All messages are end-to-end
 * encrypted with room keys.
 */

#ifndef CRYPTO_MESSAGE_H
#define CRYPTO_MESSAGE_H

#include "common.h"
#include <sodium.h>

/**
 * @brief Send an encrypted text message through the socket
 *
 * Encrypts the plaintext message using AES-256-GCM with a random nonce,
 * then sends it over the network in the protocol frame format.
 *
 * Frame format:
 * [2 room_len][room][2 name_len][name][2 nonce_len][nonce][1 type][4 clen][cipher]
 *
 * @param s Socket descriptor
 * @param room Room name (metadata, part of authenticated data)
 * @param name Sender name (metadata, part of authenticated data)
 * @param key 32-byte encryption key
 * @param plaintext Plaintext message to encrypt
 * @param plen Length of plaintext message
 * @return 0 on success, -1 on failure
 *
 * @note Uses random nonce for each message (stored in frame)
 * @note Room and name are authenticated but not encrypted (metadata visible to server)
 */
int send_ciphertext(sock_t s, const char *room, const char *name,
                   const uint8_t *key, const uint8_t *plaintext, size_t plen);

/**
 * @brief Receive and decrypt a message from the socket
 *
 * Reads a complete protocol frame, verifies it belongs to the same room,
 * decrypts the message, and displays it to the user.
 *
 * @param s Socket descriptor
 * @param room Expected room name (messages from other rooms are ignored)
 * @param key 32-byte decryption key
 * @param myname Local user name (own messages are filtered out)
 * @return 1 on success, 0 if message filtered, -1 on error/disconnect
 *
 * @note Handles multiple message types: TEXT, FILE_*, USER_LIST
 * @note Service messages (USER_LIST) use zero nonce and are not encrypted
 * @note Own messages are filtered (not displayed)
 */
int recv_and_decrypt(sock_t s, const char *room, const uint8_t *key,
                    const char *myname);

/**
 * @brief Print a timestamped local message
 *
 * Displays a message with current time in [HH:MM:SS] format.
 * Used for echoing sent messages locally.
 *
 * @param name Sender name (usually local user)
 * @param msg Message text to display
 */
void print_local_message(const char *name, const char *msg);

#endif /* CRYPTO_MESSAGE_H */
