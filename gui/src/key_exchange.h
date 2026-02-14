/**
 * @file key_exchange.h
 * @brief Curve25519 key exchange wrapper for F.E.A.R. GUI
 *
 * Provides a Qt-friendly interface to libsodium's crypto_box API
 * for public key cryptography and key exchange operations.
 */

#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <QObject>
#include <QString>
#include <QByteArray>

/**
 * @class KeyExchange
 * @brief Wrapper for libsodium public key cryptography (Curve25519)
 *
 * This class provides a convenient Qt interface for:
 * - Generating Curve25519 key pairs
 * - Encrypting messages with recipient's public key
 * - Decrypting messages with own secret key
 *
 * Security notes:
 * - Uses crypto_box (X25519-XSalsa20-Poly1305)
 * - Public keys can be safely shared
 * - Secret keys must be kept private
 * - Each message uses a random nonce
 */
class KeyExchange : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Construct a new KeyExchange object
     * @param parent Parent QObject for Qt memory management
     */
    explicit KeyExchange(QObject *parent = nullptr);

    /**
     * @brief Destructor - securely clears secret key from memory
     */
    ~KeyExchange();

    /**
     * @brief Generate a new Curve25519 key pair
     * @return true on success, false on failure
     * @note Previous keys will be overwritten
     */
    bool generateKeyPair();

    /**
     * @brief Get public key as hexadecimal string
     * @return 64-character hex string, or empty if not generated
     */
    QString getPublicKey() const;

    /**
     * @brief Get secret key as hexadecimal string
     * @return 64-character hex string, or empty if not generated
     * @warning Keep secret key private! Never share it.
     */
    QString getSecretKey() const;

    /**
     * @brief Encrypt a message for a recipient
     * @param message Plaintext message to encrypt
     * @param recipientPublicKey Recipient's public key (64-char hex)
     * @return Hex-encoded ciphertext (nonce + encrypted data), or empty on error
     * @note Uses random nonce for each encryption
     */
    QString encryptMessage(const QString &message, const QString &recipientPublicKey);

    /**
     * @brief Decrypt a message from a sender
     * @param ciphertext Hex-encoded ciphertext (with nonce)
     * @param senderPublicKey Sender's public key (64-char hex)
     * @return Decrypted plaintext, or empty on authentication failure
     * @note Returns empty string if authentication tag is invalid
     */
    QString decryptMessage(const QString &ciphertext, const QString &senderPublicKey);

    /**
     * @brief Import public key from hex string
     * @param publicKey 64-character hex string
     * @return true on success, false if invalid format
     */
    bool setPublicKey(const QString &publicKey);

    /**
     * @brief Import secret key from hex string
     * @param secretKey 64-character hex string
     * @return true on success, false if invalid format
     * @warning Only import trusted secret keys!
     */
    bool setSecretKey(const QString &secretKey);

    /**
     * @brief Check if key pair has been generated
     * @return true if keys are available, false otherwise
     */
    bool isKeysGenerated() const { return m_keysGenerated; }

private:
    unsigned char m_publicKey[32];  /**< Public key (32 bytes) */
    unsigned char m_secretKey[32];  /**< Secret key (32 bytes) */
    bool m_keysGenerated;           /**< True if keys are initialized */
};

#endif // KEY_EXCHANGE_H