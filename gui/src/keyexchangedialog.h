/**
 * @file keyexchangedialog.h
 * @brief Dialog for secure Curve25519 key exchange
 *
 * This dialog provides a user interface for generating Curve25519 key pairs,
 * encrypting messages with a friend's public key, and decrypting received
 * encrypted messages using ECDH (Elliptic Curve Diffie-Hellman) key agreement.
 *
 * Security features:
 * - Curve25519 elliptic curve cryptography
 * - Public/private key pair generation
 * - Message encryption using shared secret
 * - Secure key exchange protocol
 */

#ifndef KEYEXCHANGEDIALOG_H
#define KEYEXCHANGEDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include "key_exchange.h"

/**
 * @class KeyExchangeDialog
 * @brief Dialog for managing secure key exchange and message encryption
 *
 * Provides UI for:
 * - Generating Curve25519 key pairs
 * - Displaying public key for sharing
 * - Encrypting messages with friend's public key
 * - Decrypting received encrypted messages
 * - Managing secret key visibility
 */
class KeyExchangeDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructs a new key exchange dialog
     * @param parent Parent widget (optional)
     */
    explicit KeyExchangeDialog(QWidget *parent = nullptr);

private slots:
    /**
     * @brief Generates a new Curve25519 key pair
     *
     * Creates a new public/private key pair and displays the public key
     * for sharing with communication partners.
     */
    void onGenerateKeys();

    /**
     * @brief Encrypts a message with friend's public key
     *
     * Takes plaintext message and friend's public key, performs ECDH
     * key agreement, and produces encrypted hex-encoded output.
     */
    void onEncrypt();

    /**
     * @brief Decrypts a received encrypted message
     *
     * Takes encrypted hex message and sender's public key, performs ECDH
     * key agreement, and recovers the original plaintext.
     */
    void onDecrypt();

    /**
     * @brief Updates encryption/decryption button states
     *
     * Enables or disables buttons based on whether all required fields
     * are filled with valid data.
     */
    void updateButtonStates();

private:
    KeyExchange *m_keyExchange;  ///< Cryptographic backend for key operations

    // Key pair display
    QLineEdit *m_publicKeyEdit;       ///< Displays generated public key
    QLineEdit *m_secretKeyEdit;       ///< Displays secret key (password mode)
    QPushButton *m_showSecretBtn;     ///< Toggle secret key visibility
    QTextEdit *m_shareEdit;           ///< Data to share with friend

    // Encryption fields
    QLineEdit *m_messageEdit;         ///< Plaintext message to encrypt
    QLineEdit *m_friendPublicKeyEdit; ///< Friend's public key (64 hex chars)
    QLineEdit *m_encryptedEdit;       ///< Resulting encrypted message

    // Decryption fields
    QLineEdit *m_encryptedInputEdit;  ///< Encrypted message to decrypt
    QLineEdit *m_senderPublicKeyEdit; ///< Sender's public key (64 hex chars)
    QLineEdit *m_decryptedEdit;       ///< Resulting decrypted message

    // Control buttons
    QPushButton *m_generateKeysBtn;   ///< Generate new key pair
    QPushButton *m_encryptBtn;        ///< Encrypt message
    QPushButton *m_decryptBtn;        ///< Decrypt message
    QLabel *m_statusLabel;            ///< Status message display
};

#endif // KEYEXCHANGEDIALOG_H
