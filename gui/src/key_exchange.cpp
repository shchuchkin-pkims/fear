#include "key_exchange.h"
#include <sodium.h>
#include <QDebug>
#include <QByteArray>

KeyExchange::KeyExchange(QObject *parent) 
    : QObject(parent), m_keysGenerated(false)
{
    // Initialize libsodium
    if (sodium_init() < 0) {
        qCritical() << "Failed to initialize libsodium";
    }
}

KeyExchange::~KeyExchange()
{
    // Clear sensitive data from memory
    if (m_keysGenerated) {
        sodium_memzero(m_secretKey, sizeof(m_secretKey));
    }
}

bool KeyExchange::generateKeyPair()
{
    if (crypto_box_keypair(m_publicKey, m_secretKey) != 0) {
        qCritical() << "Failed to generate key pair";
        m_keysGenerated = false;
        return false;
    }
    
    m_keysGenerated = true;
    qDebug() << "Key pair generated successfully";
    return true;
}

QString KeyExchange::getPublicKey() const
{
    if (!m_keysGenerated) {
        return QString();
    }
    
    QByteArray keyBytes(reinterpret_cast<const char*>(m_publicKey), crypto_box_PUBLICKEYBYTES);
    return QString(keyBytes.toHex());
}

QString KeyExchange::getSecretKey() const
{
    if (!m_keysGenerated) {
        return QString();
    }
    
    QByteArray keyBytes(reinterpret_cast<const char*>(m_secretKey), crypto_box_SECRETKEYBYTES);
    return QString(keyBytes.toHex());
}

bool KeyExchange::setPublicKey(const QString &publicKey)
{
    if (publicKey.length() != crypto_box_PUBLICKEYBYTES * 2) {
        qWarning() << "Invalid public key length";
        return false;
    }
    
    QByteArray keyBytes = QByteArray::fromHex(publicKey.toLatin1());
    if (keyBytes.length() != crypto_box_PUBLICKEYBYTES) {
        qWarning() << "Failed to decode public key";
        return false;
    }
    
    memcpy(m_publicKey, keyBytes.constData(), crypto_box_PUBLICKEYBYTES);
    return true;
}

bool KeyExchange::setSecretKey(const QString &secretKey)
{
    if (secretKey.length() != crypto_box_SECRETKEYBYTES * 2) {
        qWarning() << "Invalid secret key length";
        return false;
    }
    
    QByteArray keyBytes = QByteArray::fromHex(secretKey.toLatin1());
    if (keyBytes.length() != crypto_box_SECRETKEYBYTES) {
        qWarning() << "Failed to decode secret key";
        return false;
    }
    
    memcpy(m_secretKey, keyBytes.constData(), crypto_box_SECRETKEYBYTES);
    m_keysGenerated = true;
    return true;
}

QString KeyExchange::encryptMessage(const QString &message, const QString &recipientPublicKey)
{
    if (!m_keysGenerated) {
        qCritical() << "No key pair generated";
        return QString();
    }
    
    // Convert recipient public key from hex
    QByteArray recipientKeyBytes = QByteArray::fromHex(recipientPublicKey.toLatin1());
    if (recipientKeyBytes.length() != crypto_box_PUBLICKEYBYTES) {
        qCritical() << "Invalid recipient public key";
        return QString();
    }
    
    const unsigned char* recipient_pk = reinterpret_cast<const unsigned char*>(recipientKeyBytes.constData());
    
    // Prepare message data
    QByteArray messageBytes = message.toUtf8();
    const unsigned char* message_data = reinterpret_cast<const unsigned char*>(messageBytes.constData());
    unsigned long long message_len = messageBytes.length();
    
    // Calculate ciphertext length (nonce + encrypted message)
    unsigned long long ciphertext_len = crypto_box_NONCEBYTES + crypto_box_MACBYTES + message_len;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    
    // Generate random nonce
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Copy nonce to beginning of ciphertext
    memcpy(ciphertext, nonce, crypto_box_NONCEBYTES);
    
    // Encrypt the message
    if (crypto_box_easy(ciphertext + crypto_box_NONCEBYTES,
                       message_data, message_len,
                       nonce, recipient_pk, m_secretKey) != 0) {
        qCritical() << "Encryption failed";
        delete[] ciphertext;
        return QString();
    }
    
    // Convert ciphertext to hex
    QByteArray ciphertextBytes(reinterpret_cast<char*>(ciphertext), ciphertext_len);
    QString result = QString(ciphertextBytes.toHex());
    
    // Clean up
    delete[] ciphertext;
    
    return result;
}

QString KeyExchange::decryptMessage(const QString &ciphertext, const QString &senderPublicKey)
{
    if (!m_keysGenerated) {
        qCritical() << "No key pair generated";
        return QString();
    }
    
    // Convert sender public key from hex
    QByteArray senderKeyBytes = QByteArray::fromHex(senderPublicKey.toLatin1());
    if (senderKeyBytes.length() != crypto_box_PUBLICKEYBYTES) {
        qCritical() << "Invalid sender public key";
        return QString();
    }
    
    const unsigned char* sender_pk = reinterpret_cast<const unsigned char*>(senderKeyBytes.constData());
    
    // Convert ciphertext from hex
    QByteArray ciphertextBytes = QByteArray::fromHex(ciphertext.toLatin1());
    if (ciphertextBytes.length() < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        qCritical() << "Ciphertext too short";
        return QString();
    }
    
    const unsigned char* ciphertext_data = reinterpret_cast<const unsigned char*>(ciphertextBytes.constData());
    unsigned long long ciphertext_len = ciphertextBytes.length();
    
    // Extract nonce from ciphertext
    unsigned char nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, ciphertext_data, crypto_box_NONCEBYTES);
    
    // Prepare decrypted message buffer
    unsigned long long message_len = ciphertext_len - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
    unsigned char* decrypted = new unsigned char[message_len + 1]; // +1 for null terminator
    
    // Decrypt the message
    if (crypto_box_open_easy(decrypted,
                            ciphertext_data + crypto_box_NONCEBYTES,
                            ciphertext_len - crypto_box_NONCEBYTES,
                            nonce, sender_pk, m_secretKey) != 0) {
        qCritical() << "Decryption failed";
        delete[] decrypted;
        return QString();
    }
    
    // Add null terminator and convert to QString
    decrypted[message_len] = '\0';
    QString result = QString::fromUtf8(reinterpret_cast<char*>(decrypted), message_len);
    
    // Clean up
    delete[] decrypted;
    
    return result;
}