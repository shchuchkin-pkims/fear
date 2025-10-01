#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <QObject>
#include <QString>
#include <QByteArray>

class KeyExchange : public QObject
{
    Q_OBJECT

public:
    explicit KeyExchange(QObject *parent = nullptr);
    ~KeyExchange();

    // Generate key pair
    bool generateKeyPair();
    
    // Get public key in hex format
    QString getPublicKey() const;
    
    // Get secret key in hex format  
    QString getSecretKey() const;
    
    // Encrypt message
    QString encryptMessage(const QString &message, const QString &recipientPublicKey);
    
    // Decrypt message
    QString decryptMessage(const QString &ciphertext, const QString &senderPublicKey);
    
    // Set keys from hex strings
    bool setPublicKey(const QString &publicKey);
    bool setSecretKey(const QString &secretKey);

    // Check if keys are generated
    bool isKeysGenerated() const { return m_keysGenerated; }

private:
    unsigned char m_publicKey[32];  // crypto_box_PUBLICKEYBYTES
    unsigned char m_secretKey[32];  // crypto_box_SECRETKEYBYTES
    bool m_keysGenerated;
};

#endif // KEY_EXCHANGE_H