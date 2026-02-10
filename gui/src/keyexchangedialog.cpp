/**
 * @file keyexchangedialog.cpp
 * @brief Implementation of secure key exchange dialog
 */

#include "keyexchangedialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QDebug>

KeyExchangeDialog::KeyExchangeDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Secure Key Exchange");
    setMinimumSize(600, 500);

    // Create cryptographic backend
    m_keyExchange = new KeyExchange(this);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // ===== Key pair section =====
    QGroupBox *keysGroup = new QGroupBox("Key Pair", this);
    QFormLayout *keysLayout = new QFormLayout(keysGroup);

    m_publicKeyEdit = new QLineEdit(keysGroup);
    m_publicKeyEdit->setReadOnly(true);
    m_publicKeyEdit->setPlaceholderText("Public key will appear here after generation");

    m_secretKeyEdit = new QLineEdit(keysGroup);
    m_secretKeyEdit->setEchoMode(QLineEdit::Password);
    m_secretKeyEdit->setPlaceholderText("Secret key will appear here after generation");

    QHBoxLayout *secretLayout = new QHBoxLayout();
    secretLayout->addWidget(m_secretKeyEdit);
    m_showSecretBtn = new QPushButton("Show", keysGroup);
    secretLayout->addWidget(m_showSecretBtn);

    keysLayout->addRow("Public key:", m_publicKeyEdit);
    keysLayout->addRow("Secret key (keep safe!):", secretLayout);
    mainLayout->addWidget(keysGroup);

    // ===== Data to share section =====
    QGroupBox *shareGroup = new QGroupBox("Data to share with friend", this);
    QVBoxLayout *shareLayout = new QVBoxLayout(shareGroup);
    m_shareEdit = new QTextEdit(shareGroup);
    m_shareEdit->setReadOnly(true);
    m_shareEdit->setPlaceholderText("Public key and encrypted messages will appear here");
    QPushButton *copyBtn = new QPushButton("Copy to clipboard", shareGroup);
    shareLayout->addWidget(m_shareEdit);
    shareLayout->addWidget(copyBtn);
    mainLayout->addWidget(shareGroup);

    // ===== Encryption section =====
    QGroupBox *encryptGroup = new QGroupBox("Encryption", this);
    QFormLayout *encryptLayout = new QFormLayout(encryptGroup);

    m_messageEdit = new QLineEdit(encryptGroup);
    m_messageEdit->setPlaceholderText("Enter message to encrypt");

    m_friendPublicKeyEdit = new QLineEdit(encryptGroup);
    m_friendPublicKeyEdit->setPlaceholderText("Enter friend's public key (64 hex characters)");

    m_encryptedEdit = new QLineEdit(encryptGroup);
    m_encryptedEdit->setReadOnly(true);
    m_encryptedEdit->setPlaceholderText("Encrypted message will appear here");

    encryptLayout->addRow("Message to send:", m_messageEdit);
    encryptLayout->addRow("Friend's public key:", m_friendPublicKeyEdit);
    encryptLayout->addRow("Encrypted (hex):", m_encryptedEdit);
    mainLayout->addWidget(encryptGroup);

    // ===== Decryption section =====
    QGroupBox *decryptGroup = new QGroupBox("Decryption", this);
    QFormLayout *decryptLayout = new QFormLayout(decryptGroup);

    m_encryptedInputEdit = new QLineEdit(decryptGroup);
    m_encryptedInputEdit->setPlaceholderText("Paste encrypted message here (hex format)");

    m_senderPublicKeyEdit = new QLineEdit(decryptGroup);
    m_senderPublicKeyEdit->setPlaceholderText("Enter sender's public key (64 hex characters)");

    m_decryptedEdit = new QLineEdit(decryptGroup);
    m_decryptedEdit->setReadOnly(true);
    m_decryptedEdit->setPlaceholderText("Decrypted message will appear here");

    decryptLayout->addRow("Encrypted message:", m_encryptedInputEdit);
    decryptLayout->addRow("Sender's public key:", m_senderPublicKeyEdit);
    decryptLayout->addRow("Decrypted:", m_decryptedEdit);
    mainLayout->addWidget(decryptGroup);

    // ===== Control buttons =====
    QHBoxLayout *btnLayout = new QHBoxLayout();
    m_generateKeysBtn = new QPushButton("Generate Key Pair", this);
    m_encryptBtn = new QPushButton("Encrypt", this);
    m_decryptBtn = new QPushButton("Decrypt", this);
    QPushButton *closeBtn = new QPushButton("Close", this);

    // Initially disable encryption/decryption until keys are generated
    m_encryptBtn->setEnabled(false);
    m_decryptBtn->setEnabled(false);

    btnLayout->addWidget(m_generateKeysBtn);
    btnLayout->addWidget(m_encryptBtn);
    btnLayout->addWidget(m_decryptBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(closeBtn);
    mainLayout->addLayout(btnLayout);

    // ===== Status label =====
    m_statusLabel = new QLabel("Ready to generate keys", this);
    mainLayout->addWidget(m_statusLabel);

    // ===== Signal connections =====

    // Copy button - copies shared data to clipboard
    connect(copyBtn, &QPushButton::clicked, this, [this]() {
        QGuiApplication::clipboard()->setText(m_shareEdit->toPlainText());
        QMessageBox::information(this, "Copied", "Shared data copied to clipboard.");
    });

    // Main action buttons
    connect(m_generateKeysBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onGenerateKeys);
    connect(m_encryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onEncrypt);
    connect(m_decryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onDecrypt);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    // Show/hide secret key button
    connect(m_showSecretBtn, &QPushButton::clicked, this, [this]() {
        if (m_secretKeyEdit->echoMode() == QLineEdit::Password) {
            m_secretKeyEdit->setEchoMode(QLineEdit::Normal);
            m_showSecretBtn->setText("Hide");
        } else {
            m_secretKeyEdit->setEchoMode(QLineEdit::Password);
            m_showSecretBtn->setText("Show");
        }
    });

    // Enable/disable buttons when required fields are filled
    connect(m_publicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    connect(m_secretKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    connect(m_messageEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    connect(m_friendPublicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    connect(m_encryptedInputEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    connect(m_senderPublicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
}

void KeyExchangeDialog::onGenerateKeys() {
    if (m_keyExchange->generateKeyPair()) {
        m_publicKeyEdit->setText(m_keyExchange->getPublicKey());
        m_secretKeyEdit->setText(m_keyExchange->getSecretKey());

        // Only public key in the share field
        QString shareData = QString("Public key: %1").arg(m_keyExchange->getPublicKey());
        m_shareEdit->setPlainText(shareData);

        m_statusLabel->setText("Key pair generated successfully!");
    } else {
        m_statusLabel->setText("Failed to generate key pair");
        QMessageBox::warning(this, "Error", "Failed to generate key pair. Please try again.");
    }
}

void KeyExchangeDialog::onEncrypt() {
    QString message = m_messageEdit->text().trimmed();
    QString friendPublicKey = m_friendPublicKeyEdit->text().trimmed();

    // Validate message
    if (message.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter a message to encrypt.");
        return;
    }

    // Validate friend's public key (must be 64 hex characters)
    if (friendPublicKey.length() != 64) {
        QMessageBox::warning(this, "Error",
            QString("Please enter a valid friend's public key (64 hex characters).\nCurrent length: %1").arg(friendPublicKey.length()));
        return;
    }

    // Perform encryption using ECDH
    QString encrypted = m_keyExchange->encryptMessage(message, friendPublicKey);
    if (!encrypted.isEmpty()) {
        m_encryptedEdit->setText(encrypted);
        m_statusLabel->setText("Message encrypted successfully!");

        // Add encrypted message to share field
        QString shareData = QString("Public key: %1\n\nEncrypted message: %2")
                              .arg(m_keyExchange->getPublicKey())
                              .arg(encrypted);
        m_shareEdit->setPlainText(shareData);

        // Auto-copy encrypted message to clipboard for easy sharing
        QGuiApplication::clipboard()->setText(encrypted);
        QMessageBox::information(this, "Encrypted",
            "Message encrypted successfully!\n\nEncrypted message has been copied to clipboard. Send it to your friend.");
    } else {
        m_statusLabel->setText("Encryption failed");
        QMessageBox::warning(this, "Error", "Failed to encrypt message. Please check your keys.");
    }
}

void KeyExchangeDialog::onDecrypt() {
    QString encrypted = m_encryptedInputEdit->text().trimmed();
    QString senderPublicKey = m_senderPublicKeyEdit->text().trimmed();

    // Validate encrypted message
    if (encrypted.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter an encrypted message to decrypt.");
        return;
    }

    // Validate sender's public key (must be 64 hex characters)
    if (senderPublicKey.length() != 64) {
        QMessageBox::warning(this, "Error",
            QString("Please enter a valid sender's public key (64 hex characters).\nCurrent length: %1").arg(senderPublicKey.length()));
        return;
    }

    // Perform decryption using ECDH
    QString decrypted = m_keyExchange->decryptMessage(encrypted, senderPublicKey);
    if (!decrypted.isEmpty()) {
        m_decryptedEdit->setText(decrypted);
        m_statusLabel->setText("Message decrypted successfully!");
        QMessageBox::information(this, "Decrypted", "Message decrypted successfully!");
    } else {
        m_statusLabel->setText("Decryption failed");
        QMessageBox::warning(this, "Error", "Failed to decrypt message. Please check:\n- Encrypted message format\n- Sender's public key\n- Your secret key");
    }
}

void KeyExchangeDialog::updateButtonStates() {
    bool hasKeys = !m_publicKeyEdit->text().isEmpty() && !m_secretKeyEdit->text().isEmpty();
    bool hasFriendKey = m_friendPublicKeyEdit->text().trimmed().length() == 64;
    bool hasMessage = !m_messageEdit->text().trimmed().isEmpty();
    bool hasEncryptedInput = !m_encryptedInputEdit->text().trimmed().isEmpty();
    bool hasSenderKey = m_senderPublicKeyEdit->text().trimmed().length() == 64;

    // Debug output to help diagnose issues
    qDebug() << "updateButtonStates: hasKeys=" << hasKeys
             << " hasFriendKey=" << hasFriendKey
             << " hasMessage=" << hasMessage
             << " friendKeyLen=" << m_friendPublicKeyEdit->text().trimmed().length()
             << " publicKeyLen=" << m_publicKeyEdit->text().length()
             << " secretKeyLen=" << m_secretKeyEdit->text().length();

    // Enable encrypt button only when all required fields are valid
    m_encryptBtn->setEnabled(hasKeys && hasFriendKey && hasMessage);

    // Enable decrypt button only when all required fields are valid
    m_decryptBtn->setEnabled(hasKeys && hasSenderKey && hasEncryptedInput);
}
