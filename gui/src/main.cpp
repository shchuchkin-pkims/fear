#include <QKeyEvent>
#include <QFontDialog> 
#include <QApplication>
#include <QMainWindow>
#include <QSplitter>
#include <QListWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QMenuBar>
#include <QAction>
#include <QLabel>
#include <QProcess>
#include <QFileDialog>
#include <QFile>
#include <QRegularExpression>
#include <QClipboard>
#include <QGuiApplication>
#include <QMessageBox>
#include <QInputDialog>
#include <QSettings>
#include <QTimer>
#include <QDateTime>
#include <QDebug>
#include <QDialog>
#include <QStatusBar>
#include <QMenu>
#include <QProgressDialog>
#include <QDesktopServices>
#include <QGroupBox>
#include <QComboBox>
#include <QSpinBox>

#include <QFormLayout>
#include <QIcon>

// #include "dh.h"
#include "key_exchange.h"

class KeyExchangeDialog : public QDialog {
    Q_OBJECT
public:
    explicit KeyExchangeDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Secure Key Exchange");
        setMinimumSize(600, 500);
        
        m_keyExchange = new KeyExchange(this);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // Key pair section
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

        // Data to share
        QGroupBox *shareGroup = new QGroupBox("Data to share with friend", this);
        QVBoxLayout *shareLayout = new QVBoxLayout(shareGroup);
        m_shareEdit = new QTextEdit(shareGroup);
        m_shareEdit->setReadOnly(true);
        m_shareEdit->setPlaceholderText("Public key and encrypted messages will appear here");
        QPushButton *copyBtn = new QPushButton("Copy to clipboard", shareGroup);
        shareLayout->addWidget(m_shareEdit);
        shareLayout->addWidget(copyBtn);
        mainLayout->addWidget(shareGroup);

        // Encryption section
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

        // Decryption section
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

        // Buttons
        QHBoxLayout *btnLayout = new QHBoxLayout();
        m_generateKeysBtn = new QPushButton("Generate Key Pair", this);
        m_encryptBtn = new QPushButton("Encrypt", this);
        m_decryptBtn = new QPushButton("Decrypt", this);
        QPushButton *closeBtn = new QPushButton("Close", this);
        
        m_encryptBtn->setEnabled(false);
        m_decryptBtn->setEnabled(false);
        
        btnLayout->addWidget(m_generateKeysBtn);
        btnLayout->addWidget(m_encryptBtn);
        btnLayout->addWidget(m_decryptBtn);
        btnLayout->addStretch();
        btnLayout->addWidget(closeBtn);
        mainLayout->addLayout(btnLayout);

        // Status label
        m_statusLabel = new QLabel("Ready to generate keys", this);
        mainLayout->addWidget(m_statusLabel);

        // Connections
        connect(copyBtn, &QPushButton::clicked, this, [this]() {
            QGuiApplication::clipboard()->setText(m_shareEdit->toPlainText());
            QMessageBox::information(this, "Copied", "Shared data copied to clipboard.");
        });
        
        connect(m_generateKeysBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onGenerateKeys);
        connect(m_encryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onEncrypt);
        connect(m_decryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onDecrypt);
        connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
        
        connect(m_showSecretBtn, &QPushButton::clicked, this, [this]() {
            if (m_secretKeyEdit->echoMode() == QLineEdit::Password) {
                m_secretKeyEdit->setEchoMode(QLineEdit::Normal);
                m_showSecretBtn->setText("Hide");
            } else {
                m_secretKeyEdit->setEchoMode(QLineEdit::Password);
                m_showSecretBtn->setText("Show");
            }
        });
        
        // Enable buttons when required fields are filled
        connect(m_publicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
        connect(m_secretKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
        connect(m_messageEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
        connect(m_friendPublicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
        connect(m_encryptedInputEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
        connect(m_senderPublicKeyEdit, &QLineEdit::textChanged, this, &KeyExchangeDialog::updateButtonStates);
    }

private slots:

    void onGenerateKeys() {
        if (m_keyExchange->generateKeyPair()) {
            m_publicKeyEdit->setText(m_keyExchange->getPublicKey());
            m_secretKeyEdit->setText(m_keyExchange->getSecretKey());
            
            // Только публичный ключ в поле для обмена
            QString shareData = QString("Public key: %1").arg(m_keyExchange->getPublicKey());
            m_shareEdit->setPlainText(shareData);
            
            m_statusLabel->setText("Key pair generated successfully!");
        } else {
            m_statusLabel->setText("Failed to generate key pair");
            QMessageBox::warning(this, "Error", "Failed to generate key pair. Please try again.");
        }
    }

    void onEncrypt() {
        QString message = m_messageEdit->text().trimmed();
        QString friendPublicKey = m_friendPublicKeyEdit->text().trimmed();

        if (message.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please enter a message to encrypt.");
            return;
        }

        if (friendPublicKey.length() != 64) {
            QMessageBox::warning(this, "Error",
                QString("Please enter a valid friend's public key (64 hex characters).\nCurrent length: %1").arg(friendPublicKey.length()));
            return;
        }
        
        QString encrypted = m_keyExchange->encryptMessage(message, friendPublicKey);
        if (!encrypted.isEmpty()) {
            m_encryptedEdit->setText(encrypted);
            m_statusLabel->setText("Message encrypted successfully!");
            
            // Добавляем зашифрованное сообщение в поле для обмена
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

    void onDecrypt() {
        QString encrypted = m_encryptedInputEdit->text().trimmed();
        QString senderPublicKey = m_senderPublicKeyEdit->text().trimmed();

        if (encrypted.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please enter an encrypted message to decrypt.");
            return;
        }

        if (senderPublicKey.length() != 64) {
            QMessageBox::warning(this, "Error",
                QString("Please enter a valid sender's public key (64 hex characters).\nCurrent length: %1").arg(senderPublicKey.length()));
            return;
        }
        
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
    
    void updateButtonStates() {
        bool hasKeys = !m_publicKeyEdit->text().isEmpty() && !m_secretKeyEdit->text().isEmpty();
        bool hasFriendKey = m_friendPublicKeyEdit->text().trimmed().length() == 64;
        bool hasMessage = !m_messageEdit->text().trimmed().isEmpty();
        bool hasEncryptedInput = !m_encryptedInputEdit->text().trimmed().isEmpty();
        bool hasSenderKey = m_senderPublicKeyEdit->text().trimmed().length() == 64;

        // Debug output to help diagnose the issue
        qDebug() << "updateButtonStates: hasKeys=" << hasKeys
                 << " hasFriendKey=" << hasFriendKey
                 << " hasMessage=" << hasMessage
                 << " friendKeyLen=" << m_friendPublicKeyEdit->text().trimmed().length()
                 << " publicKeyLen=" << m_publicKeyEdit->text().length()
                 << " secretKeyLen=" << m_secretKeyEdit->text().length();

        m_encryptBtn->setEnabled(hasKeys && hasFriendKey && hasMessage);
        m_decryptBtn->setEnabled(hasKeys && hasSenderKey && hasEncryptedInput);
    }

private:
    KeyExchange *m_keyExchange;
    
    QLineEdit *m_publicKeyEdit;
    QLineEdit *m_secretKeyEdit;
    QPushButton *m_showSecretBtn;
    QTextEdit *m_shareEdit;
    
    // Encryption fields
    QLineEdit *m_messageEdit;
    QLineEdit *m_friendPublicKeyEdit;
    QLineEdit *m_encryptedEdit;
    
    // Decryption fields  
    QLineEdit *m_encryptedInputEdit;
    QLineEdit *m_senderPublicKeyEdit;
    QLineEdit *m_decryptedEdit;
    
    QPushButton *m_generateKeysBtn;
    QPushButton *m_encryptBtn;
    QPushButton *m_decryptBtn;
    QLabel *m_statusLabel;
};

// Аудио звонки
class AudioCallManager : public QObject {
    Q_OBJECT
public:
    AudioCallManager(QObject *parent = nullptr) : QObject(parent), callProcess(nullptr) {
        settings = new QSettings("fear-messenger", "fear-audio", this);
    }

    ~AudioCallManager() {
        stopCall();
    }

    bool generateKey() {
        QString audioAppPath = findAudioCallApp();
        if (audioAppPath.isEmpty()) {
            emit error("Audio call application not found");
            return false;
        }

        QProcess process;
        process.start(audioAppPath, QStringList() << "genkey");

        if (!process.waitForFinished(5000)) {
            emit error("Key generation timed out");
            return false;
        }

        if (process.exitCode() != 0) {
            emit error("Key generation failed");
            return false;
        }

        QString output = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        if (output.length() == 64) { // 32 bytes in hex
            currentKey = output;
            emit keyGenerated(output);
            return true;
        }

        emit error("Invalid key format");
        return false;
    }

    bool startCall(const QString &remoteIp, quint16 remotePort, const QString &key, quint16 localPort = 0, int inputDevice = -1, int outputDevice = -1) {
        if (key.isEmpty()) {
            emit error("Key is required to start a call");
            return false;
        }

        stopCall();

        QString audioAppPath = findAudioCallApp();
        if (audioAppPath.isEmpty()) {
            emit error("Audio call application not found");
            return false;
        }

        callProcess = new QProcess(this);
        connect(callProcess, &QProcess::readyReadStandardOutput, this, &AudioCallManager::onProcessOutput);
        connect(callProcess, &QProcess::readyReadStandardError, this, &AudioCallManager::onProcessError);
        connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &AudioCallManager::onProcessFinished);

        QStringList args;
        args << "call" << remoteIp << QString::number(remotePort) << key;
        if (localPort > 0) {
            args << QString::number(localPort);
        } else {
            args << "0";  // Default local port
        }

        // Добавляем параметры устройств
        if (inputDevice >= 0) {
            args << QString::number(inputDevice);
            if (outputDevice >= 0) {
                args << QString::number(outputDevice);
            }
        } else if (outputDevice >= 0) {
            args << "-1" << QString::number(outputDevice);
        }

        callProcess->start(audioAppPath, args);

        if (!callProcess->waitForStarted(3000)) {
            emit error("Failed to start audio call");
            delete callProcess;
            callProcess = nullptr;
            return false;
        }

        emit callStarted();
        return true;
    }

    bool startListening(quint16 localPort, const QString &key, int inputDevice = -1, int outputDevice = -1) {
        if (key.isEmpty()) {
            emit error("Key is required to start listening");
            return false;
        }

        stopCall();

        QString audioAppPath = findAudioCallApp();
        if (audioAppPath.isEmpty()) {
            emit error("Audio call application not found");
            return false;
        }

        callProcess = new QProcess(this);
        connect(callProcess, &QProcess::readyReadStandardOutput, this, &AudioCallManager::onProcessOutput);
        connect(callProcess, &QProcess::readyReadStandardError, this, &AudioCallManager::onProcessError);
        connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &AudioCallManager::onProcessFinished);

        QStringList args;
        args << "listen" << QString::number(localPort) << key;

        // Добавляем параметры устройств
        if (inputDevice >= 0) {
            args << QString::number(inputDevice);
            if (outputDevice >= 0) {
                args << QString::number(outputDevice);
            }
        } else if (outputDevice >= 0) {
            args << "-1" << QString::number(outputDevice);
        }

        callProcess->start(audioAppPath, args);

        if (!callProcess->waitForStarted(3000)) {
            emit error("Failed to start audio listening");
            delete callProcess;
            callProcess = nullptr;
            return false;
        }

        emit listeningStarted();
        return true;
    }

    void stopCall() {
        if (callProcess && callProcess->state() == QProcess::Running) {
            callProcess->terminate();
            if (!callProcess->waitForFinished(1000)) {
                callProcess->kill();
            }
        }
        delete callProcess;
        callProcess = nullptr;

        emit callStopped();
    }

    bool isCallActive() const {
        return callProcess && callProcess->state() == QProcess::Running;
    }

    QString getCurrentKey() const { return currentKey; }

signals:
    void keyGenerated(const QString &key);
    void callStarted();
    void listeningStarted();
    void callStopped();
    void error(const QString &error);
    void output(const QString &message);

private slots:
    void onProcessOutput() {
        if (callProcess) {
            QString output = QString::fromUtf8(callProcess->readAllStandardOutput());
            emit this->output(output);
        }
    }

    void onProcessError() {
        if (callProcess) {
            QString error = QString::fromUtf8(callProcess->readAllStandardError());
            emit this->error(error);
        }
    }

    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
        Q_UNUSED(exitCode);
        Q_UNUSED(exitStatus);
        emit callStopped();
    }

private:
    QProcess *callProcess;
    QString currentKey;
    QSettings *settings;

    QString findAudioCallApp() {
        // Поиск audio_call в разных местах
        QStringList possiblePaths = {
            QApplication::applicationDirPath() + "/audio_call",
            QApplication::applicationDirPath() + "/bin/audio_call",
            QApplication::applicationDirPath() + "/../bin/audio_call",
            "audio_call",
            "./audio_call"
        };

#ifdef Q_OS_WIN
        for (QString &path : possiblePaths) {
            path += ".exe";
        }
#endif

        for (const QString &path : possiblePaths) {
            if (QFile::exists(path)) {
                return path;
            }
        }

        return QString();
    }
};

// Диалог для аудиозвонков
class AudioCallDialog : public QDialog {
    Q_OBJECT
public:
    AudioCallDialog(AudioCallManager *audioManager, QWidget *parent = nullptr)
        : QDialog(parent), audioManager(audioManager) {
        setWindowTitle("Audio Call");
        setMinimumSize(500, 450);

        setupUI();
        setupConnections();

        // Загружаем список устройств при открытии диалога
        refreshAudioDevices();
    }

private slots:
    void onGenerateKey() {
        if (audioManager->generateKey()) {
            // Ключ будет установлен через сигнал keyGenerated
        }
    }

    void onKeyGenerated(const QString &key) {
        keyEdit->setText(key);
        outputText->append("Key generated: " + key);
    }

    void onStartCall() {
        QString remoteIp = ipEdit->text();
        quint16 remotePort = portSpin->value();
        QString key = keyEdit->text();

        if (remoteIp.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please enter remote IP");
            return;
        }

        if (key.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please generate or enter a key first");
            return;
        }

        // Получаем выбранные устройства
        int inputDevice = inputDeviceCombo->currentData().toInt();
        int outputDevice = outputDeviceCombo->currentData().toInt();

        if (audioManager->startCall(remoteIp, remotePort, key, localPortSpin->value(), inputDevice, outputDevice)) {
            statusLabel->setText("Call started");
        }
    }

    void onStartListening() {
        QString key = keyEdit->text();
        if (key.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please generate or enter a key first");
            return;
        }

        // Получаем выбранные устройства
        int inputDevice = inputDeviceCombo->currentData().toInt();
        int outputDevice = outputDeviceCombo->currentData().toInt();

        if (audioManager->startListening(localPortSpin->value(), key, inputDevice, outputDevice)) {
            statusLabel->setText("Listening started");
        }
    }

    void onStopCall() {
        audioManager->stopCall();
        statusLabel->setText("Call stopped");
    }

    void onCallStarted() {
        callButton->setEnabled(false);
        listenButton->setEnabled(false);
        stopButton->setEnabled(true);
    }

    void onCallStopped() {
        callButton->setEnabled(true);
        listenButton->setEnabled(true);
        stopButton->setEnabled(false);
    }

    void onError(const QString &error) {
        outputText->append("Error: " + error);
        statusLabel->setText("Error: " + error.left(30));
    }

    void onOutput(const QString &output) {
        outputText->append(output);
    }

private:
    void setupUI() {
        QVBoxLayout *layout = new QVBoxLayout(this);

        // Key section
        QGroupBox *keyGroup = new QGroupBox("Encryption Key", this);
        QHBoxLayout *keyLayout = new QHBoxLayout(keyGroup);
        keyEdit = new QLineEdit(keyGroup);
        keyEdit->setPlaceholderText("32-byte hex key");
        genKeyButton = new QPushButton("Generate", keyGroup);
        keyLayout->addWidget(keyEdit);
        keyLayout->addWidget(genKeyButton);
        layout->addWidget(keyGroup);

        // Audio devices section
        QGroupBox *devicesGroup = new QGroupBox("Audio Devices", this);
        QGridLayout *devicesLayout = new QGridLayout(devicesGroup);

        devicesLayout->addWidget(new QLabel("Input device:"), 0, 0);
        inputDeviceCombo = new QComboBox(devicesGroup);
        devicesLayout->addWidget(inputDeviceCombo, 0, 1);

        devicesLayout->addWidget(new QLabel("Output device:"), 1, 0);
        outputDeviceCombo = new QComboBox(devicesGroup);
        devicesLayout->addWidget(outputDeviceCombo, 1, 1);

        refreshDevicesButton = new QPushButton("Refresh Devices", devicesGroup);
        devicesLayout->addWidget(refreshDevicesButton, 2, 0, 1, 2);

        layout->addWidget(devicesGroup);

        // Connection section
        QGroupBox *connGroup = new QGroupBox("Connection", this);
        QGridLayout *connLayout = new QGridLayout(connGroup);

        connLayout->addWidget(new QLabel("Remote IP:"), 0, 0);
        ipEdit = new QLineEdit(connGroup);
        ipEdit->setText("127.0.0.1");
        connLayout->addWidget(ipEdit, 0, 1);

        connLayout->addWidget(new QLabel("Remote Port:"), 1, 0);
        portSpin = new QSpinBox(connGroup);
        portSpin->setRange(1024, 65535);
        portSpin->setValue(50000);
        connLayout->addWidget(portSpin, 1, 1);

        connLayout->addWidget(new QLabel("Local Port:"), 2, 0);
        localPortSpin = new QSpinBox(connGroup);
        localPortSpin->setRange(1024, 65535);
        localPortSpin->setValue(50001);
        connLayout->addWidget(localPortSpin, 2, 1);

        layout->addWidget(connGroup);

        // Buttons
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        callButton = new QPushButton("Start Call", this);
        listenButton = new QPushButton("Start Listening", this);
        stopButton = new QPushButton("Stop", this);
        stopButton->setEnabled(false);

        buttonLayout->addWidget(callButton);
        buttonLayout->addWidget(listenButton);
        buttonLayout->addWidget(stopButton);
        layout->addLayout(buttonLayout);

        // Status
        statusLabel = new QLabel("Ready", this);
        layout->addWidget(statusLabel);

        // Output
        outputText = new QTextEdit(this);
        outputText->setReadOnly(true);
        layout->addWidget(outputText);
    }

    void setupConnections() {
        // Подключаем сигналы от менеджера аудио
        connect(audioManager, &AudioCallManager::keyGenerated, this, &AudioCallDialog::onKeyGenerated);
        connect(audioManager, &AudioCallManager::callStarted, this, &AudioCallDialog::onCallStarted);
        connect(audioManager, &AudioCallManager::listeningStarted, this, &AudioCallDialog::onCallStarted);
        connect(audioManager, &AudioCallManager::callStopped, this, &AudioCallDialog::onCallStopped);
        connect(audioManager, &AudioCallManager::error, this, &AudioCallDialog::onError);
        connect(audioManager, &AudioCallManager::output, this, &AudioCallDialog::onOutput);

        // Подключаем кнопки UI
        connect(genKeyButton, &QPushButton::clicked, this, &AudioCallDialog::onGenerateKey);
        connect(refreshDevicesButton, &QPushButton::clicked, this, &AudioCallDialog::refreshAudioDevices);
        connect(callButton, &QPushButton::clicked, this, &AudioCallDialog::onStartCall);
        connect(listenButton, &QPushButton::clicked, this, &AudioCallDialog::onStartListening);
        connect(stopButton, &QPushButton::clicked, this, &AudioCallDialog::onStopCall);
    }

    AudioCallManager *audioManager;
    QLineEdit *keyEdit;
    QLineEdit *ipEdit;
    QSpinBox *portSpin;
    QSpinBox *localPortSpin;
    QComboBox *inputDeviceCombo;
    QComboBox *outputDeviceCombo;
    QPushButton *genKeyButton;
    QPushButton *refreshDevicesButton;
    QPushButton *callButton;
    QPushButton *listenButton;
    QPushButton *stopButton;
    QLabel *statusLabel;
    QTextEdit *outputText;

    void refreshAudioDevices() {
        QString audioAppPath = findAudioCallApp();
        if (audioAppPath.isEmpty()) {
            outputText->append("Audio call application not found");
            return;
        }

        QProcess process;
        process.start(audioAppPath, QStringList() << "listdevices");

        if (!process.waitForFinished(5000)) {
            outputText->append("Failed to get audio devices list");
            return;
        }

        QString output = QString::fromUtf8(process.readAllStandardOutput());

        // Парсим вывод
        inputDeviceCombo->clear();
        outputDeviceCombo->clear();

        inputDeviceCombo->addItem("Default", -1);
        outputDeviceCombo->addItem("Default", -1);

        QStringList lines = output.split('\n');
        for (const QString &line : lines) {
            // Ищем строки вида "Device N: Name"
            if (line.contains("Device ") && line.contains(":")) {
                QStringList parts = line.split(':');
                if (parts.size() >= 2) {
                    QString devicePart = parts[0].trimmed();
                    QString namePart = parts[1].trimmed();

                    // Извлекаем номер устройства
                    QStringList deviceWords = devicePart.split(' ');
                    if (deviceWords.size() >= 2) {
                        bool ok;
                        int deviceId = deviceWords[1].toInt(&ok);
                        if (ok) {
                            // Проверяем на следующих строках, есть ли input/output каналы
                            inputDeviceCombo->addItem(namePart, deviceId);
                            outputDeviceCombo->addItem(namePart, deviceId);
                        }
                    }
                }
            }
        }

        outputText->append(QString("Found %1 audio devices").arg(inputDeviceCombo->count() - 1));
    }

    QString findAudioCallApp() {
        QStringList possiblePaths = {
            QApplication::applicationDirPath() + "/audio_call",
            QApplication::applicationDirPath() + "/bin/audio_call",
            QApplication::applicationDirPath() + "/../bin/audio_call",
            "audio_call",
            "./audio_call"
        };

#ifdef Q_OS_WIN
        for (QString &path : possiblePaths) {
            path += ".exe";
        }
#endif

        for (const QString &path : possiblePaths) {
            if (QFile::exists(path)) {
                return path;
            }
        }

        return QString();
    }
};

class Backend : public QObject {
    Q_OBJECT
public:
    Backend(QObject *parent = nullptr) : QObject(parent) {
        settings = new QSettings("fear-messenger", "fear-gui", this);
        cliPath = settings->value("cli/path", "fear.exe").toString();
        clientProc = nullptr;
        serverProc = nullptr;
        lastMessageId = 0;
        isConnected = false;

        // Инициализация менеджера аудиозвонков
        audioManager = new AudioCallManager(this);
    }

    ~Backend(){
        if(clientProc){
            clientProc->kill();
            clientProc->waitForFinished(200);
            delete clientProc;
        }
        if(serverProc){
            serverProc->kill();
            serverProc->waitForFinished(200);
            delete serverProc;
        }
    }

    QString cliPath;
    bool isConnected;
    AudioCallManager *audioManager;

    void setCliPath(const QString &path){
        cliPath = path;
        settings->setValue("cli/path", path);
    }

    bool connectToServer(const QString &host, int port, const QString &room, const QString &key, const QString &name){
        if(clientProc){
            qWarning() << "Client already running";
            return false;
        }

        // Проверяем, существует ли исполняемый файл
        if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
            QString defaultPath = "./bin/fear.exe";
            if (!QFile::exists(defaultPath)) {
                emit error("CLI executable not found. Please set the correct path to fear.exe");
                return false;
            }
            cliPath = defaultPath;
        }

        clientProc = new QProcess(this);
        clientProc->setProcessChannelMode(QProcess::MergedChannels);
        connect(clientProc, &QProcess::readyReadStandardOutput, this, &Backend::onClientStdout);
        connect(clientProc, &QProcess::readyReadStandardError, this, &Backend::onClientStderr);
        connect(clientProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &Backend::onClientFinished);

        QStringList args;
        args << "client" << "--host" << host << "--port" << QString::number(port)
             << "--room" << room << "--key" << key << "--name" << name;

        qDebug() << "Starting client:" << cliPath << args;

        // Устанавливаем переменные окружения
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        clientProc->setProcessEnvironment(env);

        clientProc->start(cliPath, args);
        if(!clientProc->waitForStarted(3000)){
            QString errorMsg = QString("Failed to start client process: %1 %2").arg(cliPath).arg(args.join(" "));
            qWarning() << errorMsg;
            emit error(errorMsg);
            delete clientProc;
            clientProc = nullptr;
            return false;
        }

        // Изменение: сразу считаем подключение успешным после запуска процесса
        isConnected = true;
        emit connected();
        return true;
    }

    bool createServer(int port, const QString &name){
        Q_UNUSED(name);
        if(serverProc){
            qWarning() << "Server already running";
            return false;
        }

        // Проверяем, существует ли исполняемый файл
        if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
            QString defaultPath = "fear.exe";
            if (!QFile::exists(defaultPath)) {
                emit error("CLI executable not found. Please set the correct path to fear.exe");
                return false;
            }
            cliPath = defaultPath;
        }

        serverProc = new QProcess(this);
        serverProc->setProcessChannelMode(QProcess::MergedChannels);
        connect(serverProc, &QProcess::readyReadStandardOutput, this, &Backend::onServerStdout);
        connect(serverProc, &QProcess::readyReadStandardError, this, &Backend::onServerStderr);
        connect(serverProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &Backend::onServerFinished);

        QStringList args;
        args << "server" << "--port" << QString::number(port);

        qDebug() << "Starting server:" << cliPath << args;

        // Устанавливаем переменные окружения
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        serverProc->setProcessEnvironment(env);

        serverProc->start(cliPath, args);
        if(!serverProc->waitForStarted(3000)){
            QString errorMsg = QString("Failed to start server: %1 %2").arg(cliPath).arg(args.join(" "));
            qWarning() << errorMsg;
            emit error(errorMsg);
            delete serverProc;
            serverProc = nullptr;
            return false;
        }

        // Ждем дольше для запуска сервера
        if(serverProc->waitForReadyRead(5000)){
            QByteArray chunk = serverProc->readAllStandardOutput();
            QString s = QString::fromLocal8Bit(chunk);
            qDebug() << "Server output:" << s;

            if(s.contains("listening", Qt::CaseInsensitive) ||
                s.contains("started", Qt::CaseInsensitive) ||
                s.contains("running", Qt::CaseInsensitive) ||
                s.contains("port", Qt::CaseInsensitive)){
                emit serverCreated();
                return true;
            } else if (s.contains("error", Qt::CaseInsensitive) ||
                       s.contains("fail", Qt::CaseInsensitive)) {
                emit error(s);
                return false;
            }
        }

        // Если не получили ожидаемый вывод, но процесс работает, считаем успехом
        if (serverProc->state() == QProcess::Running) {
            emit serverCreated();
            return true;
        }

        QString errorMsg = "Server failed to start properly";
        qWarning() << errorMsg;
        emit error(errorMsg);
        return false;
    }

    bool disconnect(){
        if(clientProc){
            clientProc->terminate();
            if(!clientProc->waitForFinished(1000)){
                clientProc->kill();
                clientProc->waitForFinished(500);
            }
            delete clientProc;
            clientProc = nullptr;
        }
        if(serverProc){
            serverProc->terminate();
            if(!serverProc->waitForFinished(1000)){
                serverProc->kill();
                serverProc->waitForFinished(500);
            }
            delete serverProc;
            serverProc = nullptr;
        }
        isConnected = false;
        emit disconnected();
        return true;
    }

    bool sendMessage(const QString &contact, const QString &message){
        Q_UNUSED(contact);
        if(!clientProc || !isConnected) return false;

        QByteArray data = message.toLocal8Bit();
        data.append('\n');
        qint64 written = clientProc->write(data);

        if(written == -1) {
            qWarning() << "Failed to write to client process";
            return false;
        }

        bool bytesWritten = clientProc->waitForBytesWritten(1000);
        if(!bytesWritten) {
            qWarning() << "Failed to wait for bytes written";
        }

        return written > 0 && bytesWritten;
    }

    QStringList listContacts(){
        return QStringList();
    }

    QStringList getRecentMessages(int &outLastId){
        Q_UNUSED(outLastId);
        return QStringList();
    }

    bool generateKeypair(const QString &outPath){
        // Проверяем, существует ли исполняемый файл
        if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
            QString defaultPath = "fear.exe";
            if (!QFile::exists(defaultPath)) {
                emit error("CLI executable not found. Please set the correct path to fear.exe");
                return false;
            }
            cliPath = defaultPath;
        }

        QProcess p;
        p.start(cliPath, QStringList() << "genkey");

        if(!p.waitForStarted(2000)){
            emit error("Failed to start genkey process");
            return false;
        }

        if(!p.waitForFinished(5000)){
            emit error("Genkey process timed out");
            p.kill();
            return false;
        }

        QString out = QString::fromLocal8Bit(p.readAllStandardOutput());
        QString err = QString::fromLocal8Bit(p.readAllStandardError());

        qDebug() << "Genkey output:" << out;
        qDebug() << "Genkey error:" << err;

        // The output typically contains a line with the base64 key
        QRegularExpression re("([A-Za-z0-9_\\-]{20,})");
        QRegularExpressionMatch m = re.match(out);
        QString key;

        if(m.hasMatch()) {
            key = m.captured(1);
        } else {
            // Try to find key in error output if not in stdout
            m = re.match(err);
            if(m.hasMatch()) {
                key = m.captured(1);
            }
        }

        if(!outPath.isEmpty()){
            QFile f(outPath);
            if(f.open(QIODevice::WriteOnly)){
                f.write(out.toUtf8());
                f.close();
            }
        }

        if(!key.isEmpty()){
            emit keyGenerated(key);
            return true;
        }

        emit error("Failed to extract key from genkey output");
        return false;
    }

signals:
    void connected();
    void disconnected();
    void serverCreated();
    void keyGenerated(const QString &key);
    void contactsUpdated(const QStringList &contacts);
    void newMessages(const QStringList &messages);
    void error(const QString &error);

private slots:
    void onClientStdout(){
        if(!clientProc) return;

        QByteArray chunk = clientProc->readAllStandardOutput();
        QString s = QString::fromLocal8Bit(chunk);
        qDebug() << "Client stdout:" << s;

        parseClientOutput(s);
    }

    void onClientStderr(){
        if(!clientProc) return;

        QByteArray chunk = clientProc->readAllStandardError();
        QString s = QString::fromLocal8Bit(chunk);
        qDebug() << "Client stderr:" << s;

        // Если есть ошибки в stderr, отправляем их как ошибки
        if(!s.trimmed().isEmpty()) {
            emit error(s);
        }
    }

    void onClientFinished(int exitCode, QProcess::ExitStatus status){
        isConnected = false;
        qDebug() << "Client process finished with exit code:" << exitCode << "status:" << status;

        // Очищаем указатель на процесс, чтобы можно было повторно подключиться
        if(clientProc) {
            clientProc->deleteLater();
            clientProc = nullptr;
        }

        emit disconnected();

        // Не показываем ошибку - процесс мог быть остановлен пользователем через disconnect
        // Ошибки будут приходить через stderr если они есть
        Q_UNUSED(exitCode);
        Q_UNUSED(status);
    }

    void onServerStdout(){
        if(!serverProc) return;

        QByteArray chunk = serverProc->readAllStandardOutput();
        QString s = QString::fromLocal8Bit(chunk);
        qDebug() << "Server stdout:" << s;

        QStringList lines = s.split('\n', Qt::SkipEmptyParts);
        for(const QString &l : lines){
            QString t = l.trimmed();
            if(t.isEmpty()) continue;

            emit newMessages(QStringList() << QString("[server] %1").arg(t));

            if(t.contains("listening", Qt::CaseInsensitive)){
                emit serverCreated();
            }
        }
    }

    void onServerStderr(){
        if(!serverProc) return;

        QByteArray chunk = serverProc->readAllStandardError();
        QString s = QString::fromLocal8Bit(chunk);
        qDebug() << "Server stderr:" << s;

        // Если есть ошибки в stderr, отправляем их как ошибки
        if(!s.trimmed().isEmpty()) {
            emit error(s);
        }
    }

    void onServerFinished(int exitCode, QProcess::ExitStatus status){
        Q_UNUSED(exitCode);
        Q_UNUSED(status);

        qDebug() << "Server process finished";
        emit newMessages(QStringList() << "[server] stopped");
    }

private:
    QSettings *settings;
    QProcess *clientProc;
    QProcess *serverProc;
    int lastMessageId;

    void parseClientOutput(const QString &s){
        if(s.isEmpty()) return;

        QStringList lines = s.split('\n', Qt::SkipEmptyParts);
        QStringList out;

        for(const QString &l : lines){
            QString t = l.trimmed();
            if(t.isEmpty()) continue;

            // Check for user list messages
            if(t.startsWith("[USERS]")) {
                // Парсим список участников: "[USERS] Room participants (2): Alice, Bob"
                QRegularExpression re("\\[USERS\\].*?:\\s*(.+)$");
                QRegularExpressionMatch m = re.match(t);
                if(m.hasMatch()) {
                    QString userListStr = m.captured(1).trimmed();
                    QStringList users = userListStr.split(',', Qt::SkipEmptyParts);

                    // Очищаем имена от пробелов
                    for(QString &user : users) {
                        user = user.trimmed();
                    }

                    emit contactsUpdated(users);
                }
                // Не добавляем это в out, чтобы не показывать в чате
                continue;
            }

            // Check for error messages
            if(t.contains("error", Qt::CaseInsensitive) ||
                t.contains("fail", Qt::CaseInsensitive) ||
                t.contains("cannot", Qt::CaseInsensitive)) {
                emit error(t);
            }

            // Pass through typical client messages
            out << t;
        }

        if(!out.isEmpty()) {
            emit newMessages(out);
        }
    }
};

class UpdateDialog : public QDialog {
    Q_OBJECT
public:
    UpdateDialog(QWidget *parent = nullptr, const QString &cliPath = "")
        : QDialog(parent), m_cliPath(cliPath) {
        setWindowTitle("Check for Updates");
        setMinimumSize(600, 500);

        QVBoxLayout *layout = new QVBoxLayout(this);

        // Заголовок
        QLabel *titleLabel = new QLabel("F.E.A.R. Messenger - Version Information", this);
        titleLabel->setStyleSheet("font-size: 14px;");
        layout->addWidget(titleLabel);

        // Текстовое поле для вывода информации о версии
        m_versionText = new QTextEdit(this);
        m_versionText->setReadOnly(true);
        m_versionText->setPlaceholderText("Click 'Check Version' to get version information...");
        layout->addWidget(m_versionText);

        // Статус
        m_statusLabel = new QLabel("Ready to check version", this);
        layout->addWidget(m_statusLabel);

        // Кнопки
        QHBoxLayout *buttonLayout = new QHBoxLayout();

        m_checkButton = new QPushButton("Check Version", this);
        m_updateButton = new QPushButton("Update", this);
        QPushButton *closeButton = new QPushButton("Close", this);

        m_updateButton->setEnabled(false);

        buttonLayout->addWidget(m_checkButton);
        buttonLayout->addWidget(m_updateButton);
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);

        // Подключаем сигналы
        connect(m_checkButton, &QPushButton::clicked, this, &UpdateDialog::checkVersion);
        connect(m_updateButton, &QPushButton::clicked, this, &UpdateDialog::runUpdater);
        connect(closeButton, &QPushButton::clicked, this, &UpdateDialog::accept);

        // Инициализируем процесс
        m_updaterProcess = nullptr;
    }

    ~UpdateDialog() {
        if (m_updaterProcess) {
            if (m_updaterProcess->state() == QProcess::Running) {
                m_updaterProcess->kill();
                m_updaterProcess->waitForFinished(1000);
            }
            m_updaterProcess->deleteLater();
        }
    }

    void setCliPath(const QString &path) {
        m_cliPath = path;
    }

private slots:
    void checkVersion() {
        m_statusLabel->setText("Checking version...");
        m_versionText->setPlainText("Please wait while checking version...");
        m_updateButton->setEnabled(false);
        m_checkButton->setEnabled(false);

        // Даем GUI обновиться
        QApplication::processEvents();

        QString fearPath = m_cliPath;
        if (fearPath.isEmpty() || !QFile::exists(fearPath)) {
            fearPath = "./bin/fear.exe";
            if (!QFile::exists(fearPath)) {
                fearPath = "fear.exe";
            }
        }

        if (!QFile::exists(fearPath)) {
            m_versionText->setPlainText("Error: fear.exe not found!\n"
                                        "Searched paths:\n"
                                        "- " + m_cliPath + "\n"
                                                      "- ./bin/fear.exe\n"
                                                      "- fear.exe\n\n"
                                                      "Please set the correct CLI path in File -> Set CLI path...");
            m_statusLabel->setText("Error: fear.exe not found");
            m_checkButton->setEnabled(true);
            return;
        }

        QProcess *process = new QProcess(this);
        process->start(fearPath, QStringList() << "--version");

        if (!process->waitForStarted(3000)) {
            m_versionText->setPlainText("Error: Failed to start fear.exe process\n"
                                        "Path: " + fearPath);
            m_statusLabel->setText("Error: Process failed to start");
            process->deleteLater();
            m_checkButton->setEnabled(true);
            return;
        }

        if (!process->waitForFinished(10000)) {
            m_versionText->setPlainText("Error: Process timed out after 10 seconds");
            m_statusLabel->setText("Error: Process timed out");
            process->kill();
            process->waitForFinished(1000);
            process->deleteLater();
            m_checkButton->setEnabled(true);
            return;
        }

        QString output = QString::fromLocal8Bit(process->readAllStandardOutput());
        QString error = QString::fromLocal8Bit(process->readAllStandardError());

        if (process->exitCode() != 0) {
            m_versionText->setPlainText(QString("Error: Process exited with code %1\n\nError output:\n%2\n\nStandard output:\n%3")
                                            .arg(process->exitCode()).arg(error).arg(output));
            m_statusLabel->setText("Error: Process failed");
            process->deleteLater();
            m_checkButton->setEnabled(true);
            return;
        }

        // Парсим версию
        QString currentVersion = parseVersion(output);
        m_currentVersion = currentVersion;

        QString versionInfo = QString("Current F.E.A.R. version: %1\n\nFull output:\n%2")
                                  .arg(currentVersion.isEmpty() ? "Unknown" : currentVersion)
                                  .arg(output);

        m_versionText->setPlainText(versionInfo);

        // Включаем кнопку обновления
        m_updateButton->setEnabled(true);
        m_checkButton->setEnabled(true);
        m_statusLabel->setText(currentVersion.isEmpty() ? "Version unknown" : "Version: " + currentVersion);

        process->deleteLater();
    }

    void runUpdater() {
        QString updaterPath = "./bin/updater.exe";
        QFileInfo updaterInfo(updaterPath);

        if (!updaterInfo.exists()) {
            QMessageBox::warning(this, "Update Error",
                                 "Updater not found at: " + updaterPath +
                                     "\nPlease download the updater manually from GitHub.");
            return;
        }

        // Получаем абсолютный путь к каталогу с updater.exe
        QString updaterDir = updaterInfo.absolutePath();

        if (QMessageBox::question(this, "Confirm Update",
                                  "The updater will now start. This may take several minutes.\n"
                                  "Do you want to continue?") != QMessageBox::Yes) {
            return;
        }

        // Отключаем кнопки во время обновления
        m_updateButton->setEnabled(false);
        m_checkButton->setEnabled(false);
        m_statusLabel->setText("Running updater...");

        // Очищаем текстовое поле и показываем вывод updater
        m_versionText->clear();
        m_versionText->setPlainText("Starting updater...\n\n");

        // Создаем процесс для updater
        m_updaterProcess = new QProcess(this);
        m_updaterProcess->setWorkingDirectory(updaterDir);
        m_updaterProcess->setProcessChannelMode(QProcess::MergedChannels);

        // Подключаем сигналы для чтения вывода
        connect(m_updaterProcess, &QProcess::readyRead, this, &UpdateDialog::onUpdaterOutput);
        connect(m_updaterProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &UpdateDialog::onUpdaterFinished);

        // Запускаем процесс
        m_updaterProcess->start(updaterInfo.absoluteFilePath());

        if (!m_updaterProcess->waitForStarted(3000)) {
            m_versionText->append("Error: Failed to start updater process");
            m_statusLabel->setText("Error: Updater failed to start");
            cleanupUpdaterProcess();
            return;
        }

        m_versionText->append("Updater started successfully. Waiting for output...\n");
    }

    void onUpdaterOutput() {
        if (!m_updaterProcess) return;

        QByteArray output = m_updaterProcess->readAll();
        QString text = QString::fromLocal8Bit(output);

        // Добавляем вывод в текстовое поле
        m_versionText->insertPlainText(text);

        // Прокручиваем вниз
        QTextCursor cursor = m_versionText->textCursor();
        cursor.movePosition(QTextCursor::End);
        m_versionText->setTextCursor(cursor);

        // Обрабатываем вывод
        QApplication::processEvents();
    }

    void onUpdaterFinished(int exitCode, QProcess::ExitStatus exitStatus) {
        Q_UNUSED(exitStatus);

        m_versionText->append(QString("\n\nUpdater finished with exit code: %1").arg(exitCode));

        if (exitCode == 0) {
            m_versionText->append("Update completed successfully!");
            m_statusLabel->setText("Update completed");

            // Автоматический перезапуск с подтверждением
            m_versionText->append("Update completed! The application needs to restart to apply changes.");
            QApplication::processEvents();

            if (QMessageBox::information(this, "Update Complete",
                                         "Update completed successfully!\n"
                                         "The application will now restart to apply the changes.",
                                         QMessageBox::Ok) == QMessageBox::Ok) {
                restartApplication();
            } else {
                cleanupUpdaterProcess();
            }

        } else {
            m_versionText->append("Update failed or was cancelled.");
            m_statusLabel->setText("Update failed");

            QMessageBox::warning(this, "Update Failed",
                                 QString("Updater exited with code %1. Please check the output above for details.")
                                     .arg(exitCode));

            cleanupUpdaterProcess();
        }
    }

private:
    QString m_cliPath;
    QString m_currentVersion;
    QTextEdit *m_versionText;
    QLabel *m_statusLabel;
    QPushButton *m_checkButton;
    QPushButton *m_updateButton;
    QProcess *m_updaterProcess;

    void restartApplication() {
        qDebug() << "Restarting application...";

        // Получаем путь к текущему исполняемому файлу
        QString program = QApplication::applicationFilePath();
        QStringList arguments = QApplication::arguments();
        QString workingDir = QApplication::applicationDirPath();

        // Убираем возможные дубликаты аргументов
        if (!arguments.isEmpty() && arguments.first() == program) {
            arguments.removeFirst();
        }

        // Запускаем новую копию приложения
        bool started = QProcess::startDetached(program, arguments, workingDir);

        if (started) {
            qDebug() << "New instance started successfully, closing current instance";
            QApplication::quit();
        } else {
            qDebug() << "Failed to restart application";
            QMessageBox::warning(this, "Restart Failed",
                                 "Failed to restart the application. Please restart it manually.");
            cleanupUpdaterProcess();
        }
    }

    void cleanupUpdaterProcess() {
        if (m_updaterProcess) {
            if (m_updaterProcess->state() == QProcess::Running) {
                m_updaterProcess->kill();
                m_updaterProcess->waitForFinished(1000);
            }
            m_updaterProcess->deleteLater();
            m_updaterProcess = nullptr;
        }
        m_updateButton->setEnabled(true);
        m_checkButton->setEnabled(true);
    }

    QString parseVersion(const QString &output) {
        // Ищем строку с версией программы
        QRegularExpression re("Program version:\\s*([0-9]+\\.[0-9]+\\.[0-9]+)");
        QRegularExpressionMatch match = re.match(output);

        if (match.hasMatch()) {
            return match.captured(1).trimmed();
        }

        // Альтернативные форматы
        re.setPattern("version\\s*([0-9]+\\.[0-9]+\\.[0-9]+)");
        match = re.match(output);

        if (match.hasMatch()) {
            return match.captured(1).trimmed();
        }

        re.setPattern("([0-9]+\\.[0-9]+\\.[0-9]+)");
        match = re.match(output);

        if (match.hasMatch()) {
            return match.captured(1).trimmed();
        }

        return QString();
    }
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent){
        setWindowTitle("F.E.A.R. Project GUI");
        resize(1000, 640);

        appSettings = new QSettings("fear-messenger", "fear-gui", this);
        backend = new Backend(this);

        // Инициализация шрифта чата
        chatFont = QFont("Arial", 10);

        createActions();
        createMenus();
        createToolbar();
        createCentral();
        createStatusBar();

        // Connect backend signals
        connect(backend, &Backend::contactsUpdated, this, &MainWindow::onContactsUpdated);
        connect(backend, &Backend::newMessages, this, &MainWindow::onNewMessages);
        connect(backend, &Backend::connected, this, [this](){
            statusLabel->setText("Connected");
            connectAction->setEnabled(false);
            disconnectAction->setEnabled(true);
        });
        connect(backend, &Backend::disconnected, this, [this](){
            statusLabel->setText("Disconnected");
            connectAction->setEnabled(true);
            disconnectAction->setEnabled(false);
            contactsWidget->clear();  // Очищаем список участников при отключении
        });
        connect(backend, &Backend::serverCreated, this, &MainWindow::onServerStarted);
        connect(backend, &Backend::keyGenerated, this, &MainWindow::onKeyGenerated);
        connect(backend, &Backend::error, this, &MainWindow::onError);

        // initial refresh of contacts (non-blocking attempt)
        QTimer::singleShot(100, this, &MainWindow::refreshContacts);
    }
public:
    QString getCliPath() const {
        return backend->cliPath;
    }

protected:
    void keyPressEvent(QKeyEvent *event) override {
        if (event->key() == Qt::Key_F1) {
            onOpenDocumentation();
        }
        QMainWindow::keyPressEvent(event);
    }

private slots:

void onSendFile() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select file to send", QDir::homePath());
    if (filePath.isEmpty()) {
        return;
    }

    // Проверяем существование файла
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        QMessageBox::warning(this, "Send File", "Selected file does not exist or is not a valid file.");
        return;
    }

    // Получаем абсолютный путь (на случай относительных путей)
    QString absolutePath = QDir::toNativeSeparators(fileInfo.absoluteFilePath());
    
    // Формируем команду для отправки
    QString command = QString("/sendfile %1").arg(absolutePath);
    
    // Отправляем команду через бэкенд
    QString contact = currentContact();
    bool ok = backend->sendMessage(contact, command);

    if (ok) {
        // Получаем имя пользователя из настроек
        QString userName = appSettings->value("last/name", "Me").toString();
        if (userName.isEmpty()) {
            userName = "Me";
        }
        // Показываем в чате что команда отправлена
        appendChatLine(QString("[%1] %2: /sendfile \"%3\"")
                      .arg(QDateTime::currentDateTime().toString("HH:mm:ss"), 
                           userName, 
                           fileInfo.fileName()));
        
        // Не показываем сообщение об успехе, чтобы не мешать
        qDebug() << "File send command sent:" << command;
    } else {
        QMessageBox::warning(this, "Send File", 
            "Failed to send file command. Check connection.");
    }
}

    void onClearChat() {
        if (QMessageBox::question(this, "Clear Chat", 
            "Are you sure you want to clear the chat history?",
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
            chatView->clear();
        }
    }

    void onFontSettings() {
        bool ok;
        QFont font = QFontDialog::getFont(&ok, chatFont, this, "Select Chat Font");
        if (ok) {
            chatFont = font;
            chatView->setFont(chatFont);
            appSettings->setValue("chat/font", chatFont.toString());
        }
    }

    void onAudioCall() {
        AudioCallDialog dialog(backend->audioManager, this);
        dialog.exec();
    }

    void onKeyExchange() {
        KeyExchangeDialog dlg(this);
        dlg.exec();
    }

    void onCreateServer(){
        // Создаем диалоговое окно для настройки сервера
        QDialog dialog(this);
        dialog.setWindowTitle("Create Server");
        dialog.setMinimumWidth(400);
        
        QFormLayout *formLayout = new QFormLayout(&dialog);
        
        // Порт сервера
        QSpinBox *portSpin = new QSpinBox(&dialog);
        portSpin->setRange(1, 65535);
        portSpin->setValue(appSettings->value("last/port", 7777).toInt());
        formLayout->addRow("Port:", portSpin);
        
        // Кнопки
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *createButton = new QPushButton("Create Server", &dialog);
        QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
        buttonLayout->addWidget(createButton);
        buttonLayout->addWidget(cancelButton);
        
        formLayout->addRow(buttonLayout);
        
        // Подключаем кнопки
        connect(createButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);
        
        // Показываем диалог
        if (dialog.exec() == QDialog::Accepted) {
            int port = portSpin->value();
            
            // Показываем индикатор прогресса
            QProgressDialog progress("Creating server...", "Cancel", 0, 0, this);
            progress.setWindowModality(Qt::WindowModal);
            progress.show();
            QApplication::processEvents();
            
            bool success = backend->createServer(port, "Server");
            
            progress.close();
            
            if(success){
                appSettings->setValue("last/port", port);
                QMessageBox::information(this, "Create Server", "Server created successfully.");
            } else {
                QMessageBox::warning(this, "Create Server", "Failed to create server. Check if port is available and CLI path is correct.");
            }
        }
    }

    void onConnect(){
        // Создаем диалоговое окно для подключения
        QDialog dialog(this);
        dialog.setWindowTitle("Connect to Server");
        dialog.setMinimumWidth(500);
        
        QFormLayout *formLayout = new QFormLayout(&dialog);
        
        // Хост
        QLineEdit *hostEdit = new QLineEdit(&dialog);
        hostEdit->setText(appSettings->value("last/host", "127.0.0.1").toString());
        formLayout->addRow("Host:", hostEdit);
        
        // Порт
        QSpinBox *portSpin = new QSpinBox(&dialog);
        portSpin->setRange(1, 65535);
        portSpin->setValue(appSettings->value("last/port", 7777).toInt());
        formLayout->addRow("Port:", portSpin);
        
        // Комната
        QLineEdit *roomEdit = new QLineEdit(&dialog);
        roomEdit->setText(appSettings->value("last/room", "testroom").toString());
        formLayout->addRow("Room name:", roomEdit);
        
        // Ключ комнаты - ОБЫЧНЫЙ РЕЖИМ (не скрытый)
        QLineEdit *keyEdit = new QLineEdit(&dialog);
        keyEdit->setText(appSettings->value("last/key", "").toString());
        // Убрано: keyEdit->setEchoMode(QLineEdit::Password);
        formLayout->addRow("Room key:", keyEdit);
        
        // Имя пользователя
        QLineEdit *nameEdit = new QLineEdit(&dialog);
        nameEdit->setText(appSettings->value("last/name", "").toString());
        formLayout->addRow("Your name:", nameEdit);
        
        // Кнопки
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *connectButton = new QPushButton("Connect", &dialog);
        QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
        buttonLayout->addWidget(connectButton);
        buttonLayout->addWidget(cancelButton);
        
        formLayout->addRow(buttonLayout);
        
        // Подключаем кнопки
        connect(connectButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);
        
        // Показываем диалог
        if (dialog.exec() == QDialog::Accepted) {
            QString host = hostEdit->text().trimmed();
            int port = portSpin->value();
            QString room = roomEdit->text().trimmed();
            QString key = keyEdit->text().trimmed();
            QString name = nameEdit->text().trimmed();
            
            // Валидация введенных данных
            if (host.isEmpty()) {
                QMessageBox::warning(this, "Connect", "Host cannot be empty.");
                return;
            }
            
            if (room.isEmpty()) {
                QMessageBox::warning(this, "Connect", "Room name cannot be empty.");
                return;
            }
            
            if (key.isEmpty()) {
                QMessageBox::warning(this, "Connect", "Room key is required to join private rooms.");
                return;
            }
            
            if (name.isEmpty()) {
                QMessageBox::warning(this, "Connect", "Your name cannot be empty.");
                return;
            }
            
            // Показываем индикатор прогресса
            QProgressDialog progress("Connecting to server...", "Cancel", 0, 0, this);
            progress.setWindowModality(Qt::WindowModal);
            progress.show();
            QApplication::processEvents();
            
            bool success = backend->connectToServer(host, port, room, key, name);
            
            progress.close();
            
            if(success){
                appSettings->setValue("last/host", host);
                appSettings->setValue("last/port", port);
                appSettings->setValue("last/room", room);
                appSettings->setValue("last/key", key);
                appSettings->setValue("last/name", name);
                QMessageBox::information(this, "Connect", "Connected successfully.");
            } else {
                QMessageBox::warning(this, "Connect", "Failed to connect. Check server availability and credentials.");
            }
        }
    }

    void onDisconnect(){
        backend->disconnect();
        QMessageBox::information(this, "Disconnected", "Disconnected from server.");
    }

    void onSend(){
        QString message = inputEdit->text();
        if(message.isEmpty()) return;

        QString contact = currentContact();
        bool ok = backend->sendMessage(contact, message);

        if(ok){
            // appendChatLine(QString("[%1] Me: %2").arg(QDateTime::currentDateTime().toString("HH:mm:ss"), message));  // delete double massege
            inputEdit->clear();
        } else {
            QMessageBox::warning(this, "Send", "Failed to send message. Check connection.");
        }
    }

    void onContactsUpdated(const QStringList &contacts){
        contactsWidget->clear();
        contactsWidget->addItems(contacts);
    }

    void onNewMessages(const QStringList &messages){
        for(const QString &m : messages){
            appendChatLine(m);
        }
    }

    void onError(const QString &error){
        QMessageBox::warning(this, "Error", error);
        statusLabel->setText("Error: " + error.left(20) + "...");
    }

    void refreshContacts(){
        QStringList contacts = backend->listContacts();
        onContactsUpdated(contacts);
    }

    void onSelectContact(){
        QString contact = currentContact();
        chatView->clear();
    }

    void onSetCliPath(){
        QString file = QFileDialog::getOpenFileName(this, "Select CLI executable", QString(), "Executable files (*.exe);;All files (*)");
        if(file.isEmpty()) return;

        backend->setCliPath(file);
        appSettings->setValue("cli/path", file);
        QMessageBox::information(this, "CLI Path", QString("CLI set to: %1").arg(file));
    }

    void onGenKeys(){
        bool ok = backend->generateKeypair((QString)"");   // :toDo Fix workaround: window for file name was deleted but onGenKeys() method is still required
    }

    void onKeyGenerated(const QString &key){
        QDialog dlg(this);
        dlg.setWindowTitle("Generated room key");
        dlg.setMinimumWidth(400);
        QVBoxLayout *v = new QVBoxLayout(&dlg);
        QLabel *lbl = new QLabel("Room key (base64 urlsafe):", &dlg);
        v->addWidget(lbl);

        QLineEdit *keyEdit = new QLineEdit(key, &dlg);
        keyEdit->setReadOnly(true);
        keyEdit->setSelection(0, key.length());
        v->addWidget(keyEdit);

        QHBoxLayout *h = new QHBoxLayout();
        QPushButton *copyBtn = new QPushButton("Copy", &dlg);
        QPushButton *saveBtn = new QPushButton("Save to file...", &dlg);
        QPushButton *closeBtn = new QPushButton("Close", &dlg);

        h->addWidget(copyBtn);
        h->addWidget(saveBtn);
        h->addWidget(closeBtn);
        v->addLayout(h);

        connect(copyBtn, &QPushButton::clicked, this, [keyEdit](){
            QGuiApplication::clipboard()->setText(keyEdit->text());
            // QMessageBox::information(nullptr, "Copied", "Key copied to clipboard");
        });

        connect(saveBtn, &QPushButton::clicked, this, [&dlg, key](){
            QString file = QFileDialog::getSaveFileName(&dlg, "Save key to...", "roomkey.txt", "Text files (*.txt);;All files (*)");
            if(!file.isEmpty()){
                QFile f(file);
                if(f.open(QIODevice::WriteOnly)){
                    f.write(key.toUtf8());
                    f.close();
                    QMessageBox::information(&dlg, "Saved", "Key saved to file");
                }
            }
        });

        connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
        dlg.exec();
    }

    void onServerStarted(){
        statusLabel->setText("Server: listening");
        disconnectAction->setEnabled(true);
        appendChatLine("[server] listening");
    }

    void onOpenDocumentation() {
    QString docPath = QApplication::applicationDirPath() + "/doc/manual.pdf";
    if (QFile::exists(docPath)) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(docPath));
    } else {
        QMessageBox::information(this, "Documentation", 
            "Documentation file not found.\n\n"
            "Please download the user manual from:\n"
            "https://github.com/shchuchkin-pkims/fear");
    }

}

private:
    Backend *backend;
    QListWidget *contactsWidget;
    QTextEdit *chatView;
    QLineEdit *inputEdit;
    QLabel *statusLabel;
    QSettings *appSettings;

    QAction *connectAction;
    QAction *disconnectAction;
    
    // Добавляем новые члены для управления чатом
    QFont chatFont;
    QAction *clearChatAction;
    QAction *fontSettingsAction;
    QAction *sendFileAction;

    QString currentContact(){
        QListWidgetItem *it = contactsWidget->currentItem();
        return it ? it->text() : QString();
    }
    
    void createStatusBar() {  // Добавляем правильное объявление метода
        statusLabel = new QLabel("Disconnected", this);
        statusBar()->addPermanentWidget(statusLabel);
    }

    void appendChatLine(const QString &line){
        // Parse lines like: [16:54:43] Admin: message
        static QRegularExpression re("^\\s*\\[(\\d{2}:\\d{2}:\\d{2})\\]\\s*([^:]+):\\s*(.*)$");
        QRegularExpressionMatch m = re.match(line);

        if(m.hasMatch()){
            QString ts = m.captured(1);
            QString sender = m.captured(2).trimmed();
            QString msg = m.captured(3).trimmed();

            QString html = QString("<span style='color:gray'>[%1]</span> <b>%2:</b> %3")
                               .arg(ts.toHtmlEscaped(), sender.toHtmlEscaped(), msg.toHtmlEscaped());
            chatView->append(html);
        } else {
            // fallback: append raw escaped
            chatView->append(line.toHtmlEscaped());
        }
    }

    void createActions(){
        connectAction = new QAction("Connect", this);
        connect(connectAction, &QAction::triggered, this, &MainWindow::onConnect);

        disconnectAction = new QAction("Disconnect", this);
        connect(disconnectAction, &QAction::triggered, this, &MainWindow::onDisconnect);
        disconnectAction->setEnabled(false);

        clearChatAction = new QAction("Clear chat", this);
        connect(clearChatAction, &QAction::triggered, this, &MainWindow::onClearChat);

        fontSettingsAction = new QAction("Font settings", this);
        connect(fontSettingsAction, &QAction::triggered, this, &MainWindow::onFontSettings);

        sendFileAction = new QAction("Send file", this);
        connect(sendFileAction, &QAction::triggered, this, &MainWindow::onSendFile);
    }

    void createMenus(){
        QMenu *fileMenu = menuBar()->addMenu("File");
        QAction *setCli = new QAction("Set CLI path", this);
        connect(setCli, &QAction::triggered, this, &MainWindow::onSetCliPath);
        fileMenu->addAction(setCli);
        fileMenu->addSeparator();

        QAction *exitAct = new QAction("Exit", this);
        connect(exitAct, &QAction::triggered, this, &QWidget::close);
        fileMenu->addAction(exitAct);

        QMenu *connMenu = menuBar()->addMenu("Connection");
        connMenu->addAction(connectAction);
        connMenu->addAction(disconnectAction);

        QAction *serveAct = new QAction("Create server", this);
        connect(serveAct, &QAction::triggered, this, &MainWindow::onCreateServer);
        connMenu->addAction(serveAct);

        QMenu *audioMenu = menuBar()->addMenu("Audio call");
        QAction *audioCallAct = new QAction("Start audio call", this);
        connect(audioCallAct, &QAction::triggered, this, &MainWindow::onAudioCall);
        audioMenu->addAction(audioCallAct);

        QMenu *keysMenu = menuBar()->addMenu("Keys");
        QAction *genKeys = new QAction("Generate keypair", this);
        connect(genKeys, &QAction::triggered, this, &MainWindow::onGenKeys);
        keysMenu->addAction(genKeys);
       
        QAction *keyExchangeAction = new QAction("Key exchange", this);
        connect(keyExchangeAction, &QAction::triggered, this, &MainWindow::onKeyExchange);
        keysMenu->addAction(keyExchangeAction);

        QMenu *chatMenu = menuBar()->addMenu("Chat");
        chatMenu->addAction(clearChatAction);
        chatMenu->addAction(fontSettingsAction);
        chatMenu->addAction(sendFileAction);

        QMenu *helpMenu = menuBar()->addMenu("Help");
        QAction *update = new QAction("Check for updates", this);
        connect(update, &QAction::triggered, this, [this](){
            UpdateDialog dialog(this, backend->cliPath);
            dialog.exec();
        });
        helpMenu->addAction(update);

        QAction *docAction = new QAction("Documentation", this);
        connect(docAction, &QAction::triggered, this, &MainWindow::onOpenDocumentation);
        helpMenu->addAction(docAction); 

        QAction *about = new QAction("About", this);
        connect(about, &QAction::triggered, this, [this](){
            // Создаем кастомное диалоговое окно
            QMessageBox msgBox(this);
            msgBox.setWindowTitle("About F.E.A.R.");
            msgBox.setText("This is Qt-based frontend GUI for F.E.A.R. messenger.\n"
                           "F.E.A.R. is a encrypted anonymous messenger with E2EE encryption.\n"
                           "Read more at project Github page.\n\n"
                           "Developed by Shchuchkin E. Yu.\n"
                           "Email: shchuchkin-pkims@yandex.ru\n");
            msgBox.addButton(QMessageBox::Ok);
            QPushButton *githubButton = msgBox.addButton("Github page", QMessageBox::ActionRole);
            msgBox.exec();
            if (msgBox.clickedButton() == githubButton) {
                QDesktopServices::openUrl(QUrl("https://github.com/shchuchkin-pkims/fear"));
            }
        });

        helpMenu->addAction(about);
    }

    void createToolbar(){
        QToolBar *tb = addToolBar("Main");
        tb->addAction(connectAction);
        tb->addAction(disconnectAction);
        tb->addSeparator();

        QAction *refreshAct = new QAction("Refresh contacts", this);
        connect(refreshAct, &QAction::triggered, this, &MainWindow::refreshContacts);
        tb->addAction(refreshAct);
    }

    void createCentral(){
        QWidget *central = new QWidget(this);
        setCentralWidget(central);

        QSplitter *mainSplitter = new QSplitter(this);

        // Left: contacts
        QWidget *left = new QWidget(this);
        QVBoxLayout *leftLayout = new QVBoxLayout(left);
        contactsWidget = new QListWidget(left);
        leftLayout->addWidget(new QLabel("Contacts"));
        leftLayout->addWidget(contactsWidget);

        QPushButton *newChat = new QPushButton("New chat");
        connect(newChat, &QPushButton::clicked, this, [this](){
            bool ok;
            QString name = QInputDialog::getText(this, "New chat", "Contact name:", QLineEdit::Normal, QString(), &ok);
            if(ok && !name.isEmpty()){
                contactsWidget->addItem(name);
            }
        });
        leftLayout->addWidget(newChat);

        // Right: chat area
        QWidget *right = new QWidget(this);
        QVBoxLayout *rightLayout = new QVBoxLayout(right);
        
        // Добавляем панель инструментов для чата
        QHBoxLayout *chatToolbarLayout = new QHBoxLayout();
        QLabel *chatLabel = new QLabel("Chat");
        QPushButton *sendFileBtn = new QPushButton("Send file");
        QPushButton *clearChatBtn = new QPushButton("Clear");
        
        connect(sendFileBtn, &QPushButton::clicked, this, &MainWindow::onSendFile);
        connect(clearChatBtn, &QPushButton::clicked, this, &MainWindow::onClearChat);
        
        chatToolbarLayout->addWidget(chatLabel);
        chatToolbarLayout->addStretch();
        chatToolbarLayout->addWidget(sendFileBtn);
        chatToolbarLayout->addWidget(clearChatBtn);
        
        rightLayout->addLayout(chatToolbarLayout);
        
        chatView = new QTextEdit(right);
        chatView->setReadOnly(true);
        
        // Загружаем сохраненные настройки шрифта
        QString savedFont = appSettings->value("chat/font").toString();
        if (!savedFont.isEmpty()) {
            chatFont.fromString(savedFont);
        }
        chatView->setFont(chatFont);
        
        rightLayout->addWidget(chatView);

        QHBoxLayout *bottomLayout = new QHBoxLayout();
        inputEdit = new QLineEdit(right);
        QPushButton *sendBtn = new QPushButton("Send");

        connect(sendBtn, &QPushButton::clicked, this, &MainWindow::onSend);
        connect(inputEdit, &QLineEdit::returnPressed, this, &MainWindow::onSend);

        bottomLayout->addWidget(inputEdit);
        bottomLayout->addWidget(sendBtn);
        rightLayout->addLayout(bottomLayout);

        mainSplitter->addWidget(left);
        mainSplitter->addWidget(right);
        mainSplitter->setStretchFactor(1, 1);

        QVBoxLayout *mainL = new QVBoxLayout(central);
        mainL->addWidget(mainSplitter);
    }
};

int main(int argc, char **argv){
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/icons/logo.ico"));
    MainWindow w;
    w.show();
    return app.exec();
}

#include "main.moc"
