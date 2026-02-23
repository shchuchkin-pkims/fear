/**
 * @file audiocalldialog.cpp
 * @brief Implementation of audio call dialog
 */

#include "audiocalldialog.h"
#include "backend.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QMessageBox>
#include <QApplication>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSettings>
#include <QRegularExpression>

AudioCallDialog::AudioCallDialog(AudioCallManager *audioManager, Backend *backend,
                                 QWidget *parent, const QString &roomKeyHex)
    : QDialog(parent), audioManager(audioManager), backend(backend) {
    setWindowTitle("Audio Call");
    setMinimumSize(500, 450);

    setupUI();
    setupConnections();

    // Auto-fill room key if available, hide key section
    if (!roomKeyHex.isEmpty() && roomKeyHex.length() == 64) {
        keyEdit->setText(roomKeyHex);
        keyGroup->setVisible(false);
    }

    // Load audio devices list when dialog opens
    refreshAudioDevices();

    // Pre-select defaults from settings
    QSettings settings("fear-messenger", "fear-gui");

    QString audioIn = settings.value("audio/inputDevice", "").toString();
    if (!audioIn.isEmpty() && audioIn != "System default") {
        for (int i = 0; i < inputDeviceCombo->count(); i++) {
            if (inputDeviceCombo->itemText(i) == audioIn) {
                inputDeviceCombo->setCurrentIndex(i);
                break;
            }
        }
    }

    QString audioOut = settings.value("audio/outputDevice", "").toString();
    if (!audioOut.isEmpty() && audioOut != "System default") {
        for (int i = 0; i < outputDeviceCombo->count(); i++) {
            if (outputDeviceCombo->itemText(i) == audioOut) {
                outputDeviceCombo->setCurrentIndex(i);
                break;
            }
        }
    }
}

void AudioCallDialog::onGenerateKey() {
    if (audioManager->generateKey()) {
        // Key will be set via keyGenerated signal
    }
}

void AudioCallDialog::onKeyGenerated(const QString &key) {
    keyEdit->setText(key);
    outputText->append("✓ Key generated and copied to clipboard!");
    outputText->append("Key: " + key);
    outputText->append("IMPORTANT: Share this key securely with call participants.");
}

void AudioCallDialog::onStartCall() {
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

    // Get selected audio devices
    int inputDevice = inputDeviceCombo->currentData().toInt();
    int outputDevice = outputDeviceCombo->currentData().toInt();

    if (relayCheck->isChecked() && backend) {
        // Relay mode: route through server
        if (audioManager->startRelay(remoteIp, remotePort,
                                      backend->currentRoom, backend->currentName, key,
                                      inputDevice, outputDevice)) {
            statusLabel->setText("Relay call started");
        }
    } else {
        if (audioManager->startCall(remoteIp, remotePort, key, localPortSpin->value(), inputDevice, outputDevice)) {
            statusLabel->setText("Call started");
        }
    }
}

void AudioCallDialog::onStartListening() {
    QString key = keyEdit->text();
    if (key.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please generate or enter a key first");
        return;
    }

    // Get selected audio devices
    int inputDevice = inputDeviceCombo->currentData().toInt();
    int outputDevice = outputDeviceCombo->currentData().toInt();

    if (audioManager->startListening(localPortSpin->value(), key, inputDevice, outputDevice)) {
        statusLabel->setText("Listening started");
    }
}

void AudioCallDialog::onStopCall() {
    audioManager->stopCall();
    statusLabel->setText("Call stopped");
}

void AudioCallDialog::onCallStarted() {
    callButton->setEnabled(false);
    listenButton->setEnabled(false);
    stopButton->setEnabled(true);
}

void AudioCallDialog::onCallStopped() {
    callButton->setEnabled(true);
    listenButton->setEnabled(true);
    stopButton->setEnabled(false);
}

void AudioCallDialog::onError(const QString &error) {
    outputText->append("Error: " + error);
    statusLabel->setText("Error: " + error.left(30));
}

void AudioCallDialog::onOutput(const QString &output) {
    // Parse [STATS] lines and update status label
    QStringList lines = output.split('\n');
    for (const QString &line : lines) {
        QString t = line.trimmed();
        if (t.startsWith("[STATS]")) {
            QRegularExpression rx("RTT=(\\d+)");
            QRegularExpressionMatch m = rx.match(t);
            if (m.hasMatch()) {
                statusLabel->setText(QString("RTT: %1 ms").arg(m.captured(1)));
            }
        } else if (!t.isEmpty()) {
            outputText->append(t);
        }
    }
}

void AudioCallDialog::setupUI() {
    QVBoxLayout *layout = new QVBoxLayout(this);

    // ===== Key section =====
    keyGroup = new QGroupBox("Encryption Key", this);
    QHBoxLayout *keyLayout = new QHBoxLayout(keyGroup);
    keyEdit = new QLineEdit(keyGroup);
    keyEdit->setPlaceholderText("32-byte hex key");
    genKeyButton = new QPushButton("Generate", keyGroup);
    keyLayout->addWidget(keyEdit);
    keyLayout->addWidget(genKeyButton);
    layout->addWidget(keyGroup);

    // ===== Audio devices section =====
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

    // ===== Connection section =====
    QGroupBox *connGroup = new QGroupBox("Connection", this);
    QGridLayout *connLayout = new QGridLayout(connGroup);

    relayCheck = new QCheckBox("Relay through server", connGroup);
    relayCheck->setToolTip("Route call through the chat server (for NAT traversal)");
    connLayout->addWidget(relayCheck, 0, 0, 1, 2);

    connLayout->addWidget(new QLabel("Remote IP:"), 1, 0);
    ipEdit = new QLineEdit(connGroup);
    ipEdit->setText("127.0.0.1");
    connLayout->addWidget(ipEdit, 1, 1);

    connLayout->addWidget(new QLabel("Remote Port:"), 2, 0);
    portSpin = new QSpinBox(connGroup);
    portSpin->setRange(1024, 65535);
    portSpin->setValue(50000);
    connLayout->addWidget(portSpin, 2, 1);

    connLayout->addWidget(new QLabel("Local Port:"), 3, 0);
    localPortSpin = new QSpinBox(connGroup);
    localPortSpin->setRange(1024, 65535);
    localPortSpin->setValue(50001);
    connLayout->addWidget(localPortSpin, 3, 1);

    layout->addWidget(connGroup);

    // ===== Control buttons =====
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    callButton = new QPushButton("Start Call", this);
    listenButton = new QPushButton("Start Listening", this);
    stopButton = new QPushButton("Stop", this);
    stopButton->setEnabled(false);

    buttonLayout->addWidget(callButton);
    buttonLayout->addWidget(listenButton);
    buttonLayout->addWidget(stopButton);
    layout->addLayout(buttonLayout);

    // ===== Status display =====
    statusLabel = new QLabel("Ready", this);
    layout->addWidget(statusLabel);

    // ===== Output log =====
    outputText = new QTextEdit(this);
    outputText->setReadOnly(true);
    layout->addWidget(outputText);
}

void AudioCallDialog::setupConnections() {
    // Connect signals from audio manager
    connect(audioManager, &AudioCallManager::keyGenerated, this, &AudioCallDialog::onKeyGenerated);
    connect(audioManager, &AudioCallManager::callStarted, this, &AudioCallDialog::onCallStarted);
    connect(audioManager, &AudioCallManager::listeningStarted, this, &AudioCallDialog::onCallStarted);
    connect(audioManager, &AudioCallManager::callStopped, this, &AudioCallDialog::onCallStopped);
    connect(audioManager, &AudioCallManager::error, this, &AudioCallDialog::onError);
    connect(audioManager, &AudioCallManager::output, this, &AudioCallDialog::onOutput);

    // Connect UI buttons
    connect(genKeyButton, &QPushButton::clicked, this, &AudioCallDialog::onGenerateKey);
    connect(refreshDevicesButton, &QPushButton::clicked, this, &AudioCallDialog::refreshAudioDevices);
    connect(callButton, &QPushButton::clicked, this, &AudioCallDialog::onStartCall);
    connect(listenButton, &QPushButton::clicked, this, &AudioCallDialog::onStartListening);
    connect(stopButton, &QPushButton::clicked, this, &AudioCallDialog::onStopCall);

    // Relay checkbox: auto-fill from backend connection
    connect(relayCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked && backend && backend->isConnected) {
            ipEdit->setText(backend->serverHost);
            portSpin->setValue(backend->serverPort);
            ipEdit->setEnabled(false);
            portSpin->setEnabled(false);
            localPortSpin->setEnabled(false);
            listenButton->setVisible(false);
        } else {
            ipEdit->setEnabled(true);
            portSpin->setEnabled(true);
            localPortSpin->setEnabled(true);
            listenButton->setVisible(true);
        }
    });

    // Enable relay checkbox only when connected to a remote server
    if (backend && backend->isConnected && !backend->serverHost.isEmpty()) {
        relayCheck->setEnabled(true);
    } else {
        relayCheck->setEnabled(false);
        relayCheck->setToolTip("Connect to a server first to use relay mode");
    }
}

void AudioCallDialog::refreshAudioDevices() {
    QString audioAppPath = findAudioCallApp();
    if (audioAppPath.isEmpty()) {
        outputText->append("Audio call application not found");
        return;
    }

    QProcess process;
    process.setProcessChannelMode(QProcess::ForwardedErrorChannel);
    process.start(audioAppPath, QStringList() << "listdevices");

    if (!process.waitForFinished(5000)) {
        outputText->append("Failed to get audio devices list");
        return;
    }

    QString output = QString::fromUtf8(process.readAllStandardOutput());

    // Parse output and populate device combo boxes
    inputDeviceCombo->clear();
    outputDeviceCombo->clear();

    inputDeviceCombo->addItem("Default", -1);
    outputDeviceCombo->addItem("Default", -1);

    QStringList lines = output.split('\n');

    // Structure for storing device information
    int currentDeviceId = -1;
    QString currentDeviceName;
    int maxInputChannels = 0;
    int maxOutputChannels = 0;

    for (const QString &line : lines) {
        QString trimmedLine = line.trimmed();

        // Look for lines like "Device N: Name"
        if (trimmedLine.startsWith("Device ")) {
            // If we had a previous device, add it
            if (currentDeviceId >= 0) {
                if (maxInputChannels > 0) {
                    inputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
                }
                if (maxOutputChannels > 0) {
                    outputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
                }
            }

            // Start new device
            QStringList parts = trimmedLine.split(':');
            if (parts.size() >= 2) {
                QString devicePart = parts[0].trimmed();
                currentDeviceName = parts[1].trimmed();

                // Extract device number
                QStringList deviceWords = devicePart.split(' ');
                if (deviceWords.size() >= 2) {
                    bool ok;
                    currentDeviceId = deviceWords[1].toInt(&ok);
                    if (!ok) {
                        currentDeviceId = -1;
                    }
                }
            }
            maxInputChannels = 0;
            maxOutputChannels = 0;
        }
        // Parse channel counts
        else if (trimmedLine.startsWith("Max input channels:")) {
            QStringList parts = trimmedLine.split(':');
            if (parts.size() >= 2) {
                maxInputChannels = parts[1].trimmed().toInt();
            }
        }
        else if (trimmedLine.startsWith("Max output channels:")) {
            QStringList parts = trimmedLine.split(':');
            if (parts.size() >= 2) {
                maxOutputChannels = parts[1].trimmed().toInt();
            }
        }
    }

    // Don't forget to add the last device
    if (currentDeviceId >= 0) {
        if (maxInputChannels > 0) {
            inputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
        }
        if (maxOutputChannels > 0) {
            outputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
        }
    }

    int inputCount = inputDeviceCombo->count() - 1;  // -1 for "Default"
    int outputCount = outputDeviceCombo->count() - 1;
    outputText->append(QString("Found %1 input device(s) and %2 output device(s)")
                      .arg(inputCount).arg(outputCount));
}

QString AudioCallDialog::findAudioCallApp() {
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
        if (QFileInfo(path).isFile()) {
            return path;
        }
    }

    return QString();
}
