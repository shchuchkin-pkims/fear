/**
 * @file videocalldialog.cpp
 * @brief Implementation of video call dialog
 */

#include "videocalldialog.h"
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

VideoCallDialog::VideoCallDialog(VideoCallManager *videoManager, Backend *backend,
                                 QWidget *parent, const QString &roomKeyHex)
    : QDialog(parent), videoManager(videoManager), backend(backend) {
    setWindowTitle("Video Call");
    setMinimumSize(550, 600);

    setupUI();
    setupConnections();

    // Auto-fill room key if available, hide key section
    if (!roomKeyHex.isEmpty() && roomKeyHex.length() == 64) {
        keyEdit->setText(roomKeyHex);
        keyGroupBox->setVisible(false);
    }

    refreshDevices();

    // Pre-select defaults from settings
    QSettings settings("fear-messenger", "fear-gui");

    QString defaultCamera = settings.value("video/defaultCamera", "").toString();
    if (!defaultCamera.isEmpty()) {
        for (int i = 0; i < cameraCombo->count(); i++) {
            if (cameraCombo->itemData(i).toString() == defaultCamera) {
                cameraCombo->setCurrentIndex(i);
                break;
            }
        }
    }

    QString quality = settings.value("video/quality", "medium").toString();
    int qIdx = 1; // default medium
    if (quality == "low") qIdx = 0;
    else if (quality == "medium") qIdx = 1;
    else if (quality == "high") qIdx = 2;
    qualityCombo->setCurrentIndex(qIdx);

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

void VideoCallDialog::onGenerateKey() {
    if (videoManager->generateKey()) {
        // Key will be set via keyGenerated signal
    }
}

void VideoCallDialog::onKeyGenerated(const QString &key) {
    keyEdit->setText(key);
    outputText->append("Key generated and copied to clipboard!");
    outputText->append("IMPORTANT: Share this key securely with call participants.");
}

void VideoCallDialog::onStartCall() {
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

    QString quality;
    int idx = qualityCombo->currentIndex();
    if (idx == 0) quality = "low";
    else if (idx == 1) quality = "medium";
    else if (idx == 2) quality = "high";
    // idx == 3 is custom, handled by width/height/fps/bitrate

    bool adaptive = adaptiveCheck->isChecked();
    int width = (idx == 3) ? widthSpin->value() : 0;
    int height = (idx == 3) ? heightSpin->value() : 0;
    int fps = (idx == 3) ? fpsSpin->value() : 0;
    int bitrate = (idx == 3) ? bitrateSpin->value() : 0;

    QString camera = cameraCombo->currentData().toString();
    int audioInput = inputDeviceCombo->currentData().toInt();
    int audioOutput = outputDeviceCombo->currentData().toInt();

    if (relayCheck->isChecked() && backend) {
        // Relay mode: route through server
        if (videoManager->startRelay(remoteIp, remotePort,
                                      backend->currentRoom, backend->currentName, key,
                                      quality, adaptive, width, height, fps, bitrate,
                                      camera, audioInput, audioOutput, false, false)) {
            statusLabel->setText("Relay call started");
        }
    } else {
        if (videoManager->startCall(remoteIp, remotePort, key,
                                     localPortSpin->value(), quality, adaptive,
                                     width, height, fps, bitrate,
                                     camera, audioInput, audioOutput,
                                     false, false)) {
            statusLabel->setText("Call started");
        }
    }
}

void VideoCallDialog::onStartListening() {
    QString key = keyEdit->text();
    if (key.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please generate or enter a key first");
        return;
    }

    QString quality;
    int idx = qualityCombo->currentIndex();
    if (idx == 0) quality = "low";
    else if (idx == 1) quality = "medium";
    else if (idx == 2) quality = "high";

    bool adaptive = adaptiveCheck->isChecked();
    int width = (idx == 3) ? widthSpin->value() : 0;
    int height = (idx == 3) ? heightSpin->value() : 0;
    int fps = (idx == 3) ? fpsSpin->value() : 0;
    int bitrate = (idx == 3) ? bitrateSpin->value() : 0;

    QString camera = cameraCombo->currentData().toString();
    int audioInput = inputDeviceCombo->currentData().toInt();
    int audioOutput = outputDeviceCombo->currentData().toInt();

    if (videoManager->startListening(localPortSpin->value(), key,
                                      quality, adaptive,
                                      width, height, fps, bitrate,
                                      camera, audioInput, audioOutput,
                                      false, false)) {
        statusLabel->setText("Listening started");
    }
}

void VideoCallDialog::onStopCall() {
    videoManager->stopCall();
    statusLabel->setText("Call stopped");
}

void VideoCallDialog::onCallStarted() {
    callButton->setEnabled(false);
    listenButton->setEnabled(false);
    stopButton->setEnabled(true);
}

void VideoCallDialog::onCallStopped() {
    callButton->setEnabled(true);
    listenButton->setEnabled(true);
    stopButton->setEnabled(false);
}

void VideoCallDialog::onError(const QString &error) {
    outputText->append("Error: " + error);
    statusLabel->setText("Error: " + error.left(30));
}

void VideoCallDialog::onOutput(const QString &output) {
    // Parse [STATS] lines and update status label
    QStringList lines = output.split('\n');
    for (const QString &line : lines) {
        QString t = line.trimmed();
        if (t.startsWith("[STATS]")) {
            // Extract RTT value from "[STATS] RTT=Xms"
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

void VideoCallDialog::onQualityPresetChanged(int index) {
    customWidget->setVisible(index == 3);
}

void VideoCallDialog::setupUI() {
    QVBoxLayout *layout = new QVBoxLayout(this);

    // ===== Key section =====
    keyGroupBox = new QGroupBox("Encryption Key", this);
    QHBoxLayout *keyLayout = new QHBoxLayout(keyGroupBox);
    keyEdit = new QLineEdit(keyGroupBox);
    keyEdit->setPlaceholderText("32-byte hex key (64 hex chars)");
    genKeyButton = new QPushButton("Generate", keyGroupBox);
    keyLayout->addWidget(keyEdit);
    keyLayout->addWidget(genKeyButton);
    layout->addWidget(keyGroupBox);

    // ===== Devices section =====
    QGroupBox *devicesGroup = new QGroupBox("Devices", this);
    QGridLayout *devicesLayout = new QGridLayout(devicesGroup);

    devicesLayout->addWidget(new QLabel("Camera:"), 0, 0);
    cameraCombo = new QComboBox(devicesGroup);
    devicesLayout->addWidget(cameraCombo, 0, 1);

    devicesLayout->addWidget(new QLabel("Audio Input:"), 1, 0);
    inputDeviceCombo = new QComboBox(devicesGroup);
    devicesLayout->addWidget(inputDeviceCombo, 1, 1);

    devicesLayout->addWidget(new QLabel("Audio Output:"), 2, 0);
    outputDeviceCombo = new QComboBox(devicesGroup);
    devicesLayout->addWidget(outputDeviceCombo, 2, 1);

    refreshDevicesButton = new QPushButton("Refresh Devices", devicesGroup);
    devicesLayout->addWidget(refreshDevicesButton, 3, 0, 1, 2);
    layout->addWidget(devicesGroup);

    // ===== Quality section =====
    QGroupBox *qualityGroup = new QGroupBox("Quality", this);
    QVBoxLayout *qualityLayout = new QVBoxLayout(qualityGroup);

    QHBoxLayout *presetLayout = new QHBoxLayout();
    presetLayout->addWidget(new QLabel("Preset:"));
    qualityCombo = new QComboBox(qualityGroup);
    qualityCombo->addItem("Low (320x240 15fps)");
    qualityCombo->addItem("Medium (640x480 25fps)");
    qualityCombo->addItem("High (1280x720 30fps)");
    qualityCombo->addItem("Custom");
    qualityCombo->setCurrentIndex(1);
    presetLayout->addWidget(qualityCombo);
    qualityLayout->addLayout(presetLayout);

    adaptiveCheck = new QCheckBox("Adaptive quality", qualityGroup);
    adaptiveCheck->setChecked(true);
    qualityLayout->addWidget(adaptiveCheck);

    // Custom parameters (hidden by default)
    customWidget = new QWidget(qualityGroup);
    QGridLayout *customLayout = new QGridLayout(customWidget);

    customLayout->addWidget(new QLabel("Width:"), 0, 0);
    widthSpin = new QSpinBox(customWidget);
    widthSpin->setRange(160, 1920);
    widthSpin->setValue(1280);
    customLayout->addWidget(widthSpin, 0, 1);

    customLayout->addWidget(new QLabel("Height:"), 0, 2);
    heightSpin = new QSpinBox(customWidget);
    heightSpin->setRange(120, 1080);
    heightSpin->setValue(720);
    customLayout->addWidget(heightSpin, 0, 3);

    customLayout->addWidget(new QLabel("FPS:"), 1, 0);
    fpsSpin = new QSpinBox(customWidget);
    fpsSpin->setRange(1, 60);
    fpsSpin->setValue(30);
    customLayout->addWidget(fpsSpin, 1, 1);

    customLayout->addWidget(new QLabel("Bitrate (kbps):"), 1, 2);
    bitrateSpin = new QSpinBox(customWidget);
    bitrateSpin->setRange(50, 10000);
    bitrateSpin->setValue(1500);
    customLayout->addWidget(bitrateSpin, 1, 3);

    customWidget->setVisible(false);
    qualityLayout->addWidget(customWidget);
    layout->addWidget(qualityGroup);

    // ===== Connection section =====
    QGroupBox *connGroup = new QGroupBox("Connection", this);
    QGridLayout *connLayout = new QGridLayout(connGroup);

    relayCheck = new QCheckBox("Relay through server", connGroup);
    relayCheck->setToolTip("Route call through the chat server (for NAT traversal)");
    connLayout->addWidget(relayCheck, 0, 0, 1, 4);

    connLayout->addWidget(new QLabel("Remote IP:"), 1, 0);
    ipEdit = new QLineEdit(connGroup);
    ipEdit->setText("127.0.0.1");
    connLayout->addWidget(ipEdit, 1, 1);

    connLayout->addWidget(new QLabel("Remote Port:"), 1, 2);
    portSpin = new QSpinBox(connGroup);
    portSpin->setRange(1024, 65535);
    portSpin->setValue(50000);
    connLayout->addWidget(portSpin, 1, 3);

    connLayout->addWidget(new QLabel("Local Port:"), 2, 0);
    localPortSpin = new QSpinBox(connGroup);
    localPortSpin->setRange(1024, 65535);
    localPortSpin->setValue(50001);
    connLayout->addWidget(localPortSpin, 2, 1);

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

    // ===== Status =====
    statusLabel = new QLabel("Ready", this);
    layout->addWidget(statusLabel);

    // ===== Output log =====
    outputText = new QTextEdit(this);
    outputText->setReadOnly(true);
    outputText->setMaximumHeight(120);
    layout->addWidget(outputText);
}

void VideoCallDialog::setupConnections() {
    connect(videoManager, &VideoCallManager::keyGenerated, this, &VideoCallDialog::onKeyGenerated);
    connect(videoManager, &VideoCallManager::callStarted, this, &VideoCallDialog::onCallStarted);
    connect(videoManager, &VideoCallManager::listeningStarted, this, &VideoCallDialog::onCallStarted);
    connect(videoManager, &VideoCallManager::callStopped, this, &VideoCallDialog::onCallStopped);
    connect(videoManager, &VideoCallManager::error, this, &VideoCallDialog::onError);
    connect(videoManager, &VideoCallManager::output, this, &VideoCallDialog::onOutput);

    connect(genKeyButton, &QPushButton::clicked, this, &VideoCallDialog::onGenerateKey);
    connect(refreshDevicesButton, &QPushButton::clicked, this, &VideoCallDialog::refreshDevices);
    connect(callButton, &QPushButton::clicked, this, &VideoCallDialog::onStartCall);
    connect(listenButton, &QPushButton::clicked, this, &VideoCallDialog::onStartListening);
    connect(stopButton, &QPushButton::clicked, this, &VideoCallDialog::onStopCall);
    connect(qualityCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &VideoCallDialog::onQualityPresetChanged);

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

void VideoCallDialog::refreshDevices() {
    QString appPath = findVideoCallApp();
    if (appPath.isEmpty()) {
        outputText->append("Video call application not found");
        return;
    }

    QProcess process;
    process.setProcessChannelMode(QProcess::ForwardedErrorChannel);
    process.start(appPath, QStringList() << "listdevices");

    if (!process.waitForFinished(5000)) {
        outputText->append("Failed to get device list");
        return;
    }

    QString out = QString::fromUtf8(process.readAllStandardOutput());
    QString err = QString::fromUtf8(process.readAllStandardError());

    // Clear all combos
    cameraCombo->clear();
    inputDeviceCombo->clear();
    outputDeviceCombo->clear();

    cameraCombo->addItem("Default", "");
    cameraCombo->addItem("No camera (receive only)", "__none__");
    inputDeviceCombo->addItem("Default", -1);
    outputDeviceCombo->addItem("Default", -1);

    QStringList lines = out.split('\n');
    bool inAudioSection = false;
    bool inCameraSection = false;

    int currentDeviceId = -1;
    QString currentDeviceName;
    int maxInputChannels = 0;
    int maxOutputChannels = 0;

    for (const QString &line : lines) {
        QString t = line.trimmed();

        if (t.startsWith("=== Audio")) {
            inAudioSection = true;
            inCameraSection = false;
            continue;
        }
        if (t.startsWith("=== Camera")) {
            // Finish last audio device
            if (currentDeviceId >= 0) {
                if (maxInputChannels > 0) inputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
                if (maxOutputChannels > 0) outputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
            }
            currentDeviceId = -1;
            inAudioSection = false;
            inCameraSection = true;
            continue;
        }

        if (inAudioSection) {
            if (t.startsWith("Device ")) {
                // Save previous device
                if (currentDeviceId >= 0) {
                    if (maxInputChannels > 0) inputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
                    if (maxOutputChannels > 0) outputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
                }

                QStringList parts = t.split(':');
                if (parts.size() >= 2) {
                    QString devicePart = parts[0].trimmed();
                    currentDeviceName = parts.mid(1).join(':').trimmed();
                    QStringList words = devicePart.split(' ');
                    if (words.size() >= 2) {
                        bool ok;
                        currentDeviceId = words[1].toInt(&ok);
                        if (!ok) currentDeviceId = -1;
                    }
                }
                maxInputChannels = 0;
                maxOutputChannels = 0;
            } else if (t.startsWith("Max input channels:")) {
                maxInputChannels = t.split(':').last().trimmed().toInt();
            } else if (t.startsWith("Max output channels:")) {
                maxOutputChannels = t.split(':').last().trimmed().toInt();
            }
        }

        if (inCameraSection) {
            // Camera lines: "  camera: DeviceName" (both Windows and Linux)
            if (t.startsWith("camera:")) {
                QString camName = t.mid(7).trimmed();
                if (!camName.isEmpty() && camName != "(no cameras found)") {
                    cameraCombo->addItem(camName, camName);
                }
            }
        }
    }

    // Don't forget last audio device
    if (currentDeviceId >= 0) {
        if (maxInputChannels > 0) inputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
        if (maxOutputChannels > 0) outputDeviceCombo->addItem(currentDeviceName, currentDeviceId);
    }

    // Log stderr output if any (debug info)
    if (!err.trimmed().isEmpty()) {
        outputText->append("(debug) " + err.trimmed());
    }

    int inputCount = inputDeviceCombo->count() - 1;
    int outputCount = outputDeviceCombo->count() - 1;
    int cameraCount = cameraCombo->count() - 2; /* subtract Default and No camera */
    outputText->append(QString("Found %1 camera(s), %2 audio input(s), %3 audio output(s)")
                      .arg(cameraCount).arg(inputCount).arg(outputCount));
}

QString VideoCallDialog::findVideoCallApp() {
    QStringList possiblePaths = {
        QApplication::applicationDirPath() + "/video_call",
        QApplication::applicationDirPath() + "/bin/video_call",
        QApplication::applicationDirPath() + "/../bin/video_call",
        "video_call",
        "./video_call"
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
