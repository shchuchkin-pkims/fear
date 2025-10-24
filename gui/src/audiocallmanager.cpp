/**
 * @file audiocallmanager.cpp
 * @brief Implementation of audio call process manager
 */

#include "audiocallmanager.h"
#include <QApplication>
#include <QFile>
#include <QGuiApplication>
#include <QClipboard>

AudioCallManager::AudioCallManager(QObject *parent)
    : QObject(parent), callProcess(nullptr) {
    settings = new QSettings("fear-messenger", "fear-audio", this);
}

AudioCallManager::~AudioCallManager() {
    stopCall();
}

bool AudioCallManager::generateKey() {
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

    // SECURITY: genkey now outputs key to stdout (not saved to file)
    // Read the generated key from stdout
    QString output = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
    QString key = output.split('\n').first().trimmed(); // Get first line (the key)

    if (key.length() != 64) { // 32 bytes in hex = 64 hex chars
        emit error(QString("Invalid key format (expected 64 hex chars, got %1)").arg(key.length()));
        return false;
    }

    currentKey = key;

    // SECURITY: Auto-copy to clipboard for user convenience
    QGuiApplication::clipboard()->setText(key);

    emit keyGenerated(key);
    return true;
}

bool AudioCallManager::startCall(const QString &remoteIp, quint16 remotePort, const QString &key,
                                  quint16 localPort, int inputDevice, int outputDevice) {
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
    connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &AudioCallManager::onProcessFinished);

    // SECURITY: Do NOT pass key via command line argument (visible in process list)
    // Instead, we pass it via stdin
    QStringList args;
    args << "call" << remoteIp << QString::number(remotePort);
    // NOTE: NO key argument here for security!

    if (localPort > 0) {
        args << QString::number(localPort);
    } else {
        args << "0";  // Default local port
    }

    // Add device parameters
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

    // SECURITY: Pass key via stdin (not visible in process list)
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = callProcess->write(keyData);
    if (written == -1) {
        emit error("Failed to send key to audio call process");
        callProcess->kill();
        callProcess->waitForFinished(1000);
        delete callProcess;
        callProcess = nullptr;
        return false;
    }

    // Close stdin to signal that we're done sending the key
    callProcess->closeWriteChannel();

    emit callStarted();
    return true;
}

bool AudioCallManager::startListening(quint16 localPort, const QString &key,
                                       int inputDevice, int outputDevice) {
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
    connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &AudioCallManager::onProcessFinished);

    // SECURITY: Do NOT pass key via command line argument (visible in process list)
    // Instead, we pass it via stdin
    QStringList args;
    args << "listen" << QString::number(localPort);
    // NOTE: NO key argument here for security!

    // Add device parameters
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

    // SECURITY: Pass key via stdin (not visible in process list)
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = callProcess->write(keyData);
    if (written == -1) {
        emit error("Failed to send key to audio listening process");
        callProcess->kill();
        callProcess->waitForFinished(1000);
        delete callProcess;
        callProcess = nullptr;
        return false;
    }

    // Close stdin to signal that we're done sending the key
    callProcess->closeWriteChannel();

    emit listeningStarted();
    return true;
}

void AudioCallManager::stopCall() {
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

bool AudioCallManager::isCallActive() const {
    return callProcess && callProcess->state() == QProcess::Running;
}

QString AudioCallManager::getCurrentKey() const {
    return currentKey;
}

void AudioCallManager::onProcessOutput() {
    if (callProcess) {
        QString output = QString::fromUtf8(callProcess->readAllStandardOutput());
        emit this->output(output);
    }
}

void AudioCallManager::onProcessError() {
    if (callProcess) {
        QString error = QString::fromUtf8(callProcess->readAllStandardError());
        emit this->error(error);
    }
}

void AudioCallManager::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitCode);
    Q_UNUSED(exitStatus);
    emit callStopped();
}

QString AudioCallManager::findAudioCallApp() {
    // Search for audio_call in various locations
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
