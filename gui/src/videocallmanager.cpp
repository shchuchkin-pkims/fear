/**
 * @file videocallmanager.cpp
 * @brief Implementation of video call process manager
 */

#include "videocallmanager.h"
#include <QApplication>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QClipboard>

VideoCallManager::VideoCallManager(QObject *parent)
    : QObject(parent), callProcess(nullptr) {
    settings = new QSettings("fear-messenger", "fear-video", this);
}

VideoCallManager::~VideoCallManager() {
    stopCall();
}

bool VideoCallManager::generateKey() {
    QString appPath = findVideoCallApp();
    if (appPath.isEmpty()) {
        emit error("Video call application not found");
        return false;
    }

    QProcess process;
    process.setProcessChannelMode(QProcess::ForwardedErrorChannel);
    process.start(appPath, QStringList() << "genkey");

    if (!process.waitForFinished(5000)) {
        emit error("Key generation timed out");
        return false;
    }

    if (process.exitCode() != 0) {
        emit error("Key generation failed");
        return false;
    }

    QString out = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
    QString key = out.split('\n').first().trimmed();

    if (key.length() != 64) {
        emit error(QString("Invalid key format (expected 64 hex chars, got %1)").arg(key.length()));
        return false;
    }

    currentKey = key;
    QGuiApplication::clipboard()->setText(key);
    emit keyGenerated(key);
    return true;
}

QStringList VideoCallManager::buildArgs(const QString &quality, bool adaptive,
                                         int width, int height, int fps, int bitrate,
                                         const QString &camera, int audioInput, int audioOutput,
                                         bool noVideo, bool noAudio) const {
    QStringList args;

    if (!quality.isEmpty()) {
        args << "--quality" << quality;
    }
    if (adaptive) {
        args << "--adaptive";
    }
    if (width > 0) args << "--width" << QString::number(width);
    if (height > 0) args << "--height" << QString::number(height);
    if (fps > 0) args << "--fps" << QString::number(fps);
    if (bitrate > 0) args << "--bitrate" << QString::number(bitrate);
    if (camera == "__none__") {
        args << "--no-camera";
    } else if (!camera.isEmpty()) {
        args << "--camera" << camera;
    }
    if (audioInput >= 0) args << "--audio-input" << QString::number(audioInput);
    if (audioOutput >= 0) args << "--audio-output" << QString::number(audioOutput);
    if (noVideo) args << "--no-video";
    if (noAudio) args << "--no-audio";

    return args;
}

bool VideoCallManager::startCall(const QString &remoteIp, quint16 remotePort, const QString &key,
                                  quint16 localPort, const QString &quality, bool adaptive,
                                  int width, int height, int fps, int bitrate,
                                  const QString &camera, int audioInput, int audioOutput,
                                  bool noVideo, bool noAudio) {
    if (key.isEmpty()) {
        emit error("Key is required to start a call");
        return false;
    }

    stopCall();

    QString appPath = findVideoCallApp();
    if (appPath.isEmpty()) {
        emit error("Video call application not found");
        return false;
    }

    callProcess = new QProcess(this);
    connect(callProcess, &QProcess::readyReadStandardOutput, this, &VideoCallManager::onProcessOutput);
    connect(callProcess, &QProcess::readyReadStandardError, this, &VideoCallManager::onProcessError);
    connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &VideoCallManager::onProcessFinished);

    QStringList args;
    args << "call" << remoteIp << QString::number(remotePort);
    args << buildArgs(quality, adaptive, width, height, fps, bitrate,
                      camera, audioInput, audioOutput, noVideo, noAudio);
    // Pass identity file if available
    if (!identityFilePath.isEmpty() && QFile::exists(identityFilePath)) {
        args << "--identity-file" << identityFilePath;
    }
    if (localPort > 0) {
        args << QString::number(localPort);
    }

    callProcess->start(appPath, args);

    if (!callProcess->waitForStarted(3000)) {
        emit error("Failed to start video call");
        delete callProcess;
        callProcess = nullptr;
        return false;
    }

    // SECURITY: Pass key via stdin
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = callProcess->write(keyData);
    if (written == -1) {
        emit error("Failed to send key to video call process");
        callProcess->kill();
        callProcess->waitForFinished(1000);
        delete callProcess;
        callProcess = nullptr;
        return false;
    }
    callProcess->closeWriteChannel();

    emit callStarted();
    return true;
}

bool VideoCallManager::startListening(quint16 localPort, const QString &key,
                                       const QString &quality, bool adaptive,
                                       int width, int height, int fps, int bitrate,
                                       const QString &camera, int audioInput, int audioOutput,
                                       bool noVideo, bool noAudio) {
    if (key.isEmpty()) {
        emit error("Key is required to start listening");
        return false;
    }

    stopCall();

    QString appPath = findVideoCallApp();
    if (appPath.isEmpty()) {
        emit error("Video call application not found");
        return false;
    }

    callProcess = new QProcess(this);
    connect(callProcess, &QProcess::readyReadStandardOutput, this, &VideoCallManager::onProcessOutput);
    connect(callProcess, &QProcess::readyReadStandardError, this, &VideoCallManager::onProcessError);
    connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &VideoCallManager::onProcessFinished);

    QStringList args;
    args << "listen" << QString::number(localPort);
    args << buildArgs(quality, adaptive, width, height, fps, bitrate,
                      camera, audioInput, audioOutput, noVideo, noAudio);
    // Pass identity file if available
    if (!identityFilePath.isEmpty() && QFile::exists(identityFilePath)) {
        args << "--identity-file" << identityFilePath;
    }

    callProcess->start(appPath, args);

    if (!callProcess->waitForStarted(3000)) {
        emit error("Failed to start video listening");
        delete callProcess;
        callProcess = nullptr;
        return false;
    }

    // SECURITY: Pass key via stdin
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = callProcess->write(keyData);
    if (written == -1) {
        emit error("Failed to send key to video listening process");
        callProcess->kill();
        callProcess->waitForFinished(1000);
        delete callProcess;
        callProcess = nullptr;
        return false;
    }
    callProcess->closeWriteChannel();

    emit listeningStarted();
    return true;
}

bool VideoCallManager::startRelay(const QString &serverIp, quint16 serverPort,
                                   const QString &room, const QString &name, const QString &key,
                                   const QString &quality, bool adaptive,
                                   int width, int height, int fps, int bitrate,
                                   const QString &camera, int audioInput, int audioOutput,
                                   bool noVideo, bool noAudio) {
    if (key.isEmpty()) {
        emit error("Key is required to start a relay call");
        return false;
    }

    stopCall();

    QString appPath = findVideoCallApp();
    if (appPath.isEmpty()) {
        emit error("Video call application not found");
        return false;
    }

    callProcess = new QProcess(this);
    connect(callProcess, &QProcess::readyReadStandardOutput, this, &VideoCallManager::onProcessOutput);
    connect(callProcess, &QProcess::readyReadStandardError, this, &VideoCallManager::onProcessError);
    connect(callProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &VideoCallManager::onProcessFinished);

    QStringList args;
    args << "relay" << serverIp << QString::number(serverPort)
         << "--room" << room << "--name" << name;
    args << buildArgs(quality, adaptive, width, height, fps, bitrate,
                      camera, audioInput, audioOutput, noVideo, noAudio);
    if (!identityFilePath.isEmpty() && QFile::exists(identityFilePath)) {
        args << "--identity-file" << identityFilePath;
    }

    callProcess->start(appPath, args);

    if (!callProcess->waitForStarted(3000)) {
        emit error("Failed to start video relay call");
        delete callProcess;
        callProcess = nullptr;
        return false;
    }

    // SECURITY: Pass key via stdin
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = callProcess->write(keyData);
    if (written == -1) {
        emit error("Failed to send key to video relay process");
        callProcess->kill();
        callProcess->waitForFinished(1000);
        delete callProcess;
        callProcess = nullptr;
        return false;
    }
    callProcess->closeWriteChannel();

    emit callStarted();
    return true;
}

void VideoCallManager::stopCall() {
    if (callProcess && callProcess->state() == QProcess::Running) {
        callProcess->terminate();
        if (!callProcess->waitForFinished(2000)) {
            callProcess->kill();
        }
    }
    delete callProcess;
    callProcess = nullptr;
    emit callStopped();
}

bool VideoCallManager::isCallActive() const {
    return callProcess && callProcess->state() == QProcess::Running;
}

QString VideoCallManager::getCurrentKey() const {
    return currentKey;
}

void VideoCallManager::onProcessOutput() {
    if (callProcess) {
        QString out = QString::fromUtf8(callProcess->readAllStandardOutput());
        emit this->output(out);
    }
}

void VideoCallManager::onProcessError() {
    if (callProcess) {
        QString err = QString::fromUtf8(callProcess->readAllStandardError());
        // FFmpeg/libvpx print informational messages to stderr;
        // forward as output, not as error, to avoid confusing the user
        emit this->output(err);
    }
}

void VideoCallManager::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitCode);
    Q_UNUSED(exitStatus);
    emit callStopped();
}

QString VideoCallManager::findVideoCallApp() {
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
