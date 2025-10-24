/**
 * @file backend.cpp
 * @brief Implementation of F.E.A.R. CLI backend
 */

#include "backend.h"
#include <QFile>
#include <QDebug>
#include <QGuiApplication>
#include <QClipboard>
#include <QRegularExpression>

Backend::Backend(QObject *parent) : QObject(parent) {
    settings = new QSettings("fear-messenger", "fear-gui", this);
#ifdef Q_OS_WIN
    cliPath = settings->value("cli/path", "fear.exe").toString();
#else
    cliPath = settings->value("cli/path", "fear").toString();
#endif
    clientProc = nullptr;
    serverProc = nullptr;
    lastMessageId = 0;
    isConnected = false;

    // Initialize audio call manager
    audioManager = new AudioCallManager(this);
}

Backend::~Backend() {
    if (clientProc) {
        clientProc->kill();
        clientProc->waitForFinished(200);
        delete clientProc;
    }
    if (serverProc) {
        serverProc->kill();
        serverProc->waitForFinished(200);
        delete serverProc;
    }
}

void Backend::setCliPath(const QString &path) {
    cliPath = path;
    settings->setValue("cli/path", path);
}

bool Backend::connectToServer(const QString &host, int port, const QString &room,
                               const QString &key, const QString &name) {
    if (clientProc) {
        qWarning() << "Client already running";
        return false;
    }

    // Check if executable exists
    if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
#ifdef Q_OS_WIN
        QString defaultPath = "./bin/fear.exe";
        if (!QFile::exists(defaultPath)) {
            emit error("CLI executable not found. Please set the correct path to fear.exe");
            return false;
        }
#else
        QString defaultPath = "./bin/fear";
        if (!QFile::exists(defaultPath)) {
            emit error("CLI executable not found. Please set the correct path to fear");
            return false;
        }
#endif
        cliPath = defaultPath;
    }

    clientProc = new QProcess(this);
    clientProc->setProcessChannelMode(QProcess::MergedChannels);
    connect(clientProc, &QProcess::readyReadStandardOutput, this, &Backend::onClientStdout);
    connect(clientProc, &QProcess::readyReadStandardError, this, &Backend::onClientStderr);
    connect(clientProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &Backend::onClientFinished);

    // SECURITY: Do NOT pass key via --key argument (visible in process list)
    // Instead, we pass it via stdin
    QStringList args;
    args << "client" << "--host" << host << "--port" << QString::number(port)
         << "--room" << room << "--name" << name;
    // NOTE: NO --key argument here for security!

    qDebug() << "Starting client:" << cliPath << "client --host" << host
             << "--port" << port << "--room" << room << "--name" << name
             << "(key passed via stdin)";

    // Set environment variables
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    clientProc->setProcessEnvironment(env);

    clientProc->start(cliPath, args);
    if (!clientProc->waitForStarted(3000)) {
        QString errorMsg = QString("Failed to start client process");
        qWarning() << errorMsg;
        emit error(errorMsg);
        delete clientProc;
        clientProc = nullptr;
        return false;
    }

    // SECURITY: Pass key via stdin (not visible in process list)
    QByteArray keyData = key.toUtf8() + "\n";
    qint64 written = clientProc->write(keyData);
    if (written == -1) {
        qWarning() << "Failed to write key to stdin";
        clientProc->kill();
        clientProc->waitForFinished(1000);
        delete clientProc;
        clientProc = nullptr;
        emit error("Failed to send key to client process");
        return false;
    }

    // NOTE: Do NOT close write channel here - we need to keep it open for sending messages
    // The key has been sent, but we still need stdin for chat messages

    // Consider connection successful after process starts
    isConnected = true;
    emit connected();
    return true;
}

bool Backend::createServer(int port, const QString &name) {
    Q_UNUSED(name);
    if (serverProc) {
        qWarning() << "Server already running";
        return false;
    }

    // Check if executable exists
    if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
#ifdef Q_OS_WIN
        QString defaultPath = "fear.exe";
        if (!QFile::exists(defaultPath)) {
            emit error("CLI executable not found. Please set the correct path to fear.exe");
            return false;
        }
#else
        QString defaultPath = "fear";
        if (!QFile::exists(defaultPath)) {
            emit error("CLI executable not found. Please set the correct path to fear");
            return false;
        }
#endif
        cliPath = defaultPath;
    }

    serverProc = new QProcess(this);
    serverProc->setProcessChannelMode(QProcess::MergedChannels);
    connect(serverProc, &QProcess::readyReadStandardOutput, this, &Backend::onServerStdout);
    connect(serverProc, &QProcess::readyReadStandardError, this, &Backend::onServerStderr);
    connect(serverProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &Backend::onServerFinished);

    QStringList args;
    args << "server" << "--port" << QString::number(port);

    qDebug() << "Starting server:" << cliPath << args;

    // Set environment variables
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    serverProc->setProcessEnvironment(env);

    serverProc->start(cliPath, args);
    if (!serverProc->waitForStarted(3000)) {
        QString errorMsg = QString("Failed to start server: %1 %2").arg(cliPath).arg(args.join(" "));
        qWarning() << errorMsg;
        emit error(errorMsg);
        delete serverProc;
        serverProc = nullptr;
        return false;
    }

    // Wait longer for server to start
    if (serverProc->waitForReadyRead(5000)) {
        QByteArray chunk = serverProc->readAllStandardOutput();
        QString s = QString::fromUtf8(chunk);
        qDebug() << "Server output:" << s;

        if (s.contains("listening", Qt::CaseInsensitive) ||
            s.contains("started", Qt::CaseInsensitive) ||
            s.contains("running", Qt::CaseInsensitive) ||
            s.contains("port", Qt::CaseInsensitive)) {
            emit serverCreated();
            return true;
        } else if (s.contains("error", Qt::CaseInsensitive) ||
                   s.contains("fail", Qt::CaseInsensitive)) {
            emit error(s);
            return false;
        }
    }

    // If we didn't get expected output but process is running, consider it success
    if (serverProc->state() == QProcess::Running) {
        emit serverCreated();
        return true;
    }

    QString errorMsg = "Server failed to start properly";
    qWarning() << errorMsg;
    emit error(errorMsg);
    return false;
}

bool Backend::disconnect() {
    if (clientProc) {
        clientProc->terminate();
        if (!clientProc->waitForFinished(1000)) {
            clientProc->kill();
            clientProc->waitForFinished(500);
        }
        delete clientProc;
        clientProc = nullptr;
    }
    if (serverProc) {
        serverProc->terminate();
        if (!serverProc->waitForFinished(1000)) {
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

bool Backend::sendMessage(const QString &contact, const QString &message) {
    Q_UNUSED(contact);
    if (!clientProc || !isConnected) return false;

    QByteArray data = message.toUtf8();
    data.append('\n');
    qint64 written = clientProc->write(data);

    if (written == -1) {
        qWarning() << "Failed to write to client process";
        return false;
    }

    bool bytesWritten = clientProc->waitForBytesWritten(1000);
    if (!bytesWritten) {
        qWarning() << "Failed to wait for bytes written";
    }

    return written > 0 && bytesWritten;
}

QStringList Backend::listContacts() {
    return QStringList();
}

QStringList Backend::getRecentMessages(int &outLastId) {
    Q_UNUSED(outLastId);
    return QStringList();
}

bool Backend::generateKeypair(const QString &outPath) {
    Q_UNUSED(outPath);  // Not used anymore - genkey writes to room_key.txt

    // Check if executable exists
    if (cliPath.isEmpty() || !QFile::exists(cliPath)) {
        QString defaultPath = "./bin/fear";
        if (!QFile::exists(defaultPath)) {
            defaultPath = "fear";
            if (!QFile::exists(defaultPath)) {
                emit error("CLI executable not found. Please set the correct path to fear");
                return false;
            }
        }
        cliPath = defaultPath;
    }

    QProcess p;
    p.start(cliPath, QStringList() << "genkey");

    if (!p.waitForStarted(2000)) {
        emit error("Failed to start genkey process");
        return false;
    }

    if (!p.waitForFinished(5000)) {
        emit error("Genkey process timed out");
        p.kill();
        return false;
    }

    QString err = QString::fromUtf8(p.readAllStandardError());
    qDebug() << "Genkey stderr:" << err;

    if (p.exitCode() != 0) {
        emit error("Genkey process failed");
        return false;
    }

    // SECURITY: genkey now outputs key to stdout (not saved to file)
    // Read the generated key from stdout
    QString output = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    QString key = output.split('\n').first().trimmed(); // Get first line (the key)

    if (key.isEmpty()) {
        emit error("Generated key is empty");
        return false;
    }

    qDebug() << "Key generated, length:" << key.length();

    // SECURITY: Auto-copy to clipboard for user convenience
    QGuiApplication::clipboard()->setText(key);

    emit keyGenerated(key);
    return true;
}

void Backend::onClientStdout() {
    if (!clientProc) return;

    QByteArray chunk = clientProc->readAllStandardOutput();
    QString s = QString::fromUtf8(chunk);
    qDebug() << "Client stdout:" << s;

    parseClientOutput(s);
}

void Backend::onClientStderr() {
    if (!clientProc) return;

    QByteArray chunk = clientProc->readAllStandardError();
    QString s = QString::fromUtf8(chunk);
    qDebug() << "Client stderr:" << s;

    // If there are errors in stderr, send them as errors
    if (!s.trimmed().isEmpty()) {
        emit error(s);
    }
}

void Backend::onClientFinished(int exitCode, QProcess::ExitStatus status) {
    isConnected = false;
    qDebug() << "Client process finished with exit code:" << exitCode << "status:" << status;

    // Clear process pointer so we can reconnect
    if (clientProc) {
        clientProc->deleteLater();
        clientProc = nullptr;
    }

    emit disconnected();

    // Don't show error - process may have been stopped by user via disconnect
    // Errors will come through stderr if they exist
    Q_UNUSED(exitCode);
    Q_UNUSED(status);
}

void Backend::onServerStdout() {
    if (!serverProc) return;

    QByteArray chunk = serverProc->readAllStandardOutput();
    QString s = QString::fromUtf8(chunk);
    qDebug() << "Server stdout:" << s;

    QStringList lines = s.split('\n', Qt::SkipEmptyParts);
    for (const QString &l : lines) {
        QString t = l.trimmed();
        if (t.isEmpty()) continue;

        emit newMessages(QStringList() << QString("[server] %1").arg(t));

        if (t.contains("listening", Qt::CaseInsensitive)) {
            emit serverCreated();
        }
    }
}

void Backend::onServerStderr() {
    if (!serverProc) return;

    QByteArray chunk = serverProc->readAllStandardError();
    QString s = QString::fromUtf8(chunk);
    qDebug() << "Server stderr:" << s;

    // If there are errors in stderr, send them as errors
    if (!s.trimmed().isEmpty()) {
        emit error(s);
    }
}

void Backend::onServerFinished(int exitCode, QProcess::ExitStatus status) {
    Q_UNUSED(exitCode);
    Q_UNUSED(status);

    qDebug() << "Server process finished";
    emit newMessages(QStringList() << "[server] stopped");
}

void Backend::parseClientOutput(const QString &s) {
    if (s.isEmpty()) return;

    QStringList lines = s.split('\n', Qt::SkipEmptyParts);
    QStringList out;

    for (const QString &l : lines) {
        QString t = l.trimmed();
        if (t.isEmpty()) continue;

        // Check for user list messages
        if (t.startsWith("[USERS]")) {
            // Parse participant list: "[USERS] Room participants (2): Alice, Bob"
            QRegularExpression re("\\[USERS\\].*?:\\s*(.+)$");
            QRegularExpressionMatch m = re.match(t);
            if (m.hasMatch()) {
                QString userListStr = m.captured(1).trimmed();
                QStringList users = userListStr.split(',', Qt::SkipEmptyParts);

                // Clean names from spaces
                for (QString &user : users) {
                    user = user.trimmed();
                }

                emit contactsUpdated(users);
            }
            // Don't add this to out, so it won't be shown in chat
            continue;
        }

        // Check for error messages
        if (t.contains("error", Qt::CaseInsensitive) ||
            t.contains("fail", Qt::CaseInsensitive) ||
            t.contains("cannot", Qt::CaseInsensitive)) {
            emit error(t);
        }

        // Pass through typical client messages
        out << t;
    }

    if (!out.isEmpty()) {
        emit newMessages(out);
    }
}
