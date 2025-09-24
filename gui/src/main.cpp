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

#include "dh.h"

class KeyExchangeDialog : public QDialog {
    Q_OBJECT
public:
    explicit KeyExchangeDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Diffie-Hellman Key Exchange");
        setMinimumSize(600, 500);
        srand(time(NULL));

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // Parameters
        QGroupBox *paramsGroup = new QGroupBox("Parameters", this);
        QFormLayout *paramsLayout = new QFormLayout(paramsGroup);
        pEdit = new QLineEdit(paramsGroup);
        gEdit = new QLineEdit(paramsGroup);
        pubKeyEdit = new QLineEdit(paramsGroup);

        QHBoxLayout *secretLayout = new QHBoxLayout();
        secretKeyEdit = new QLineEdit(paramsGroup);
        secretKeyEdit->setEchoMode(QLineEdit::Password);
        QPushButton *showBtn = new QPushButton("Show", paramsGroup);
        secretLayout->addWidget(secretKeyEdit);
        secretLayout->addWidget(showBtn);

        paramsLayout->addRow("Prime p:", pEdit);
        paramsLayout->addRow("Primitive root g:", gEdit);
        paramsLayout->addRow("Public key:", pubKeyEdit);
        paramsLayout->addRow("Secret key (keep safe!):", secretLayout);
        mainLayout->addWidget(paramsGroup);

        // Data to share
        QGroupBox *shareGroup = new QGroupBox("Data to share with friend", this);
        QVBoxLayout *shareLayout = new QVBoxLayout(shareGroup);
        shareEdit = new QTextEdit(shareGroup);
        shareEdit->setReadOnly(true);
        QPushButton *copyBtn = new QPushButton("Copy to clipboard", shareGroup);
        shareLayout->addWidget(shareEdit);
        shareLayout->addWidget(copyBtn);
        mainLayout->addWidget(shareGroup);

        // Encrypted/Decrypted key
        QGroupBox *encGroup = new QGroupBox("Encryption", this);
        QFormLayout *encLayout = new QFormLayout(encGroup);
        origKeyEdit = new QLineEdit(encGroup);
        friendPubKeyEdit = new QLineEdit(encGroup);
        encryptedEdit = new QLineEdit(encGroup);
        decryptedEdit = new QLineEdit(encGroup);
        encLayout->addRow("Key to send:", origKeyEdit);
        encLayout->addRow("Friend's public key:", friendPubKeyEdit);
        encLayout->addRow("Encrypted (hex):", encryptedEdit);
        encLayout->addRow("Decrypted:", decryptedEdit);
        mainLayout->addWidget(encGroup);

        // Buttons
        QHBoxLayout *btnLayout = new QHBoxLayout();
        QPushButton *genBtn = new QPushButton("Generate parameters", this);
        QPushButton *genPubBtn = new QPushButton("Generate public key", this);
        QPushButton *encryptBtn = new QPushButton("Encrypt", this);
        QPushButton *decryptBtn = new QPushButton("Decrypt", this);
        QPushButton *closeBtn = new QPushButton("Close", this);
        btnLayout->addWidget(genBtn);
        btnLayout->addWidget(genPubBtn);
        btnLayout->addWidget(encryptBtn);
        btnLayout->addWidget(decryptBtn);
        btnLayout->addStretch();
        btnLayout->addWidget(closeBtn);
        mainLayout->addLayout(btnLayout);

        // === Connections ===
        connect(copyBtn, &QPushButton::clicked, this, [this]() {
            QGuiApplication::clipboard()->setText(shareEdit->toPlainText());
            QMessageBox::information(this, "Copied", "Shared data copied to clipboard.");
        });
        connect(genBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onGenerate);
        connect(genPubBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onGeneratePublicOnly);
        connect(encryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onEncrypt);
        connect(decryptBtn, &QPushButton::clicked, this, &KeyExchangeDialog::onDecrypt);
        connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

        // Show/Hide secret key
        connect(showBtn, &QPushButton::clicked, this, [this, showBtn]() {
            if (secretKeyEdit->echoMode() == QLineEdit::Password) {
                secretKeyEdit->setEchoMode(QLineEdit::Normal);
                showBtn->setText("Hide");
            } else {
                secretKeyEdit->setEchoMode(QLineEdit::Password);
                showBtn->setText("Show");
            }
        });
    }

private slots:
    void onGenerate() {
        int p = dh_generate_large_prime(10000, 50000);
        int g = dh_find_primitive_root(p);
        int priv = dh_generate_random_number(2, p - 2);
        long long pub = dh_mod_pow(g, priv, p);

        pEdit->setText(QString::number(p));
        gEdit->setText(QString::number(g));
        pubKeyEdit->setText(QString::number(pub));
        secretKeyEdit->setText(QString::number(priv));

        QString shareData = QString("Prime p = %1\nPrimitive root g = %2\nPublic key = %3").arg(p).arg(g).arg(pub);
        shareEdit->setPlainText(shareData);
    }

    void onGeneratePublicOnly() {
        bool ok;
        int p = pEdit->text().toInt(&ok);
        if (!ok || p <= 0) {
            QMessageBox::warning(this, "Error", "Enter valid prime number p first.");
            return;
        }
        int g = gEdit->text().toInt(&ok);
        if (!ok || g <= 0) {
            QMessageBox::warning(this, "Error", "Enter valid primitive root g first.");
            return;
        }

        int priv = dh_generate_random_number(2, p - 2);
        long long pub = dh_mod_pow(g, priv, p);

        pubKeyEdit->setText(QString::number(pub));
        secretKeyEdit->setText(QString::number(priv));

        QString shareData = QString("Public key = %1").arg(pub);
        shareEdit->setPlainText(shareData);
        // QMessageBox::information(this, "Done", "Public key generated. Share it with sender.");
    }

    void onEncrypt() {
        bool ok;
        int p = pEdit->text().toInt(&ok);
        if (!ok) return;
        int priv = secretKeyEdit->text().toInt(&ok);
        if (!ok) return;
        long long friendPub = friendPubKeyEdit->text().toLongLong(&ok);
        if (!ok) return;

        long long shared = dh_mod_pow(friendPub, priv, p);
        QString key = origKeyEdit->text();
        if (key.isEmpty()) return;

        char enc[256], hex[512];
        dh_xor_encrypt_decrypt(key.toUtf8().data(), enc, shared, key.length());
        dh_binary_to_hex(enc, hex, key.length());
        encryptedEdit->setText(QString(hex));

        QMessageBox::information(this, "Done",
                                 QString("Encrypted with shared secret: %1").arg(shared));
    }

    void onDecrypt() {
        bool ok;
        int p = pEdit->text().toInt(&ok);
        if (!ok) return;
        int priv = secretKeyEdit->text().toInt(&ok);
        if (!ok) return;
        long long friendPub = friendPubKeyEdit->text().toLongLong(&ok);
        if (!ok) return;

        long long shared = dh_mod_pow(friendPub, priv, p);
        QString hex = encryptedEdit->text();
        if (hex.isEmpty()) return;

        int len = hex.length() / 2;
        char bin[256], dec[256];
        dh_hex_to_binary(hex.toUtf8().data(), bin, hex.length());
        dh_xor_encrypt_decrypt(bin, dec, shared, len);
        decryptedEdit->setText(QString(dec));
    }

private:
    QLineEdit *pEdit, *gEdit, *pubKeyEdit, *secretKeyEdit;
    QTextEdit *shareEdit;
    QLineEdit *origKeyEdit, *friendPubKeyEdit, *encryptedEdit, *decryptedEdit;
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

    bool startCall(const QString &remoteIp, quint16 remotePort, const QString &key, quint16 localPort = 0) {
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

    bool startListening(quint16 localPort, const QString &key) {
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
        setMinimumSize(500, 400);

        setupUI();
        setupConnections();
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

        if (audioManager->startCall(remoteIp, remotePort, key, localPortSpin->value())) {
            statusLabel->setText("Call started");
        }
    }

    void onStartListening() {
        QString key = keyEdit->text();
        if (key.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please generate or enter a key first");
            return;
        }

        if (audioManager->startListening(localPortSpin->value(), key)) {
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
        connect(callButton, &QPushButton::clicked, this, &AudioCallDialog::onStartCall);
        connect(listenButton, &QPushButton::clicked, this, &AudioCallDialog::onStartListening);
        connect(stopButton, &QPushButton::clicked, this, &AudioCallDialog::onStopCall);
    }

    AudioCallManager *audioManager;
    QLineEdit *keyEdit;
    QLineEdit *ipEdit;
    QSpinBox *portSpin;
    QSpinBox *localPortSpin;
    QPushButton *genKeyButton;
    QPushButton *callButton;
    QPushButton *listenButton;
    QPushButton *stopButton;
    QLabel *statusLabel;
    QTextEdit *outputText;
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
        Q_UNUSED(exitCode);
        Q_UNUSED(status);

        isConnected = false;
        qDebug() << "Client process finished with exit code:" << exitCode;
        emit disconnected();

        if (exitCode != 0) {
            emit error(QString("Client process exited with error code: %1").arg(exitCode));
        }
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
private slots:

    void onAudioCall() {
        AudioCallDialog dialog(backend->audioManager, this);
        dialog.exec();
    }

    void onKeyExchange() {
        KeyExchangeDialog dlg(this);
        dlg.exec();
    }

    void onCreateServer(){
        bool ok;
        int defaultPort = appSettings->value("last/port", 7777).toInt();
        int port = QInputDialog::getInt(this, "Create Server", "Port:", defaultPort, 1, 65535, 1, &ok);
        if(!ok) return;

        QString name = QInputDialog::getText(this, "Create Server", "Your name:");
        if(name.isEmpty()) return;

        bool success = backend->createServer(port, name);
        if(success){
            appSettings->setValue("last/port", port);
            QMessageBox::information(this, "Create Server", "Server created successfully.");
        } else {
            QMessageBox::warning(this, "Create Server", "Failed to create server. Check if port is available and CLI path is correct.");
        }
    }

    void onConnect(){
        QString hostDef = appSettings->value("last/host", "127.0.0.1").toString();
        int portDef = appSettings->value("last/port", 7777).toInt();
        QString roomDef = appSettings->value("last/room", "testroom").toString();
        QString keyDef = appSettings->value("last/key", "").toString();
        QString nameDef = appSettings->value("last/name", "").toString();

        QString host = QInputDialog::getText(this, "Connect", "Host:", QLineEdit::Normal, hostDef);
        if(host.isEmpty()) return;

        bool ok;
        int port = QInputDialog::getInt(this, "Connect", "Port:", portDef, 1, 65535, 1, &ok);
        if(!ok) return;

        QString room = QInputDialog::getText(this, "Connect", "Room name:", QLineEdit::Normal, roomDef);
        if(room.isEmpty()) return;

        QString key = QInputDialog::getText(this, "Connect", "Room key (shared secret):", QLineEdit::Normal, keyDef);
        if(key.isEmpty()){
            QMessageBox::warning(this, "Connect", "Room key is required to join private rooms.");
            return;
        }

        QString name = QInputDialog::getText(this, "Connect", "Your name:", QLineEdit::Normal, nameDef);
        if(name.isEmpty()) return;

        // Показываем индикатор прогресса
        QProgressDialog progress("Connecting to server...", "Cancel", 0, 0, this);
        progress.setWindowModality(Qt::WindowModal);
        progress.show();

        QApplication::processEvents(); // Обрабатываем события для отображения диалога

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

private:
    Backend *backend;
    QListWidget *contactsWidget;
    QTextEdit *chatView;
    QLineEdit *inputEdit;
    QLabel *statusLabel;
    QSettings *appSettings;

    QAction *connectAction;
    QAction *disconnectAction;

    QString currentContact(){
        QListWidgetItem *it = contactsWidget->currentItem();
        return it ? it->text() : QString();
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

        QAction *serveAct = new QAction("Create server...", this);
        connect(serveAct, &QAction::triggered, this, &MainWindow::onCreateServer);
        connMenu->addAction(serveAct);

        QMenu *audioMenu = menuBar()->addMenu("Audio Call");
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

        QMenu *helpMenu = menuBar()->addMenu("Help");
        QAction *update = new QAction("Check for updates", this);
        connect(update, &QAction::triggered, this, [this](){
            UpdateDialog dialog(this, backend->cliPath);
            dialog.exec();
        });
        helpMenu->addAction(update);

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
        chatView = new QTextEdit(right);
        chatView->setReadOnly(true);
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

    void createStatusBar(){
        statusLabel = new QLabel("Disconnected", this);
        statusBar()->addPermanentWidget(statusLabel);
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
