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
            QString defaultPath = "fear.exe";
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

private slots:
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
        statusLabel->setText("Error: " + error.left(20) + "..."); // Ограничиваем длину для статусбара
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
        QString out = QFileDialog::getSaveFileName(this, "Save genkey full output to...", QString(), "Text files (*.txt);;All files (*)");
        bool ok = backend->generateKeypair(out);

        if(!ok){
            QMessageBox::warning(this, "Generate Keys", "Failed to generate keypair. Check if fear.exe is in PATH or set CLI path.");
        }
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
            QMessageBox::information(nullptr, "Copied", "Key copied to clipboard");
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
        QAction *setCli = new QAction("Set CLI path...", this);
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

        QMenu *keysMenu = menuBar()->addMenu("Keys");
        QAction *genKeys = new QAction("Generate keypair...", this);
        connect(genKeys, &QAction::triggered, this, &MainWindow::onGenKeys);
        keysMenu->addAction(genKeys);

        QMenu *helpMenu = menuBar()->addMenu("Help");
        QAction *about = new QAction("About", this);
        connect(about, &QAction::triggered, this, [this](){
            QMessageBox::about(this, "About F.E.A.R.",
                               "F.E.A.R. messenger GUI\n"
                               "Qt-based frontend for ecrypted anonymous messenger.\n"
                               "Read more at:.\n"
                               "https://github.com/shchuchkin-pkims/fear");
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
