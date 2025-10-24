/**
 * @file mainwindow.cpp
 * @brief Implementation of main application window
 */

#include "mainwindow.h"
#include "keyexchangedialog.h"
#include "audiocalldialog.h"
#include "updatedialog.h"
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QSpinBox>
#include <QDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QFontDialog>
#include <QInputDialog>
#include <QProgressDialog>
#include <QTimer>
#include <QKeyEvent>
#include <QApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QGuiApplication>
#include <QClipboard>
#include <QRegularExpression>
#include <QDebug>
#include <QDir>
#include <QPainter>
#include <QPixmap>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("F.E.A.R. Project GUI");
    resize(1000, 640);

    appSettings = new QSettings("fear-messenger", "fear-gui", this);
    backend = new Backend(this);

    // Initialize chat font
    chatFont = QFont("Arial", 10);

    // Initialize tray variables
    unreadMessages = 0;
    isHidden = false;

    createActions();
    createMenus();
    createToolbar();
    createCentral();
    createStatusBar();
    createTrayIcon();

    // Connect backend signals
    connect(backend, &Backend::contactsUpdated, this, &MainWindow::onContactsUpdated);
    connect(backend, &Backend::newMessages, this, &MainWindow::onNewMessages);
    connect(backend, &Backend::connected, this, [this]() {
        statusLabel->setText("Connected");
        connectAction->setEnabled(false);
        disconnectAction->setEnabled(true);
    });
    connect(backend, &Backend::disconnected, this, [this]() {
        statusLabel->setText("Disconnected");
        connectAction->setEnabled(true);
        disconnectAction->setEnabled(false);
        contactsWidget->clear();  // Clear participant list on disconnect
    });
    connect(backend, &Backend::serverCreated, this, &MainWindow::onServerStarted);
    connect(backend, &Backend::keyGenerated, this, &MainWindow::onKeyGenerated);
    connect(backend, &Backend::error, this, &MainWindow::onError);

    // Initial refresh of contacts (non-blocking attempt)
    QTimer::singleShot(100, this, &MainWindow::refreshContacts);
}

QString MainWindow::getCliPath() const {
    return backend->cliPath;
}

void MainWindow::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_F1) {
        onOpenDocumentation();
    }
    QMainWindow::keyPressEvent(event);
}

void MainWindow::changeEvent(QEvent *event) {
    if (event->type() == QEvent::WindowStateChange) {
        if (isMinimized()) {
            // Hide to tray when minimized
            QTimer::singleShot(0, this, &MainWindow::hideToTray);
        }
    }
    QMainWindow::changeEvent(event);
}

void MainWindow::onSendFile() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select file to send", QDir::homePath());
    if (filePath.isEmpty()) {
        return;
    }

    // Check if file exists
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        QMessageBox::warning(this, "Send File", "Selected file does not exist or is not a valid file.");
        return;
    }

    // Get absolute path (in case of relative paths)
    QString absolutePath = QDir::toNativeSeparators(fileInfo.absoluteFilePath());

    // Form command to send
    QString command = QString("/sendfile %1").arg(absolutePath);

    // Send command through backend
    QString contact = currentContact();
    bool ok = backend->sendMessage(contact, command);

    if (ok) {
        // Get user name from settings
        QString userName = appSettings->value("last/name", "Me").toString();
        if (userName.isEmpty()) {
            userName = "Me";
        }
        // Show in chat that command was sent
        appendChatLine(QString("[%1] %2: /sendfile \"%3\"")
                      .arg(QDateTime::currentDateTime().toString("HH:mm:ss"),
                           userName,
                           fileInfo.fileName()));

        // Don't show success message to avoid interruption
        qDebug() << "File send command sent:" << command;
    } else {
        QMessageBox::warning(this, "Send File",
            "Failed to send file command. Check connection.");
    }
}

void MainWindow::onClearChat() {
    if (QMessageBox::question(this, "Clear Chat",
        "Are you sure you want to clear the chat history?",
        QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        chatView->clear();
    }
}

void MainWindow::onFontSettings() {
    bool ok;
    QFont font = QFontDialog::getFont(&ok, chatFont, this, "Select Chat Font");
    if (ok) {
        chatFont = font;
        chatView->setFont(chatFont);
        appSettings->setValue("chat/font", chatFont.toString());
    }
}

void MainWindow::onAudioCall() {
    AudioCallDialog dialog(backend->audioManager, this);
    dialog.exec();
}

void MainWindow::onKeyExchange() {
    KeyExchangeDialog dlg(this);
    dlg.exec();
}

void MainWindow::onCreateServer() {
    // Create server configuration dialog
    QDialog dialog(this);
    dialog.setWindowTitle("Create Server");
    dialog.setMinimumWidth(400);

    QFormLayout *formLayout = new QFormLayout(&dialog);

    // Server port
    QSpinBox *portSpin = new QSpinBox(&dialog);
    portSpin->setRange(1, 65535);
    portSpin->setValue(appSettings->value("last/port", 7777).toInt());
    formLayout->addRow("Port:", portSpin);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *createButton = new QPushButton("Create Server", &dialog);
    QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
    buttonLayout->addWidget(createButton);
    buttonLayout->addWidget(cancelButton);

    formLayout->addRow(buttonLayout);

    // Connect buttons
    connect(createButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    // Show dialog
    if (dialog.exec() == QDialog::Accepted) {
        int port = portSpin->value();

        // Show progress indicator
        QProgressDialog progress("Creating server...", "Cancel", 0, 0, this);
        progress.setWindowModality(Qt::WindowModal);
        progress.show();
        QApplication::processEvents();

        bool success = backend->createServer(port, "Server");

        progress.close();

        if (success) {
            appSettings->setValue("last/port", port);
            QMessageBox::information(this, "Create Server", "Server created successfully.");
        } else {
            QMessageBox::warning(this, "Create Server", "Failed to create server. Check if port is available and CLI path is correct.");
        }
    }
}

void MainWindow::onConnect() {
    // Create connection dialog
    QDialog dialog(this);
    dialog.setWindowTitle("Connect to Server");
    dialog.setMinimumWidth(500);

    QFormLayout *formLayout = new QFormLayout(&dialog);

    // Host
    QLineEdit *hostEdit = new QLineEdit(&dialog);
    hostEdit->setText(appSettings->value("last/host", "127.0.0.1").toString());
    formLayout->addRow("Host:", hostEdit);

    // Port
    QSpinBox *portSpin = new QSpinBox(&dialog);
    portSpin->setRange(1, 65535);
    portSpin->setValue(appSettings->value("last/port", 7777).toInt());
    formLayout->addRow("Port:", portSpin);

    // Room
    QLineEdit *roomEdit = new QLineEdit(&dialog);
    roomEdit->setText(appSettings->value("last/room", "testroom").toString());
    formLayout->addRow("Room name:", roomEdit);

    // Room key - SECURE MODE (not saved)
    QLineEdit *keyEdit = new QLineEdit(&dialog);
    // SECURITY: Never load key from settings (it should not be stored on disk)
    keyEdit->setPlaceholderText("Enter room key (not saved for security)");
    formLayout->addRow("Room key:", keyEdit);

    // User name
    QLineEdit *nameEdit = new QLineEdit(&dialog);
    nameEdit->setText(appSettings->value("last/name", "").toString());
    formLayout->addRow("Your name:", nameEdit);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *connectButton = new QPushButton("Connect", &dialog);
    QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
    buttonLayout->addWidget(connectButton);
    buttonLayout->addWidget(cancelButton);

    formLayout->addRow(buttonLayout);

    // Connect buttons
    connect(connectButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    // Show dialog
    if (dialog.exec() == QDialog::Accepted) {
        QString host = hostEdit->text().trimmed();
        int port = portSpin->value();
        QString room = roomEdit->text().trimmed();
        QString key = keyEdit->text().trimmed();
        QString name = nameEdit->text().trimmed();

        // Validate input data
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

        // Show progress indicator
        QProgressDialog progress("Connecting to server...", "Cancel", 0, 0, this);
        progress.setWindowModality(Qt::WindowModal);
        progress.show();
        QApplication::processEvents();

        bool success = backend->connectToServer(host, port, room, key, name);

        progress.close();

        if (success) {
            appSettings->setValue("last/host", host);
            appSettings->setValue("last/port", port);
            appSettings->setValue("last/room", room);
            // SECURITY: DO NOT save key to disk (removed: appSettings->setValue("last/key", key);)
            appSettings->setValue("last/name", name);
            QMessageBox::information(this, "Connect", "Connected successfully.");
        } else {
            QMessageBox::warning(this, "Connect", "Failed to connect. Check server availability and credentials.");
        }
    }
}

void MainWindow::onDisconnect() {
    backend->disconnect();
    QMessageBox::information(this, "Disconnected", "Disconnected from server.");
}

void MainWindow::onSend() {
    QString message = inputEdit->text();
    if (message.isEmpty()) return;

    QString contact = currentContact();
    bool ok = backend->sendMessage(contact, message);

    if (ok) {
        // Don't append here - message will come back through backend
        inputEdit->clear();
    } else {
        QMessageBox::warning(this, "Send", "Failed to send message. Check connection.");
    }
}

void MainWindow::onContactsUpdated(const QStringList &contacts) {
    contactsWidget->clear();
    contactsWidget->addItems(contacts);
}

void MainWindow::onNewMessages(const QStringList &messages) {
    for (const QString &m : messages) {
        appendChatLine(m);
    }

    // Track unread messages if window is hidden
    if (isHidden && !messages.isEmpty()) {
        unreadMessages += messages.count();
        updateTrayIcon();

        // Show notification
        if (trayIcon && trayIcon->isVisible()) {
            QString notificationText;
            if (messages.count() == 1) {
                notificationText = "New message";
            } else {
                notificationText = QString("%1 new messages").arg(messages.count());
            }
            trayIcon->showMessage("F.E.A.R. Messenger", notificationText,
                                 QSystemTrayIcon::Information, 3000);
        }
    }
}

void MainWindow::onError(const QString &error) {
    QMessageBox::warning(this, "Error", error);
    statusLabel->setText("Error: " + error.left(20) + "...");
}

void MainWindow::refreshContacts() {
    QStringList contacts = backend->listContacts();
    onContactsUpdated(contacts);
}

void MainWindow::onSelectContact() {
    QString contact = currentContact();
    chatView->clear();
}

void MainWindow::onSetCliPath() {
#ifdef Q_OS_WIN
    QString file = QFileDialog::getOpenFileName(this, "Select CLI executable", QString(), "Executable files (*.exe);;All files (*)");
#else
    QString file = QFileDialog::getOpenFileName(this, "Select CLI executable", QString(), "All files (*)");
#endif
    if (file.isEmpty()) return;

    backend->setCliPath(file);
    appSettings->setValue("cli/path", file);
    QMessageBox::information(this, "CLI Path", QString("CLI set to: %1").arg(file));
}

void MainWindow::onGenKeys() {
    bool ok = backend->generateKeypair((QString)"");   // Fix workaround: window for file name was deleted but onGenKeys() method is still required
}

void MainWindow::onKeyGenerated(const QString &key) {
    QDialog dlg(this);
    dlg.setWindowTitle("Generated room key");
    dlg.setMinimumWidth(400);
    QVBoxLayout *v = new QVBoxLayout(&dlg);

    // Info label with clipboard notice
    QLabel *infoLbl = new QLabel("<b>Room key generated and copied to clipboard!</b>", &dlg);
    infoLbl->setStyleSheet("color: green; padding: 5px;");
    v->addWidget(infoLbl);

    QLabel *lbl = new QLabel("Room key (base64 urlsafe):", &dlg);
    v->addWidget(lbl);

    QLineEdit *keyEdit = new QLineEdit(key, &dlg);
    keyEdit->setReadOnly(true);
    keyEdit->setSelection(0, key.length());
    v->addWidget(keyEdit);

    // Warning label
    QLabel *warningLbl = new QLabel("⚠ SECURITY: Share this key securely with participants only.\nDo NOT save to disk unless absolutely necessary.", &dlg);
    warningLbl->setStyleSheet("color: red; padding: 5px;");
    warningLbl->setWordWrap(true);
    v->addWidget(warningLbl);

    QHBoxLayout *h = new QHBoxLayout();
    QPushButton *copyBtn = new QPushButton("Copy again", &dlg);
    QPushButton *saveBtn = new QPushButton("Save to file...", &dlg);
    QPushButton *closeBtn = new QPushButton("Close", &dlg);

    h->addWidget(copyBtn);
    h->addWidget(saveBtn);
    h->addWidget(closeBtn);
    v->addLayout(h);

    connect(copyBtn, &QPushButton::clicked, this, [keyEdit]() {
        QGuiApplication::clipboard()->setText(keyEdit->text());
        QMessageBox::information(nullptr, "Copied", "Key copied to clipboard");
    });

    connect(saveBtn, &QPushButton::clicked, this, [&dlg, key]() {
        QString file = QFileDialog::getSaveFileName(&dlg, "Save key to...", "roomkey.txt", "Text files (*.txt);;All files (*)");
        if (!file.isEmpty()) {
            QFile f(file);
            if (f.open(QIODevice::WriteOnly)) {
                f.write(key.toUtf8());
                f.close();
                QMessageBox::information(&dlg, "Saved", "Key saved to file.\n\nREMEMBER: Delete this file after sharing the key!");
            }
        }
    });

    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}

void MainWindow::onServerStarted() {
    statusLabel->setText("Server: listening");
    disconnectAction->setEnabled(true);
    appendChatLine("[server] listening");
}

void MainWindow::onOpenDocumentation() {
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

QString MainWindow::currentContact() {
    QListWidgetItem *it = contactsWidget->currentItem();
    return it ? it->text() : QString();
}

void MainWindow::createStatusBar() {
    statusLabel = new QLabel("Disconnected", this);
    statusBar()->addPermanentWidget(statusLabel);
}

void MainWindow::appendChatLine(const QString &line) {
    // Parse lines like: [16:54:43] Admin: message
    static QRegularExpression re("^\\s*\\[(\\d{2}:\\d{2}:\\d{2})\\]\\s*([^:]+):\\s*(.*)$");
    QRegularExpressionMatch m = re.match(line);

    if (m.hasMatch()) {
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

void MainWindow::createActions() {
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

void MainWindow::createMenus() {
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
    connect(update, &QAction::triggered, this, [this]() {
        UpdateDialog dialog(this, backend->cliPath);
        dialog.exec();
    });
    helpMenu->addAction(update);

    QAction *docAction = new QAction("Documentation", this);
    connect(docAction, &QAction::triggered, this, &MainWindow::onOpenDocumentation);
    helpMenu->addAction(docAction);

    QAction *about = new QAction("About", this);
    connect(about, &QAction::triggered, this, [this]() {
        // Create custom dialog window
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

void MainWindow::createToolbar() {
    QToolBar *tb = addToolBar("Main");
    tb->addAction(connectAction);
    tb->addAction(disconnectAction);
    tb->addSeparator();

    QAction *refreshAct = new QAction("Refresh contacts", this);
    connect(refreshAct, &QAction::triggered, this, &MainWindow::refreshContacts);
    tb->addAction(refreshAct);
}

void MainWindow::createCentral() {
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
    connect(newChat, &QPushButton::clicked, this, [this]() {
        bool ok;
        QString name = QInputDialog::getText(this, "New chat", "Contact name:", QLineEdit::Normal, QString(), &ok);
        if (ok && !name.isEmpty()) {
            contactsWidget->addItem(name);
        }
    });
    leftLayout->addWidget(newChat);

    // Right: chat area
    QWidget *right = new QWidget(this);
    QVBoxLayout *rightLayout = new QVBoxLayout(right);

    // Add chat toolbar
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

    // Load saved font settings
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

void MainWindow::createTrayIcon() {
    // Create tray menu
    trayMenu = new QMenu(this);

    QAction *showAction = new QAction("Show", this);
    connect(showAction, &QAction::triggered, this, &MainWindow::showFromTray);
    trayMenu->addAction(showAction);

    trayMenu->addSeparator();
    trayMenu->addAction(connectAction);
    trayMenu->addAction(disconnectAction);

    trayMenu->addSeparator();
    QAction *quitAction = new QAction("Quit", this);
    connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
    trayMenu->addAction(quitAction);

    // Create tray icon
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayMenu);
    trayIcon->setToolTip("F.E.A.R. Messenger");

    // Set initial icon
    updateTrayIcon();

    // Connect activation signal (for clicking on icon)
    connect(trayIcon, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayIconActivated);

    // Show tray icon
    trayIcon->show();
}

void MainWindow::updateTrayIcon() {
    // Load base icon
    QIcon baseIcon(":/icons/logo.ico");
    if (baseIcon.isNull()) {
        // Fallback if icon not found
        baseIcon = style()->standardIcon(QStyle::SP_ComputerIcon);
    }

    if (unreadMessages > 0) {
        // Create pixmap with badge
        QPixmap pixmap = baseIcon.pixmap(64, 64);
        QPainter painter(&pixmap);

        // Draw red circle badge
        int badgeSize = 24;
        int x = pixmap.width() - badgeSize - 2;
        int y = 2;

        // Red background
        painter.setBrush(QBrush(QColor(255, 0, 0)));
        painter.setPen(QPen(QColor(255, 255, 255), 2));
        painter.setRenderHint(QPainter::Antialiasing);
        painter.drawEllipse(x, y, badgeSize, badgeSize);

        // White text with count (if <= 99)
        if (unreadMessages <= 99) {
            painter.setPen(QColor(255, 255, 255));
            QFont font = painter.font();
            font.setPixelSize(12);
            font.setBold(true);
            painter.setFont(font);
            painter.drawText(QRect(x, y, badgeSize, badgeSize),
                           Qt::AlignCenter,
                           QString::number(unreadMessages));
        } else {
            // Just show "99+"
            painter.setPen(QColor(255, 255, 255));
            QFont font = painter.font();
            font.setPixelSize(10);
            font.setBold(true);
            painter.setFont(font);
            painter.drawText(QRect(x, y, badgeSize, badgeSize),
                           Qt::AlignCenter,
                           "99+");
        }

        painter.end();
        trayIcon->setIcon(QIcon(pixmap));
    } else {
        // No unread messages, use base icon
        trayIcon->setIcon(baseIcon);
    }
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
        // Single or double click - show window
        showFromTray();
    }
}

void MainWindow::showFromTray() {
    show();
    setWindowState(Qt::WindowActive);
    activateWindow();
    raise();
    isHidden = false;

    // Reset unread counter
    unreadMessages = 0;
    updateTrayIcon();
}

void MainWindow::hideToTray() {
    hide();
    isHidden = true;

    // Show notification only if there are unread messages
    if (trayIcon && trayIcon->isVisible() && unreadMessages > 0) {
        QString notificationText;
        if (unreadMessages == 1) {
            notificationText = "You have 1 unread message";
        } else {
            notificationText = QString("You have %1 unread messages").arg(unreadMessages);
        }
        trayIcon->showMessage("F.E.A.R. Messenger",
                             notificationText,
                             QSystemTrayIcon::Information,
                             2000);
    }
}
