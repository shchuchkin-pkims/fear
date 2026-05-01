#include "chatwindow.h"
#include "widgets/sidebar.h"
#include "widgets/chatarea.h"
#include "widgets/chatlistitem.h"
#include "theme/theme.h"
#include "connectiondialog.h"
#include "backend.h"
#include "audiocalldialog.h"
#include "videocalldialog.h"
#include "settingsdialog.h"
#include "knownkeysdialog.h"

#include <QSplitter>
#include <QApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QCursor>
#include <QShowEvent>
#include <QTimer>
#include <QRegularExpression>
#include <QMessageBox>
#include <QMenu>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QSettings>

namespace fear {

ChatWindow::ChatWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("F.E.A.R."));
    resize(1200, 780);

    if (QScreen *s = QGuiApplication::screenAt(QCursor::pos())) {
        const QRect g = s->availableGeometry();
        move(g.x() + (g.width() - 1200) / 2, g.y() + (g.height() - 780) / 2);
    }

    // Restore last-used theme (default Dark on first launch).
    {
        QSettings s("fear-messenger", "fear-gui");
        const int saved = s.value("theme/mode", int(Theme::Dark)).toInt();
        Theme::instance().setMode(Theme::Mode(saved == int(Theme::Light) ? Theme::Light : Theme::Dark));
    }
    if (auto *app = qobject_cast<QApplication*>(QApplication::instance())) {
        app->setStyleSheet(Theme::instance().styleSheet());
    }
    // Whenever the theme changes, push the new stylesheet to the application.
    connect(&Theme::instance(), &Theme::modeChanged, this, [](Theme::Mode){
        if (auto *app = qobject_cast<QApplication*>(QApplication::instance())) {
            app->setStyleSheet(Theme::instance().styleSheet());
        }
    });

    m_sidebar  = new Sidebar(this);
    m_chatArea = new ChatArea(this);

    m_split = new QSplitter(Qt::Horizontal, this);
    m_split->addWidget(m_sidebar);
    m_split->addWidget(m_chatArea);
    m_split->setStretchFactor(0, 0);
    m_split->setStretchFactor(1, 1);
    m_split->setSizes({330, 870});
    m_split->setHandleWidth(1);
    m_split->setChildrenCollapsible(false);

    setCentralWidget(m_split);

    m_backend = new Backend(this);

    // Backend → UI
    connect(m_backend, &Backend::connected,         this, &ChatWindow::handleConnected);
    connect(m_backend, &Backend::disconnected,      this, &ChatWindow::handleDisconnected);
    connect(m_backend, &Backend::newMessages,       this, &ChatWindow::handleNewMessages);
    connect(m_backend, &Backend::contactsUpdated,   this, &ChatWindow::handleContactsUpdated);
    connect(m_backend, &Backend::error,             this, &ChatWindow::handleError);

    // UI → Backend
    connect(m_chatArea, &ChatArea::sendRequested, this, [this](const QString &text) {
        if (!m_backend->isConnected) {
            handleError(tr("Not connected. Click ☰ to connect."));
            return;
        }
        m_backend->sendMessage(QString(), text);
    });

    connect(m_sidebar,  &Sidebar::menuRequested,        this, &ChatWindow::onSidebarMenu);
    connect(m_chatArea, &ChatArea::audioCallRequested,  this, &ChatWindow::onAudioCallRequested);
    connect(m_chatArea, &ChatArea::videoCallRequested,  this, &ChatWindow::onVideoCallRequested);
    connect(m_chatArea, &ChatArea::attachRequested,     this, &ChatWindow::onAttachRequested);

    // Initial empty state
    m_chatArea->showEmptyState(tr("Click ☰ to connect to a room."));
}

void ChatWindow::showEvent(QShowEvent *e) {
    QMainWindow::showEvent(e);
    if (!m_connectShown) {
        m_connectShown = true;
        QTimer::singleShot(0, this, &ChatWindow::requestConnect);
    }
}

void ChatWindow::requestConnect() {
    if (m_backend->isConnected) {
        if (QMessageBox::question(this, tr("Reconnect?"),
                tr("Already connected. Disconnect and connect to a different room?"),
                QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return;
        }
        m_backend->disconnect();
    }

    ConnectionDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;

    if (dlg.host().isEmpty() || dlg.room().isEmpty() || dlg.name().isEmpty()) {
        QMessageBox::warning(this, tr("Connect"),
            tr("Server, room and name are required."));
        QTimer::singleShot(0, this, &ChatWindow::requestConnect);
        return;
    }
    if (dlg.mode() == Backend::MANUAL_KEY && dlg.key().isEmpty()) {
        QMessageBox::warning(this, tr("Connect"),
            tr("Room key is required for the “Use key” mode."));
        QTimer::singleShot(0, this, &ChatWindow::requestConnect);
        return;
    }

    dlg.saveToSettings();

    m_lastMode = dlg.mode();
    m_connectStarted = QDateTime::currentDateTime();
    if (!m_backend->connectToServer(dlg.host(), dlg.port(), dlg.room(),
                                    dlg.key(), dlg.name(), dlg.mode())) {
        QMessageBox::warning(this, tr("Connect"),
            tr("Failed to start connection. Check the CLI path in Settings."));
    }
}

void ChatWindow::handleConnected() {
    ChatListEntry e;
    e.id           = m_backend->currentRoom;
    e.title        = m_backend->currentRoom;
    e.preview      = QString();
    e.lastActivity = QDateTime::currentDateTime();
    e.unread       = 0;
    m_sidebar->clearChats();
    m_sidebar->addOrUpdateChat(e);
    m_sidebar->selectChat(e.id);

    m_chatArea->clearMessages();
    m_seenPeers.clear();
    m_reportedCount = 0;
    updateOnlineStatus();
}

void ChatWindow::updateOnlineStatus() {
    if (m_backend->currentRoom.isEmpty()) return;
    // Two independent sources: the server's [USERS] broadcast count, and the
    // set of peers we've actually heard messages from. Take the max — joiners
    // sometimes miss the [USERS] frame during ECDH handshake, but messages
    // they receive afterwards still let us count.
    const int fromPeers = m_seenPeers.size() + 1;          // +1 for self
    const int total     = qMax(m_reportedCount, fromPeers);
    QString status = (total <= 1) ? tr("just you online")
                                  : tr("%1 online").arg(total);
    m_chatArea->setChat(m_backend->currentRoom, m_backend->currentRoom, status);
}

void ChatWindow::handleDisconnected() {
    m_seenPeers.clear();
    m_reportedCount = 0;
    QString text = tr("Disconnected. Click ☰ to reconnect.");

    // Common case: user picked JOIN mode and is alone in the room. The CLI
    // closes after a 30s key-exchange timeout. Tell them what happened and
    // suggest the right mode.
    const qint64 secsAlive = m_connectStarted.isValid()
        ? m_connectStarted.secsTo(QDateTime::currentDateTime()) : 0;
    if (m_lastMode == Backend::JOIN_ROOM && secsAlive > 0 && secsAlive < 40) {
        text = tr("No one responded with a room key (the room may be empty). "
                  "If you want to start a new room, use Create instead of Join. "
                  "Click ☰ to reconnect.");
    }

    Message m;
    m.text      = text;
    m.timestamp = QDateTime::currentDateTime();
    m.isSystem  = true;
    m_chatArea->appendMessage(m);

    if (!m_backend->currentRoom.isEmpty()) {
        m_chatArea->setChat(m_backend->currentRoom, m_backend->currentRoom, tr("disconnected"));
    }
}

void ChatWindow::handleNewMessages(const QStringList &lines) {
    for (const QString &l : lines) appendParsedLine(l);
}

void ChatWindow::handleContactsUpdated(const QStringList &users) {
    m_reportedCount = users.size();
    // Also seed the peer set so it stays consistent if [USERS] arrived first.
    for (const QString &u : users) {
        if (u != m_backend->currentName) m_seenPeers.insert(u);
    }
    updateOnlineStatus();
}

void ChatWindow::handleError(const QString &err) {
    const QString trimmed = err.trimmed();
    if (trimmed.isEmpty()) return;
    // Suppress informational stderr that the CLI emits during normal flow —
    // we only want true errors visible to the user.
    static const QStringList kIgnore = {
        "Identity loaded",
        "Commands: /sendfile",
        "[client] connected",
        "[create]",
        "[join] Will request",
        "[join] Waiting",
        "[join] Key exchange verified",
        "[join] Room key",
        "[join] Key exchange failed",  // surfaced via handleDisconnected instead
    };
    for (const QString &p : kIgnore) {
        if (trimmed.contains(p)) return;
    }
    Message m;
    m.text      = tr("⚠ %1").arg(trimmed);
    m.timestamp = QDateTime::currentDateTime();
    m.isSystem  = true;
    m_chatArea->appendMessage(m);
}

void ChatWindow::appendParsedLine(const QString &line) {
    // Inbound file offer: "[FILE_OFFER] sender wants to send "name" (size). Type /accept [path] or /reject"
    // The CLI appends usage hint after `(size)`, so we don't anchor to end-of-line.
    static const QRegularExpression fileOfferRe(
        R"(^\s*\[FILE_OFFER\]\s*(.+?)\s+wants to send\s+\"(.+?)\"\s+\(([^)]+)\))");
    if (auto m = fileOfferRe.match(line); m.hasMatch()) {
        handleFileOffer(m.captured(1), m.captured(2), m.captured(3));
        return;
    }

    // Match: "[HH:MM:SS] sender: msg"  or  "[HH:MM:SS] [V|T|?|!] sender: msg"
    static const QRegularExpression re(
        R"(^\s*\[(\d{2}:\d{2}:\d{2})\](?:\s*\[([VT?!])\])?\s*([^:]+):\s*(.*)$)");
    QRegularExpressionMatch match = re.match(line);
    if (!match.hasMatch()) {
        // CLI status/diagnostic noise — silently drop. The chat header status
        // and disconnect messages already convey state.
        return;
    }

    QString sender = match.captured(3).trimmed();
    // Skip non-user "senders" like [server], [client], [join], [create], [TOFU]…
    if (sender.startsWith('[')) return;

    Message msg;
    msg.sender    = sender;
    msg.text      = match.captured(4).trimmed();
    msg.timestamp = QDateTime(QDate::currentDate(),
                              QTime::fromString(match.captured(1), "HH:mm:ss"));
    msg.fromSelf  = (msg.sender == m_backend->currentName);
    msg.delivered = true;
    m_chatArea->appendMessage(msg);

    // Heard from a real peer — count them as online even if [USERS] never came.
    if (!msg.fromSelf) {
        const int before = m_seenPeers.size();
        m_seenPeers.insert(msg.sender);
        if (m_seenPeers.size() != before) updateOnlineStatus();
    }
}

// ───────── Hamburger menu ─────────

void ChatWindow::onSidebarMenu(const QPoint &globalPos) {
    QMenu menu(this);
    QAction *connectAct    = menu.addAction(tr("Connect to room…"));
    QAction *disconnectAct = menu.addAction(tr("Disconnect"));
    menu.addSeparator();
    QAction *themeAct      = menu.addAction(
        Theme::instance().mode() == Theme::Dark ? tr("Switch to light theme")
                                                 : tr("Switch to dark theme"));
    QAction *settingsAct   = menu.addAction(tr("Settings"));
    QAction *trustedAct    = menu.addAction(tr("Trusted keys"));
    menu.addSeparator();
    QAction *quitAct       = menu.addAction(tr("Quit"));

    disconnectAct->setEnabled(m_backend->isConnected);
    connectAct->setText(m_backend->isConnected ? tr("Switch room…") : tr("Connect to room…"));

    QAction *picked = menu.exec(globalPos);
    if      (picked == connectAct)    requestConnect();
    else if (picked == disconnectAct) m_backend->disconnect();
    else if (picked == themeAct)      toggleTheme();
    else if (picked == settingsAct)   openSettings();
    else if (picked == trustedAct)    openTrustedKeys();
    else if (picked == quitAct)       close();
}

void ChatWindow::toggleTheme() {
    const auto cur = Theme::instance().mode();
    const auto next = (cur == Theme::Dark) ? Theme::Light : Theme::Dark;
    Theme::instance().setMode(next);
    QSettings s("fear-messenger", "fear-gui");
    s.setValue("theme/mode", int(next));
}

void ChatWindow::openSettings() {
    QSettings settings("fear-messenger", "fear-gui");
    SettingsDialog dlg(&settings, this);
    connect(&dlg, &SettingsDialog::cliPathChanged, this,
            [this](const QString &p) { m_backend->setCliPath(p); });
    dlg.exec();
}

void ChatWindow::openTrustedKeys() {
    KnownKeysDialog dlg(this);
    dlg.exec();
}

// ───────── Calls ─────────

void ChatWindow::onAudioCallRequested() {
    if (!m_backend->isConnected) {
        QMessageBox::information(this, tr("Audio call"),
            tr("Connect to a room first."));
        return;
    }
    AudioCallDialog dlg(m_backend->audioManager, m_backend, this, m_backend->roomKeyHex);
    dlg.exec();
}

void ChatWindow::onVideoCallRequested() {
    if (!m_backend->isConnected) {
        QMessageBox::information(this, tr("Video call"),
            tr("Connect to a room first."));
        return;
    }
    VideoCallDialog dlg(m_backend->videoManager, m_backend, this, m_backend->roomKeyHex);
    dlg.exec();
}

// ───────── File transfer ─────────

void ChatWindow::onAttachRequested() {
    if (!m_backend->isConnected) {
        QMessageBox::information(this, tr("Attach file"),
            tr("Connect to a room first."));
        return;
    }
    const QString filePath = QFileDialog::getOpenFileName(this,
        tr("Select file to send"), QDir::homePath());
    if (filePath.isEmpty()) return;

    QFileInfo fi(filePath);
    if (!fi.exists() || !fi.isFile()) {
        QMessageBox::warning(this, tr("Attach file"),
            tr("Selected path is not a regular file."));
        return;
    }
    const QString abs = QDir::toNativeSeparators(fi.absoluteFilePath());
    if (!m_backend->sendMessage(QString(), QString("/sendfile %1").arg(abs))) {
        QMessageBox::warning(this, tr("Attach file"),
            tr("Failed to send file. Check connection."));
        return;
    }

    // Local feedback in the chat — receiver will see a real FILE_OFFER bubble too.
    Message m;
    m.sender    = m_backend->currentName;
    m.fromSelf  = true;
    m.text      = tr("📎 sent file: %1").arg(fi.fileName());
    m.timestamp = QDateTime::currentDateTime();
    m.isSystem  = true;
    m_chatArea->appendMessage(m);
}

void ChatWindow::handleFileOffer(const QString &sender, const QString &filename, const QString &sizeStr) {
    QSettings s("fear-messenger", "fear-gui");
    if (s.value("privacy/autoAcceptFiles", false).toBool()) {
        m_backend->sendMessage(QString(), "/accept");
        return;
    }
    QMessageBox box(this);
    box.setWindowTitle(tr("Incoming file"));
    box.setIcon(QMessageBox::Question);
    box.setText(tr("%1 wants to send you a file:\n\n\"%2\" (%3)\n\nAccept?")
                    .arg(sender, filename, sizeStr));
    QPushButton *acceptBtn = box.addButton(tr("Accept"),     QMessageBox::AcceptRole);
    QPushButton *saveAsBtn = box.addButton(tr("Save as…"),   QMessageBox::ActionRole);
    box.addButton(tr("Reject"), QMessageBox::RejectRole);
    box.exec();

    if (box.clickedButton() == acceptBtn) {
        m_backend->sendMessage(QString(), "/accept");
    } else if (box.clickedButton() == saveAsBtn) {
        const QString path = QFileDialog::getSaveFileName(this, tr("Save file as…"),
            QDir::homePath() + "/Downloads/" + filename);
        if (path.isEmpty()) {
            m_backend->sendMessage(QString(), "/reject");
        } else {
            m_backend->sendMessage(QString(), "/accept " + path);
        }
    } else {
        m_backend->sendMessage(QString(), "/reject");
    }
}

}
