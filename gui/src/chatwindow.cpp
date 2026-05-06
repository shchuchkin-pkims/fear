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
#include "identitybackupdialog.h"
#include "updatedialog.h"
#include "history.h"
#include "searchdialog.h"
#include "profilesettings.h"
#include "profiledialog.h"
#include "contactsdialog.h"
#include "contactsstore.h"
#include "peerprofiledialog.h"
#include "groupparticipantsdialog.h"
#include <QFile>
#include <QDir>
#include <QSet>
#include <QStandardPaths>

extern "C" {
#include "identity.h"
#include <sodium.h>
}

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
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>

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
    m_history = new History(this);
    m_profile = new ProfileSettings(this);

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
    connect(m_chatArea, &ChatArea::senderClicked,       this, &ChatWindow::openPeerProfile);
    connect(m_chatArea, &ChatArea::headerClicked,       this, &ChatWindow::onChatHeaderClicked);
    // Phase B-5: unified chat list — sidebar selection routes to DM open
    // or current-room reuse, "+" opens the contacts dialog.
    connect(m_sidebar, &Sidebar::chatSelected,
            this, &ChatWindow::onSidebarChatSelected);
    connect(m_sidebar, &Sidebar::addNewRequested,
            this, &ChatWindow::openContacts);
    connect(ContactsStore::instance(), &ContactsStore::contactsChanged,
            this, &ChatWindow::rebuildSidebarChats);

    // Initial empty state
    m_chatArea->showEmptyState(tr("Click ☰ to connect to a room."));

    // Phase B-5: paint the sidebar with whatever we already know about
    // (cached contacts + previous group rooms). Identity may not be loaded
    // yet, in which case DM entries get filled in after the first connect.
    rebuildSidebarChats();
}

void ChatWindow::showEvent(QShowEvent *e) {
    QMainWindow::showEvent(e);
    if (!m_connectShown) {
        m_connectShown = true;
        QTimer::singleShot(0, this, &ChatWindow::requestConnect);
        // Silent auto-update check ~3s after launch (let the connect dialog
        // appear first, then probe GitHub in the background).
        QTimer::singleShot(3000, this, [this]{ checkForUpdates(/*silent=*/true); });
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

    ConnectionDialog dlg(m_profile, m_backend->identityFilePath, this);
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
    // Mirror of Android ProfileStore.markRegistered: first successful connect
    // to a host = this user has effectively claimed @displayName@host on it.
    // Phase B-2 will replace this with the server's REGISTER_HANDLE confirmation.
    if (m_profile && !m_backend->serverHost.isEmpty()) {
        m_profile->markRegistered(m_backend->serverHost);
    }

    rebuildSidebarChats();
    m_sidebar->selectChat(m_backend->currentRoom);

    m_chatArea->clearMessages();

    // Replay locally-persisted history for this room (Phase A §9a) before
    // any new live messages arrive.
    if (m_history) {
        const auto recent = m_history->loadRecent(m_backend->currentRoom);
        for (const auto &m : recent) m_chatArea->appendMessage(m);
    }

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
    m_chatArea->setChat(m_backend->currentRoom,
                        prettyRoomTitle(m_backend->currentRoom), status);
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
        m_chatArea->setChat(m_backend->currentRoom,
                            prettyRoomTitle(m_backend->currentRoom),
                            tr("disconnected"));
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

    // Persist to local history (Phase A §9a). Skip when no room is set
    // (defensive — should never happen once connected).
    if (m_history && !m_backend->currentRoom.isEmpty()) {
        m_history->insert(m_backend->currentRoom, msg.sender, msg.text,
                          msg.timestamp.toMSecsSinceEpoch(),
                          msg.fromSelf, /*isSystem=*/false);
    }

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
    QAction *profileAct    = menu.addAction(tr("My profile…"));
    QAction *contactsAct   = menu.addAction(tr("Contacts…"));
    QAction *settingsAct   = menu.addAction(tr("Settings"));
    QAction *trustedAct    = menu.addAction(tr("Trusted keys"));
    menu.addSeparator();
    QAction *exportIdAct   = menu.addAction(tr("Export identity…"));
    QAction *importIdAct   = menu.addAction(tr("Import identity…"));
    menu.addSeparator();
    QAction *searchAct     = menu.addAction(tr("Search messages…"));
    QAction *clearHistAct  = menu.addAction(tr("Clear chat history…"));
    menu.addSeparator();
    QAction *updateAct     = menu.addAction(tr("Check for updates"));
    QAction *aboutAct      = menu.addAction(tr("About F.E.A.R."));
    menu.addSeparator();
    QAction *quitAct       = menu.addAction(tr("Quit"));

    disconnectAct->setEnabled(m_backend->isConnected);
    connectAct->setText(m_backend->isConnected ? tr("Switch room…") : tr("Connect to room…"));

    QAction *picked = menu.exec(globalPos);
    if      (picked == connectAct)    requestConnect();
    else if (picked == disconnectAct) m_backend->disconnect();
    else if (picked == themeAct)      toggleTheme();
    else if (picked == profileAct)    openProfile();
    else if (picked == contactsAct)   openContacts();
    else if (picked == settingsAct)   openSettings();
    else if (picked == trustedAct)    openTrustedKeys();
    else if (picked == exportIdAct)   openIdentityBackup(/*export=*/true);
    else if (picked == importIdAct)   openIdentityBackup(/*export=*/false);
    else if (picked == clearHistAct)  clearActiveHistory();
    else if (picked == searchAct) {
        SearchDialog dlg(m_history, this);
        dlg.exec();
    }
    else if (picked == updateAct)     checkForUpdates(/*silent=*/false);
    else if (picked == aboutAct)      showAbout();
    else if (picked == quitAct)       close();
}

void ChatWindow::openContacts() {
    if (m_backend->serverHost.isEmpty()) {
        QMessageBox::information(this, tr("Contacts"),
            tr("Connect to a server first — contacts are stored as an "
               "encrypted blob on the server."));
        return;
    }
    ContactsDialog dlg(m_backend->identityFilePath,
                       m_backend->serverHost,
                       (uint16_t)m_backend->serverPort,
                       this);
    /* Phase B-4: double-click on a contact → start a DM with the
     * deterministic room id. Both sides need to be online for the
     * ECDH handshake (Phase E §9b will lift that with a server inbox). */
    QString currentHost = m_backend->serverHost;
    int     currentPort = m_backend->serverPort;
    QString currentName = m_backend->currentName;
    connect(&dlg, &ContactsDialog::openDmRequested, this,
            [this](const QString &room) {
        // ContactsDialog::openDmRequested даёт нам уже готовый pm:... id,
        // но для switchToDmRoom нужен peerPkB64. Делегируем через единый
        // путь, который сам найдёт контакт по id.
        onSidebarChatSelected(room);
    });
    dlg.exec();
}

// Sender of the message bubble was clicked → look up whatever we know
// about that name in the local TOFU known_keys file and show a profile
// dialog. Offers an "Open chat" action that derives the deterministic DM
// room id from the peer's pk and switches rooms.
QString ChatWindow::prettyRoomTitle(const QString &roomId) const {
    // Для ЛС-комнаты ищем контакт, чьё pmRoomId совпадает с roomId, и
    // возвращаем его displayName / handle. Иначе — id как есть.
    if (!roomId.startsWith("pm:") && !roomId.startsWith("dm:")) return roomId;

    uint8_t my_pk[IDENTITY_PK_BYTES];
    if (identity_load_pk(m_backend->identityFilePath.toUtf8().constData(),
                         my_pk) != 0) {
        return roomId;
    }
    for (const auto &c : ContactsStore::instance()->all()) {
        if (c.pk.isEmpty()) continue;
        uint8_t their_pk[IDENTITY_PK_BYTES];
        size_t pkLen = 0;
        QByteArray pkUtf8 = c.pk.toUtf8();
        if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                              pkUtf8.constData(), pkUtf8.size(),
                              nullptr, &pkLen, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
            || pkLen != IDENTITY_PK_BYTES) {
            continue;
        }
        char buf[IDENTITY_PM_ROOM_ID_LEN];
        if (identity_pm_room_id(my_pk, their_pk, buf) != 0) continue;
        if (QString::fromUtf8(buf) == roomId) {
            if (!c.name.isEmpty())   return c.name;
            if (!c.handle.isEmpty()) return c.handle;
            return roomId;
        }
    }
    return roomId;
}

void ChatWindow::onChatHeaderClicked() {
    const QString &room = m_backend->currentRoom;
    if (room.isEmpty()) return;

    if (room.startsWith("pm:") || room.startsWith("dm:")) {
        // Найдём имя собеседника по контакту с совпадающим pm room_id
        // и передадим в openPeerProfile (тот покажет PeerProfileDialog).
        for (const auto &c : ContactsStore::instance()->all()) {
            if (c.pk.isEmpty()) continue;
            uint8_t their_pk[IDENTITY_PK_BYTES];
            size_t pkLen = 0;
            QByteArray pkUtf8 = c.pk.toUtf8();
            if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                                  pkUtf8.constData(), pkUtf8.size(),
                                  nullptr, &pkLen, nullptr,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
                || pkLen != IDENTITY_PK_BYTES) {
                continue;
            }
            uint8_t my_pk[IDENTITY_PK_BYTES];
            if (identity_load_pk(m_backend->identityFilePath.toUtf8().constData(),
                                 my_pk) != 0) break;
            char buf[IDENTITY_PM_ROOM_ID_LEN];
            if (identity_pm_room_id(my_pk, their_pk, buf) != 0) continue;
            if (QString::fromUtf8(buf) == room) {
                openPeerProfile(c.name.isEmpty() ? c.handle : c.name);
                return;
            }
        }
        return;
    }

    // Group room — собираем известных участников и показываем диалог.
    QStringList participants;
    for (const QString &p : m_seenPeers) participants.append(p);
    if (!m_backend->currentName.isEmpty())
        participants.append(m_backend->currentName);
    participants.removeDuplicates();
    participants.sort(Qt::CaseInsensitive);

    auto *dlg = new GroupParticipantsDialog(prettyRoomTitle(room),
                                            participants, this);
    connect(dlg, &GroupParticipantsDialog::peerSelected, this,
            &ChatWindow::openPeerProfile);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->open();
}

void ChatWindow::openPeerProfile(const QString &senderName) {
    const QString sender = senderName.trimmed();
    if (sender.isEmpty() || sender == "system" || sender == "server") return;

    // Read the known_keys.tsv that FearClient writes on TOFU.
    QString cfgDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (cfgDir.isEmpty())
        cfgDir = QDir::homePath() + "/.config/fear";
    const QString knownKeysPath = cfgDir + "/known_keys.tsv";

    QString pkB64;
    bool verified = false;
    QFile f(knownKeysPath);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!f.atEnd()) {
            const QString line = QString::fromUtf8(f.readLine()).trimmed();
            if (line.isEmpty()) continue;
            const QStringList parts = line.split('\t');
            if (parts.size() < 2) continue;
            if (parts[0] == sender) {
                pkB64 = parts[1];
                if (parts.size() >= 3) verified = parts[2].toInt() != 0;
                break;
            }
        }
    }

    // Compute the full hex fingerprint (32 bytes → 64 hex chars, : every byte).
    QString fingerprint;
    if (!pkB64.isEmpty()) {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        size_t binLen = 0;
        QByteArray pkUtf8 = pkB64.toUtf8();
        if (sodium_base642bin(pk, sizeof(pk),
                              pkUtf8.constData(), pkUtf8.size(),
                              nullptr, &binLen, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0
            && binLen == sizeof(pk)) {
            unsigned char hash[32];
            crypto_generichash(hash, sizeof(hash), pk, sizeof(pk), nullptr, 0);
            QString fp;
            for (int i = 0; i < 32; ++i) {
                if (i > 0) fp += ':';
                fp += QString("%1").arg(hash[i], 2, 16, QChar('0'));
            }
            fingerprint = fp;
        }
    }

    // Use the cached contacts list to fill handle/server when known.
    QString handle, server;
    for (const auto &c : ContactsStore::instance()->all()) {
        if (c.pk == pkB64) { handle = c.handle; server = c.server; break; }
    }
    PeerProfileDialog dlg(sender, pkB64, fingerprint,
                          handle, server, verified, this);
    connect(&dlg, &PeerProfileDialog::openChatRequested, this,
            &ChatWindow::switchToDmRoom);
    dlg.exec();
}

// Phase B-5: rebuild the sidebar list from contacts cache + history.
// Each saved contact becomes a DM entry with the deterministic dm:...
// room id; each room we have history for becomes a Group entry; the
// currently-joined group room is included even if it has no history yet.
void ChatWindow::rebuildSidebarChats() {
    QVector<ChatListEntry> chats;

    // ---- DM entries from cached contacts ------------------------------
    uint8_t my_pk[IDENTITY_PK_BYTES];
    bool haveIdentity = (identity_load_pk(
        m_backend->identityFilePath.toUtf8().constData(), my_pk) == 0);

    QHash<QString, qint64> historyTs;
    if (m_history) {
        for (const auto &s : m_history->allRoomSummaries())
            historyTs.insert(s.roomId, s.lastTs);
    }

    if (haveIdentity) {
        for (const auto &c : ContactsStore::instance()->all()) {
            uint8_t their_pk[IDENTITY_PK_BYTES];
            size_t  pkLen = 0;
            QByteArray pkUtf8 = c.pk.toUtf8();
            if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                                  pkUtf8.constData(), pkUtf8.size(),
                                  nullptr, &pkLen, nullptr,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
                || pkLen != IDENTITY_PK_BYTES) {
                continue;
            }
            char roomBuf[IDENTITY_PM_ROOM_ID_LEN];
            if (identity_pm_room_id(my_pk, their_pk, roomBuf) != 0) continue;
            ChatListEntry e;
            e.id           = QString::fromUtf8(roomBuf);
            e.title        = c.name.isEmpty() ? c.handle : c.name;
            e.preview      = (!c.handle.isEmpty() && !c.server.isEmpty())
                ? QString("@%1@%2").arg(c.handle, c.server) : QString();
            e.kind         = ChatKind::Dm;
            e.peerPkB64    = c.pk;
            const auto ts = historyTs.value(e.id, 0);
            e.lastActivity = ts ? QDateTime::fromMSecsSinceEpoch(ts)
                                : QDateTime::currentDateTime();
            chats.append(e);
        }
    }

    // ---- Group entries: every non-DM room we have history for ---------
    QSet<QString> groupRooms;
    for (auto it = historyTs.constBegin(); it != historyTs.constEnd(); ++it) {
        const QString &r = it.key();
        if (!r.startsWith("pm:") && !r.startsWith("dm:")) groupRooms.insert(r);
    }
    if (m_backend->isConnected
        && !m_backend->currentRoom.isEmpty()
        && !m_backend->currentRoom.startsWith("pm:")
        && !m_backend->currentRoom.startsWith("dm:")) {
        groupRooms.insert(m_backend->currentRoom);
    }
    for (const QString &room : groupRooms) {
        ChatListEntry e;
        e.id           = room;
        e.title        = room;
        e.kind         = ChatKind::Group;
        const auto ts = historyTs.value(room, 0);
        e.lastActivity = ts ? QDateTime::fromMSecsSinceEpoch(ts)
                            : QDateTime::currentDateTime();
        chats.append(e);
    }

    m_sidebar->setChats(chats);
}

void ChatWindow::onSidebarChatSelected(const QString &id) {
    // Already on this room → just bring the chat pane forward (no-op for
    // QSplitter layout; we still suppress reconnects).
    if (id == m_backend->currentRoom) return;

    // ЛС → ключ комнаты вычисляется детерминированно (X25519 ECDH из
    // identity-ключей обоих собеседников). Гонки нет — оба клиента
    // независимо получают один и тот же K_pm и подключаются как MANUAL_KEY.
    if (id.startsWith("pm:") || id.startsWith("dm:")) {
        // Найдём peerPkB64 для этого id в кэше контактов.
        QString peerPkB64;
        for (const auto &c : ContactsStore::instance()->all()) {
            if (c.pk.isEmpty()) continue;
            uint8_t their_pk[IDENTITY_PK_BYTES];
            size_t pkLen = 0;
            QByteArray pkUtf8 = c.pk.toUtf8();
            if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                                  pkUtf8.constData(), pkUtf8.size(),
                                  nullptr, &pkLen, nullptr,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
                || pkLen != IDENTITY_PK_BYTES) {
                continue;
            }
            uint8_t my_pk[IDENTITY_PK_BYTES];
            if (identity_load_pk(m_backend->identityFilePath.toUtf8().constData(),
                                 my_pk) != 0) continue;
            char roomBuf[IDENTITY_PM_ROOM_ID_LEN];
            if (identity_pm_room_id(my_pk, their_pk, roomBuf) != 0) continue;
            if (QString::fromUtf8(roomBuf) == id) { peerPkB64 = c.pk; break; }
        }
        if (peerPkB64.isEmpty()) {
            QMessageBox::warning(this, tr("Open chat"),
                tr("Не нашли контакт для этой ЛС-комнаты."));
            return;
        }
        switchToDmRoom(peerPkB64);
        return;
    }

    // Обычная (групповая) комната — нужен ключ от создателя. Если это не
    // текущая комната — спрашиваем, прежде чем дисконнектить из текущей.
    auto answer = QMessageBox::question(this, tr("Switch room"),
        tr("Switch to room '%1'? This will disconnect from '%2'.")
            .arg(id, m_backend->currentRoom));
    if (answer != QMessageBox::Yes) {
        m_sidebar->selectChat(m_backend->currentRoom);
        return;
    }
    const QString host = m_backend->serverHost;
    const int     port = m_backend->serverPort;
    const QString name = m_backend->currentName;
    if (m_backend->isConnected) m_backend->disconnect();
    m_backend->connectToServer(host, port, id,
        /*key=*/QString(),
        name.isEmpty() ? tr("me") : name,
        Backend::JOIN_ROOM);
}

void ChatWindow::switchToDmRoom(const QString &peerPkB64) {
    // Открыть ЛС с peer-ом, чей identity_pk = peerPkB64.
    // Детерминированно вычисляем room_id и K_pm через ECDH, затем
    // подключаемся в режиме MANUAL_KEY с этим ключом — никакой гонки.
    uint8_t their_pk[IDENTITY_PK_BYTES];
    size_t pkLen = 0;
    QByteArray pkUtf8 = peerPkB64.toUtf8();
    if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                          pkUtf8.constData(), pkUtf8.size(),
                          nullptr, &pkLen, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
        || pkLen != IDENTITY_PK_BYTES) {
        QMessageBox::warning(this, tr("Open chat"),
            tr("Stored peer pk is malformed."));
        return;
    }

    /* Загружаем свой полный 64-байтовый ed25519 sk + 32-байтовый pk. */
    uint8_t my_pk[IDENTITY_PK_BYTES];
    uint8_t my_sk[IDENTITY_SK_BYTES];
    if (identity_load(m_backend->identityFilePath.toUtf8().constData(),
                      my_pk, my_sk) != 0) {
        QMessageBox::warning(this, tr("Open chat"),
            tr("No identity yet — connect to a room first."));
        return;
    }

    char roomBuf[IDENTITY_PM_ROOM_ID_LEN];
    if (identity_pm_room_id(my_pk, their_pk, roomBuf) != 0) {
        sodium_memzero(my_sk, sizeof(my_sk));
        QMessageBox::warning(this, tr("Open chat"),
            tr("Could not derive PM room id."));
        return;
    }
    uint8_t key32[32];
    int rc = identity_pm_room_key(my_sk, their_pk, key32);
    sodium_memzero(my_sk, sizeof(my_sk));
    if (rc != 0) {
        QMessageBox::warning(this, tr("Open chat"),
            tr("Could not derive PM room key."));
        return;
    }

    /* CLI ждёт ключ в base64url-no-pad формате (см. MANUAL_KEY flow). */
    char keyB64[64];
    sodium_bin2base64(keyB64, sizeof(keyB64), key32, sizeof(key32),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    sodium_memzero(key32, sizeof(key32));

    const QString room = QString::fromUtf8(roomBuf);
    const QString host = m_backend->serverHost;
    const int     port = m_backend->serverPort;
    const QString name = m_backend->currentName;
    if (host.isEmpty()) {
        QMessageBox::information(this, tr("Open chat"),
            tr("Connect to a server first."));
        return;
    }
    if (m_backend->isConnected) m_backend->disconnect();
    m_backend->connectToServer(host, port, room,
        QString::fromUtf8(keyB64),
        name.isEmpty() ? tr("me") : name,
        Backend::MANUAL_KEY);
}

void ChatWindow::openProfile() {
    ProfileDialog dlg(
        m_profile,
        m_backend->identityFilePath,
        /*onExport=*/ [this]{ openIdentityBackup(/*export=*/true); },
        /*onShowQr=*/ [this]{
            // Reuse the export+QR path; the user will get a 'show as QR'
            // checkbox prefilled.
            openIdentityBackup(/*export=*/true);
        },
        this);
    dlg.exec();
}

void ChatWindow::clearActiveHistory() {
    if (!m_history || m_backend->currentRoom.isEmpty()) {
        QMessageBox::information(this, tr("Clear history"),
            tr("No active chat to clear."));
        return;
    }
    auto answer = QMessageBox::question(this, tr("Clear chat history"),
        tr("Delete all locally-stored messages for room '%1'?\n\n"
           "Messages on the server and on other participants' devices stay.")
            .arg(m_backend->currentRoom));
    if (answer != QMessageBox::Yes) return;

    if (m_history->clearRoom(m_backend->currentRoom)) {
        m_chatArea->clearMessages();
    } else {
        QMessageBox::warning(this, tr("Clear history"),
            tr("Could not clear local history."));
    }
}

void ChatWindow::showAbout() {
    // Compute the user's identity card from identity_pk (per §1 of
    // doc/architecture-decisions.md): "name#fpshort" + full 8-byte fp.
    QString identitySection;
    {
        uint8_t pk[IDENTITY_PK_BYTES];
        if (!m_backend->identityFilePath.isEmpty() &&
            QFile::exists(m_backend->identityFilePath) &&
            identity_load_pk(m_backend->identityFilePath.toUtf8().constData(), pk) == 0) {

            uint8_t hash[8];
            crypto_generichash(hash, sizeof(hash), pk, IDENTITY_PK_BYTES, NULL, 0);
            QString fpshort;
            for (int i = 0; i < 4; ++i) fpshort += QString::asprintf("%02x", hash[i]);
            QString fpfull;
            for (int i = 0; i < 8; ++i) {
                fpfull += QString::asprintf("%02x", hash[i]);
                if (i < 7) fpfull += ':';
            }
            QString name = m_backend->currentName.isEmpty() ? tr("anonymous")
                                                            : m_backend->currentName.toHtmlEscaped();
            identitySection = QString(
                "<h4>You</h4>"
                "<p style='font-weight:600;font-size:13pt'>%1#%2</p>"
                "<p style='color:#888;font-size:9pt'>fingerprint: %3</p>"
            ).arg(name, fpshort, fpfull);
        }
    }

    const QString html =
        QString(
            "<div style='font-family:sans-serif'>"
            "<h2 style='margin-bottom:4px'>F.E.A.R. Messenger</h2>"
            "<p style='color:#888;margin-top:0'>"
            "Fully Encrypted Anonymous Routing<br>"
            "Version %1"
            "</p>"
            "%2"
            "<p>End-to-end encrypted text, voice and video over a self-hostable "
            "TCP relay. Open source, decentralised, no phone numbers.</p>"
            "<h4>Author</h4>"
            "<p>Evgenii Shchuchkin<br>"
            "<a href='mailto:shchuchkin-pkims@yandex.ru'>shchuchkin-pkims@yandex.ru</a></p>"
            "<h4>Links</h4>"
            "<ul style='margin-top:0'>"
            "<li>Site: <a href='https://fear-project.ru/'>fear-project.ru</a></li>"
            "<li>Desktop: <a href='https://github.com/shchuchkin-pkims/fear'>"
            "github.com/shchuchkin-pkims/fear</a></li>"
            "<li>Mobile: <a href='https://github.com/shchuchkin-pkims/fear-mobile'>"
            "github.com/shchuchkin-pkims/fear-mobile</a></li>"
            "</ul>"
            "</div>"
        ).arg(QStringLiteral(FEAR_VERSION), identitySection);

    QMessageBox box(this);
    box.setWindowTitle(tr("About F.E.A.R."));
    box.setTextFormat(Qt::RichText);
    box.setTextInteractionFlags(Qt::TextBrowserInteraction);
    box.setText(html);
    box.setStandardButtons(QMessageBox::Ok);
    box.exec();
}

// Compare semantic versions like "1.2.3". Returns -1/0/+1 for a<b/a==b/a>b.
static int compareSemver(const QString &a, const QString &b) {
    auto parts = [](const QString &s) {
        QStringList p = s.split('.');
        while (p.size() < 3) p << "0";
        return p;
    };
    QStringList pa = parts(a), pb = parts(b);
    for (int i = 0; i < 3; ++i) {
        int xa = pa[i].toInt();
        int xb = pb[i].toInt();
        if (xa != xb) return xa < xb ? -1 : 1;
    }
    return 0;
}

void ChatWindow::checkForUpdates(bool silent) {
    static QNetworkAccessManager *net = nullptr;
    if (!net) net = new QNetworkAccessManager(this);

    QUrl url("https://api.github.com/repos/shchuchkin-pkims/fear/releases/latest");
    QNetworkRequest req(url);
    req.setRawHeader("Accept", "application/vnd.github+json");
    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, silent]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            if (!silent) QMessageBox::warning(this, tr("Update check"),
                tr("Failed to query GitHub: %1").arg(reply->errorString()));
            return;
        }
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QString tag = doc.object().value("tag_name").toString();
        const QString latest = tag.startsWith('v') ? tag.mid(1) : tag;
        const QString current = QStringLiteral(FEAR_VERSION);

        if (latest.isEmpty()) {
            if (!silent) QMessageBox::information(this, tr("Update check"),
                tr("Couldn't read latest version from GitHub."));
            return;
        }

        if (compareSemver(latest, current) <= 0) {
            // No update needed. Silent → say nothing; manual → toast-style info.
            if (!silent) QMessageBox::information(this, tr("Up to date"),
                tr("You're on the latest version (v%1).").arg(current));
            return;
        }

        // Update available — ask user.
        const auto answer = QMessageBox::question(this, tr("Update available"),
            tr("Version %1 is available (you have %2). Update now?\n\n"
               "The app will download, install and restart automatically.")
                .arg(latest, current),
            QMessageBox::Yes | QMessageBox::No);
        if (answer != QMessageBox::Yes) return;

        // Open the existing UpdateDialog — it spawns the updater binary, shows
        // live output, and offers to restart on completion.
        UpdateDialog dlg(this, m_backend->cliPath);
        dlg.exec();
    });
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

void ChatWindow::openIdentityBackup(bool exportMode) {
    if (m_backend->identityFilePath.isEmpty()) {
        QMessageBox::warning(this, tr("Identity backup"),
            tr("Identity file path is not configured."));
        return;
    }
    if (exportMode && !QFile::exists(m_backend->identityFilePath)) {
        QMessageBox::warning(this, tr("Export identity"),
            tr("No identity file found at %1.\nGenerate one by connecting to a room first.")
                .arg(m_backend->identityFilePath));
        return;
    }
    if (!exportMode && m_backend->isConnected) {
        QMessageBox::information(this, tr("Import identity"),
            tr("Disconnect from the current room before importing a new identity."));
        return;
    }

    IdentityBackupDialog dlg(
        exportMode ? IdentityBackupDialog::Export : IdentityBackupDialog::Import,
        m_backend->identityFilePath, this);
    if (dlg.exec() == QDialog::Accepted && !exportMode) {
        // Backend already cached identity availability flag — refresh it
        m_backend->identityAvailable = QFile::exists(m_backend->identityFilePath);
    }
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
