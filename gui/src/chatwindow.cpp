#include <QFontDialog>
#include <QSystemTrayIcon>
#include <QDesktopServices>
#include <QUrl>
#include "keyexchangedialog.h"
#include "chatwindow.h"
#include "widgets/sidebar.h"
#include "widgets/chatarea.h"
#include "widgets/chatlistitem.h"
#include "theme/theme.h"
#include "connectiondialog.h"
#include "backend.h"

extern "C" {
#include "server_proto.h"
}
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
#include <QStatusBar>
#include <QMenu>
#include <QInputDialog>
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

    // Restore last-used theme (default Light on first launch).
    {
        QSettings s("fear-messenger", "fear-gui");
        /* Светлая по умолчанию: ровно так выглядит приложение на телефоне,
         * и человек, открывший оба, должен видеть одно и то же. Тёмная
         * никуда не делась - переключатель в меню, выбор запоминается. */
        const int saved = s.value("theme/mode", int(Theme::Light)).toInt();
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

    /* Onboarding (audit 2026-07, UX-High): every server flow - registration,
     * ECDH, contacts sync - needs an identity, but a fresh install has none
     * and this window only offered Import. Create one silently on first run;
     * the key can be backed up later via "Export identity". */
    if (!m_backend->hasIdentity())
        m_backend->generateIdentity(/*copyToClipboard=*/false);

    // Backend → UI
    connect(m_backend, &Backend::connected,         this, &ChatWindow::handleConnected);
    connect(m_backend, &Backend::callInviteReceived, this, &ChatWindow::handleCallInvite);
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
    // Меню «⋮» в шапке чата: поиск по сообщениям и очистка истории
    // относятся к текущему чату, поэтому живут здесь, а не в главном меню.
    connect(m_chatArea, &ChatArea::searchInChatRequested, this, [this]() {
        SearchDialog dlg(m_history, this);
        dlg.exec();
    });
    connect(m_chatArea, &ChatArea::clearChatRequested,
            this, &ChatWindow::clearActiveHistory);
    // Phase B-5: unified chat list — sidebar selection routes to DM open
    // or current-room reuse, "+" opens the contacts dialog.
    connect(m_sidebar, &Sidebar::chatSelected,
            this, &ChatWindow::onSidebarChatSelected);
    connect(m_sidebar, &Sidebar::addNewRequested,
            this, &ChatWindow::onAddNewRequested);
    connect(m_sidebar, &Sidebar::deleteChatRequested,
            this, &ChatWindow::onDeleteChatRequested);
    connect(ContactsStore::instance(), &ContactsStore::contactsChanged,
            this, &ChatWindow::rebuildSidebarChats);
    /* Новый контакт - новый ящик, за которым надо следить. */
    connect(ContactsStore::instance(), &ContactsStore::contactsChanged,
            this, &ChatWindow::registerInboxWatches);

    // Initial empty state
    m_chatArea->showEmptyState(tr("Click ☰ to connect to a room."));

    // Phase B-5: paint the sidebar with whatever we already know about
    // (cached contacts + previous group rooms). Identity may not be loaded
    // yet, in which case DM entries get filled in after the first connect.
    rebuildSidebarChats();

    /* Выбранный когда-то шрифт переписки. Восстанавливаем до первого
     * сообщения, иначе человек увидит чужой размер и решит, что настройка
     * не сохранилась. */
    {
        QSettings st;
        const QString saved = st.value(QStringLiteral("chat/font")).toString();
        QFont f;
        if (!saved.isEmpty() && f.fromString(saved)) m_chatArea->setMessageFont(f);
    }

    setupTray();
}

void ChatWindow::closeEvent(QCloseEvent *e) {
    /* В лоток, а не наружу - но только если лоток вообще есть. Иначе окно
     * исчезло бы навсегда вместе с единственным способом его вернуть. */
    if (m_tray && m_tray->isVisible()) {
        hide();
        e->ignore();
        return;
    }
    QMainWindow::closeEvent(e);
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

    /* Validation loop on one dialog instance: re-exec keeps whatever the
     * user already typed. The old flow re-created the dialog via a queued
     * requestConnect(), wiping the fields on every mistake (audit UX). */
    ConnectionDialog dlg(m_profile, m_backend->identityFilePath, this);
    for (;;) {
        if (dlg.exec() != QDialog::Accepted) return;

        if (dlg.host().isEmpty() || dlg.room().isEmpty() || dlg.name().isEmpty()) {
            QMessageBox::warning(this, tr("Connect"),
                tr("Server, room and name are required."));
            continue;
        }
        if (dlg.mode() == Backend::MANUAL_KEY && dlg.key().isEmpty()) {
            QMessageBox::warning(this, tr("Connect"),
                tr("Room key is required for the “Use key” mode."));
            continue;
        }
        break;
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
    /* Сначала перенос: ящики и чаты адресуются новым идентификатором, и
     * заполнить его надо до того, как ими воспользуются. */
    migrateDmRooms();
    /* Ящики контактов - сразу после подключения: письмо могло прийти,
     * пока нас не было, и ждать его до следующего изменения списка
     * контактов незачем. */
    registerInboxWatches();
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
    const int fromPeers = m_seenPeers.size() + 1;          // +1 for self
    const int total     = qMax(m_reportedCount, fromPeers);
    const bool isPm     = m_backend->currentRoom.startsWith("pm:")
                       || m_backend->currentRoom.startsWith("dm:");
    QString status;
    if (isPm) {
        status = (total >= 2) ? tr("Online") : tr("Offline");
    } else {
        /* Число видно всегда, включая единицу: «Online 1» отвечает на вопрос
         * «сколько нас», а «just you online» заставляет догадываться, что это
         * то же самое. */
        status = tr("Online %1").arg(total);
    }
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
    // [USERS] is the server's authoritative live participant snapshot
    // pushed every time someone joins or leaves. Replace the cached set
    // wholesale instead of merging — otherwise a peer who left the room
    // would stay in m_seenPeers forever and show up in the
    // GroupParticipantsDialog as a phantom "online" user.
    m_seenPeers.clear();
    for (const QString &u : users) {
        // «?метка» - это участник, который ещё не объявился: сервер назвал
        // его меткой, а имя приходит отдельным анонсом мгновением позже.
        // В список собеседников такой огрызок попадать не должен - строка
        // перепечатается сама, как только имя станет известно.
        if (u.startsWith(QLatin1Char('?'))) continue;
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

void ChatWindow::handleCallInvite(const QString &sender, const QString &callId,
                                  const QString &host, quint16 port, bool video) {
    /* Leave a trace either way: a call that was offered and declined is
     * something the user may want to see later. */
    Message note;
    note.text      = video ? tr("%1 is inviting you to a video call").arg(sender)
                           : tr("%1 is inviting you to a voice call").arg(sender);
    note.timestamp = QDateTime::currentDateTime();
    note.isSystem  = true;
    m_chatArea->appendMessage(note);

    QMessageBox box(this);
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle(video ? tr("Incoming video call") : tr("Incoming voice call"));
    box.setText(note.text);
    box.setInformativeText(host.isEmpty()
        ? tr("The call goes through the server.")
        : tr("Direct connection to %1:%2.").arg(host).arg(port));
    QPushButton *joinBtn = box.addButton(tr("Join"), QMessageBox::AcceptRole);
    box.addButton(tr("Decline"), QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() != joinBtn) return;

    /* The call_id from the invite is what binds every media key of this
     * call, so it has to reach the media process unchanged. Without it the
     * two ends would derive different keys and hear nothing. */
    if (video) {
        if (m_backend->videoManager) m_backend->videoManager->callId = callId;
    } else {
        if (m_backend->audioManager) m_backend->audioManager->callId = callId;
    }

    /* Reuse the existing call dialogs rather than inventing a second path:
     * they own device selection and the key field. The host and port from
     * the invite are a hint the user can still override there. */
    if (video) {
        VideoCallDialog dlg(m_backend->videoManager, m_backend, this, m_backend->roomKeyHex);
        dlg.exec();
    } else {
        AudioCallDialog dlg(m_backend->audioManager, m_backend, this, m_backend->roomKeyHex);
        dlg.exec();
    }
    Q_UNUSED(host); Q_UNUSED(port);
}

void ChatWindow::promptKeyChanged(const QString &peer, const QString &fp) {
    // Always leave a visible trace in the chat view.
    Message note;
    note.text      = tr("⚠ Identity key for %1 has CHANGED (fingerprint %2). "
                        "Messages from this peer are marked [!] until you decide.")
                         .arg(peer, fp);
    note.timestamp = QDateTime::currentDateTime();
    note.isSystem  = true;
    m_chatArea->appendMessage(note);

    // But interrupt the user only once per (peer, fingerprint) per session.
    const QString sig = peer + QLatin1Char('/') + fp;
    if (m_keyChangePrompted.contains(sig)) return;
    m_keyChangePrompted.insert(sig);

    QMessageBox box(this);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(tr("Key changed - possible MITM"));
    box.setText(tr("The identity key of \"%1\" differs from the one you trusted before.")
                    .arg(peer));
    box.setInformativeText(tr(
        "New fingerprint: %1\n\n"
        "A legitimate reinstall or identity restore looks like this - but so does "
        "an attacker in the middle. Verify the fingerprint with %2 over another "
        "channel (call, in person) before trusting the new key.")
        .arg(fp, peer));
    QPushButton *trustBtn = box.addButton(tr("Trust new key"), QMessageBox::DestructiveRole);
    box.addButton(tr("Keep distrusting"), QMessageBox::RejectRole);
    box.setDefaultButton(QMessageBox::NoButton);
    box.exec();

    if (box.clickedButton() == trustBtn) {
        char kkpath[512];
        if (identity_default_known_keys_path(kkpath, sizeof kkpath) == 0 &&
            identity_remove_key(kkpath, peer.toUtf8().constData()) == 0) {
            Message ok;
            ok.text      = tr("Old key for %1 removed. The next signed message "
                              "will pin the new key (TOFU).").arg(peer);
            ok.timestamp = QDateTime::currentDateTime();
            ok.isSystem  = true;
            m_chatArea->appendMessage(ok);
        } else {
            QMessageBox::warning(this, tr("Trusted keys"),
                tr("Could not update the trusted keys database."));
        }
    }
}

/**
 * Идентификатор личной комнаты контакта.
 *
 * Сохранённый, если он есть, и старый - если контакт добавлен до перехода и
 * заполнить поле ещё не успели. Возвращать старый в этом случае обязательно:
 * иначе чат исчез бы из списка до первого подключения.
 */
static QString dmRoomFor(const ContactsStore::Record &c,
                         const uint8_t my_pk[IDENTITY_PK_BYTES],
                         const uint8_t their_pk[IDENTITY_PK_BYTES]) {
    if (!c.dmRoom.isEmpty()) return c.dmRoom;
    char buf[IDENTITY_PM_ROOM_ID_LEN];
    if (identity_pm_room_id_v1(my_pk, their_pk, buf) != 0) return QString();
    return QString::fromLatin1(buf);
}

void ChatWindow::appendParsedLine(const QString &line) {
    /* Письмо из ящика: «[INBOX] pm:… отправитель: текст».
     *
     * Оно пришло не в ту комнату, в которой мы сидим, поэтому кладём его в
     * историю нужного чата и подсвечиваем чат в списке, а на экран выводим
     * только если этот чат сейчас открыт. Иначе сообщение из личной
     * переписки появилось бы посреди общей комнаты. */
    static const QRegularExpression inboxRe(
        R"(^\s*\[INBOX\]\s+(\S+)\s+(.+?):\s(.*)$)");
    if (auto im = inboxRe.match(line); im.hasMatch()) {
        handleInboxMessage(im.captured(1), im.captured(2), im.captured(3));
        return;
    }

    /* Сервер не хранит недоставленное - об этом нужно сказать вслух, а не
     * рисовать вторую галочку. */
    if (line.contains(QLatin1String("[inbox] this relay stores nothing"))) {
        Message m;
        m.text = tr("Not delivered: the recipient is offline and this relay "
                    "keeps nothing. Ask them to come online, or use a relay "
                    "with an inbox.");
        m.timestamp = QDateTime::currentDateTime();
        m.isSystem = true;
        m_chatArea->appendMessage(m);
        return;
    }

    // File-transfer progress from the CLI ("Progress: 123/4567 bytes (2.7%)").
    // Shown transiently in the status bar: as chat messages it would flood
    // the view, and dropping it entirely made transfers look hung (audit UX).
    static const QRegularExpression progressRe(
        R"(^\s*Progress:\s*\d+/\d+ bytes \(([\d.]+)%\))");
    if (auto pm = progressRe.match(line); pm.hasMatch()) {
        statusBar()->showMessage(tr("File transfer: %1%").arg(pm.captured(1)), 3000);
        return;
    }

    // MITM guard: '[WARNING] KEY CHANGED for "alice"! Fingerprint: ab12…'
    // The CLI keeps delivering such messages tagged [!]; the modal prompt is
    // the blocking action the plain chat line never provided (audit UX).
    static const QRegularExpression keyChangedRe(
        R"(^\s*\[WARNING\] KEY CHANGED for \"(.+?)\"! Fingerprint:\s*(\S+))");
    if (auto km = keyChangedRe.match(line); km.hasMatch()) {
        promptKeyChanged(km.captured(1), km.captured(2));
        return;
    }

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

    // Don't seed m_seenPeers from message senders any more — that turned
    // it into "anyone who has ever spoken in this room", which leaks past
    // peers into the GroupParticipantsDialog. The server's [USERS]
    // broadcast (handleContactsUpdated) is now the single source of truth
    // for who is currently in the room.
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
    /* Normally the identity is auto-created on first run; this entry only
     * appears if the key file went missing (deleted or moved by hand). */
    QAction *createIdAct   = nullptr;
    if (!m_backend->hasIdentity())
        createIdAct = menu.addAction(tr("Create identity"));
    menu.addSeparator();
    /* Search messages / clear chat history относятся к текущему чату и
     * вызываются из меню «⋮» в шапке ChatArea — здесь больше не дублируются. */
    QAction *serverAct     = menu.addAction(tr("Run a relay here…"));
    QAction *keyExchAct    = menu.addAction(tr("Key exchange…"));
    QAction *fontAct       = menu.addAction(tr("Chat font…"));
    menu.addSeparator();
    QAction *docAct        = menu.addAction(tr("Documentation"));
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
    else if (createIdAct && picked == createIdAct) {
        if (m_backend->generateIdentity())
            QMessageBox::information(this, tr("Identity"),
                tr("New identity created. Its public key was copied to the clipboard."));
    }
    else if (picked == serverAct)     runLocalServer();
    else if (picked == keyExchAct)    openKeyExchange();
    else if (picked == fontAct)       chooseChatFont();
    else if (picked == docAct)        openDocumentation();
    else if (picked == updateAct)     checkForUpdates(/*silent=*/false);
    else if (picked == aboutAct)      showAbout();
    else if (picked == quitAct)       close();
}

// ───────── Перенесено из старого окна ─────────

/**
 * Поднять ретранслятор прямо здесь.
 *
 * Смысл ровно один: не зависеть от чужого сервера. Своя машина - свой
 * ретранслятор, и никто посторонний не видит даже того немногого, что
 * ретранслятору положено видеть.
 *
 * Порт запоминается: человек, поднявший сервер однажды, поднимет его на том
 * же порту и завтра.
 */
void ChatWindow::runLocalServer() {
    QSettings st;
    bool ok = false;
    const int port = QInputDialog::getInt(
        this, tr("Run a relay here"),
        tr("Port to listen on:"),
        st.value(QStringLiteral("last/port"), 7777).toInt(),
        1, 65535, 1, &ok);
    if (!ok) return;

    /* Запуск может упереться в занятый порт или права, поэтому курсор
     * ожидания, а не молчание: процесс поднимается не мгновенно. */
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const bool started = m_backend->createServer(port, QStringLiteral("Server"));
    QApplication::restoreOverrideCursor();

    if (started) {
        st.setValue(QStringLiteral("last/port"), port);
        QMessageBox::information(this, tr("Run a relay here"),
            tr("The relay is listening on port %1.\n\n"
               "Others reach it at this machine's address; from here it is "
               "127.0.0.1.").arg(port));
    } else {
        QMessageBox::warning(this, tr("Run a relay here"),
            tr("Could not start the relay on port %1. It may already be in "
               "use, or the port may need privileges.").arg(port));
    }
}

/**
 * Ручной обмен ключами.
 *
 * Обычный вход в комнату делает то же самое сам. Это - для случая, когда
 * ключ нужно получить, не подключаясь: договориться о ключе заранее и
 * другим каналом.
 */
void ChatWindow::openKeyExchange() {
    KeyExchangeDialog dlg(this);
    dlg.exec();
}

/**
 * Шрифт переписки.
 *
 * Не украшательство: у людей разное зрение и разные экраны, а читать
 * приходится подолгу. Выбор запоминается.
 */
void ChatWindow::chooseChatFont() {
    QSettings st;
    QFont current = m_chatArea->messageFont();
    bool ok = false;
    const QFont chosen = QFontDialog::getFont(&ok, current, this, tr("Chat font"));
    if (!ok) return;
    m_chatArea->setMessageFont(chosen);
    st.setValue(QStringLiteral("chat/font"), chosen.toString());
}

/** Руководство. Лежит рядом с программой, открывается системным средством. */
void ChatWindow::openDocumentation() {
    const QStringList candidates = {
        QCoreApplication::applicationDirPath() + QStringLiteral("/doc/README.md"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/README.md"),
        QStringLiteral("doc/README.md"),
    };
    for (const QString &c : candidates) {
        if (QFile::exists(c)) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(c).absoluteFilePath()));
            return;
        }
    }
    QDesktopServices::openUrl(QUrl(QStringLiteral("https://github.com/shchuchkin-pkims/fear")));
}

/**
 * Значок в системном лотке.
 *
 * Закрытое окно не должно означать пропущенный разговор: соединение живёт
 * дальше, и о новом сообщении говорит значок. Если лотка в системе нет,
 * молча обходимся без него - окно закрывается как обычно.
 */
void ChatWindow::setupTray() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;

    m_tray = new QSystemTrayIcon(windowIcon(), this);
    m_tray->setToolTip(QStringLiteral("F.E.A.R."));

    QMenu *menu = new QMenu(this);
    QAction *showAct = menu->addAction(tr("Show"));
    menu->addSeparator();
    QAction *quitAct = menu->addAction(tr("Quit"));
    m_tray->setContextMenu(menu);

    connect(showAct, &QAction::triggered, this, [this]() {
        showNormal();
        raise();
        activateWindow();
    });
    /* Выход именно отсюда, а не close(): close() прячет окно в лоток, и без
     * отдельного пункта программу нельзя было бы закрыть вовсе. */
    connect(quitAct, &QAction::triggered, qApp, &QCoreApplication::quit);
    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick) {
            if (isVisible()) hide();
            else { showNormal(); raise(); activateWindow(); }
        }
    });
    m_tray->show();
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

void ChatWindow::onAddNewRequested() {
    QMenu menu(this);
    QAction *aContact = menu.addAction(tr("Add contact"));
    QAction *aJoin    = menu.addAction(tr("Join room…"));
    QAction *aCreate  = menu.addAction(tr("Create new room…"));
    QAction *picked   = menu.exec(QCursor::pos());
    if (!picked) return;
    if (picked == aContact)      openContacts();
    else if (picked == aJoin)    promptAndConnectRoom(Backend::JOIN_ROOM);
    else if (picked == aCreate)  promptAndConnectRoom(Backend::CREATE_ROOM);
}

void ChatWindow::promptAndConnectRoom(Backend::ConnectMode mode) {
    if (m_backend->serverHost.isEmpty()) {
        QMessageBox::information(this, tr("Connect to server"),
            tr("Connect to a server first — joining or creating a room "
               "needs a relay endpoint."));
        return;
    }
    const bool isCreate = (mode == Backend::CREATE_ROOM);
    bool ok = false;
    const QString prompt = isCreate
        ? tr("Pick a room name. A fresh encryption key will be generated "
             "and shared with anyone who joins later.")
        : tr("Enter the name of an existing room. The encryption key will "
             "be fetched from a participant who is already inside.");
    const QString title = isCreate ? tr("Create new room") : tr("Join room");
    const QString room = QInputDialog::getText(this, title, prompt,
                                               QLineEdit::Normal, QString(),
                                               &ok).trimmed();
    if (!ok || room.isEmpty()) return;

    // Snapshot endpoint/name BEFORE disconnect — Backend::disconnect()
    // clears serverHost/serverPort/currentName, so reading them after the
    // tear-down would launch the CLI with empty --host/--name args and the
    // UI would just sit on "switching room…" / "Disconnected".
    const QString host = m_backend->serverHost;
    const int     port = m_backend->serverPort;
    const QString name = m_backend->currentName;

    if (m_backend->isConnected) m_backend->disconnect();
    m_lastMode = mode;
    m_connectStarted = QDateTime::currentDateTime();
    if (!m_backend->connectToServer(host, port, room,
                                    /*key=*/QString(), name, mode)) {
        QMessageBox::warning(this, title,
            tr("Failed to start connection. Check the CLI path in Settings."));
    }
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
        const QString dm = dmRoomFor(c, my_pk, their_pk);
        if (dm.isEmpty()) continue;
        if (dm == roomId) {
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
        // Для ЛС берём pk и handle/server напрямую из ContactsStore —
        // это даёт сразу полный профиль (имя + fingerprint + handle@server),
        // не полагаясь на TOFU-таблицу, где имя могло отсутствовать или
        // быть в другом регистре.
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
            const QString dm = dmRoomFor(c, my_pk, their_pk);
            if (dm.isEmpty()) continue;
            if (dm == room) {
                /* Полный fingerprint = blake2b(pk, 32 байта)[0..32]
                 * в формате xx:xx:... */
                QString fingerprint;
                {
                    unsigned char hash[32];
                    crypto_generichash(hash, sizeof(hash),
                                       their_pk, IDENTITY_PK_BYTES,
                                       nullptr, 0);
                    QString fp;
                    for (int i = 0; i < 32; ++i) {
                        if (i > 0) fp += ':';
                        fp += QString("%1").arg(hash[i], 2, 16, QChar('0'));
                    }
                    fingerprint = fp;
                }
                const QString display =
                    c.name.isEmpty() ? (c.handle.isEmpty() ? room : c.handle)
                                     : c.name;
                PeerProfileDialog dlg(display, c.pk, fingerprint,
                                      c.handle, c.server, c.verified,
                                      /*alreadyContact=*/true, this);
                connect(&dlg, &PeerProfileDialog::openChatRequested, this,
                        &ChatWindow::switchToDmRoom);
                dlg.exec();
                return;
            }
        }
        QMessageBox::information(this, tr("Profile"),
            tr("No contact found for this PM room."));
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

/**
 * Записать собеседника в контакты прямо из карточки.
 *
 * Для контакта достаточно открытого ключа и имени: личная комната и её ключ
 * выводятся из двух личных ключей, ник на сервере - только украшение. Ник
 * всё же спрашиваем у ретранслятора по ключу, но неудача здесь не повод
 * отказываться: контакт без ника работает точно так же.
 */
void ChatWindow::addPeerToContacts(const QString &pkB64, const QString &displayName) {
    if (pkB64.isEmpty()) return;

    auto *store = ContactsStore::instance();
    QVector<ContactsStore::Record> all = store->all();
    for (const auto &c : all) {
        if (c.pk == pkB64) return;          // уже есть
    }

    ContactsStore::Record rec;
    rec.name = displayName.trimmed();
    rec.pk   = pkB64;

    /* Ник по ключу - если ретранслятор его знает и до него сейчас можно
     * достучаться. */
    const QByteArray raw = QByteArray::fromBase64(
        pkB64.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    if (raw.size() == IDENTITY_PK_BYTES && !m_backend->serverHost.isEmpty()) {
        char handle[64] = {0};
        const QByteArray hb = m_backend->serverHost.toUtf8();
        if (sp_lookup_handle_by_pk(hb.constData(), m_backend->serverPort,
                                   reinterpret_cast<const uint8_t *>(raw.constData()),
                                   handle, sizeof handle) == SP_OK) {
            rec.handle = QString::fromUtf8(handle);
            rec.server = m_backend->serverHost;
        }
    }

    all.append(rec);
    store->replaceAll(all);                 // сам сохранит и обновит список чатов

    const QString who = rec.handle.isEmpty()
        ? rec.name
        : QString("%1 (@%2)").arg(rec.name, rec.handle);
    QMessageBox::information(this, tr("Contacts"),
        tr("%1 added. Their private chat is now in the list on the left.")
            .arg(who));
}

/**
 * Положить письмо из ящика в его чат.
 *
 * История хранится по идентификатору комнаты, так что письмо ложится туда же,
 * куда легло бы, приди оно живьём. Разница только в том, что мы в этой
 * комнате не находимся - значит на экран его выводим лишь когда открыт
 * именно этот чат.
 */
void ChatWindow::handleInboxMessage(const QString &roomId, const QString &sender,
                                    const QString &text) {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_history) {
        m_history->insert(roomId, sender, text, now, /*fromSelf=*/false,
                          /*isSystem=*/false);
    }

    if (roomId == m_backend->currentRoom) {
        Message m;
        m.sender    = sender;
        m.text      = text;
        m.timestamp = QDateTime::fromMSecsSinceEpoch(now);
        m_chatArea->appendMessage(m);
    } else {
        /* Чат не открыт - пусть его строка в списке скажет, что там новое. */
        rebuildSidebarChats();
        statusBar()->showMessage(tr("New message from %1").arg(sender), 5000);
    }
}

/**
 * Сказать консольному клиенту, за какими ящиками следить.
 *
 * Список контактов ведёт интерфейс, ключ пары он умеет выводить, а сам
 * клиент про контакты ничего не знает - поэтому ящики передаются ему
 * командой. Делается это при каждом подключении и при каждом изменении
 * списка контактов: пропустив контакт, мы просто не увидим его писем.
 */
/**
 * Заполнить у контактов идентификатор личной комнаты и перенести переписку.
 *
 * Старый идентификатор выводился из двух открытых ключей без секрета, и
 * ретранслятор, знающий ключи всех, кто занял имя, мог перебрать пары и
 * подписать каждую личную комнату именами обоих. Новый выводится под ключом
 * пары, и посчитать его снаружи нельзя.
 *
 * Цена - смена адреса у существующих чатов, поэтому переписка переносится
 * здесь же: без этого она осталась бы под прежним идентификатором и выглядела
 * бы пропавшей. Делается однажды на контакт, при первой возможности, то есть
 * когда секретный ключ уже загружен.
 */
void ChatWindow::migrateDmRooms() {
    auto *store = ContactsStore::instance();
    QVector<ContactsStore::Record> all = store->all();
    if (all.isEmpty()) return;

    bool needSave = false;
    for (auto &c : all) {
        if (!c.dmRoom.isEmpty() || c.pk.isEmpty()) continue;

        uint8_t their_pk[IDENTITY_PK_BYTES];
        size_t pkLen = 0;
        const QByteArray pkUtf8 = c.pk.toUtf8();
        if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                              pkUtf8.constData(), pkUtf8.size(), nullptr,
                              &pkLen, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
            || pkLen != IDENTITY_PK_BYTES) {
            continue;
        }

        uint8_t my_pk[IDENTITY_PK_BYTES];
        uint8_t my_sk[IDENTITY_SK_BYTES];
        if (identity_load(m_backend->identityFilePath.toUtf8().constData(),
                          my_pk, my_sk) != 0) {
            return;                       /* без секрета переносить нечем */
        }

        uint8_t k_pm[32];
        char oldId[IDENTITY_PM_ROOM_ID_LEN];
        char newId[IDENTITY_PM_ROOM_ID_LEN];
        const bool ok = identity_pm_room_key(my_sk, their_pk, k_pm) == 0
                     && identity_pm_room_id_v1(my_pk, their_pk, oldId) == 0
                     && identity_pm_room_id_v2(k_pm, newId) == 0;
        sodium_memzero(my_sk, sizeof my_sk);
        sodium_memzero(k_pm, sizeof k_pm);
        if (!ok) continue;

        c.dmRoom = QString::fromLatin1(newId);
        needSave = true;
        if (m_history) {
            m_history->renameRoom(QString::fromLatin1(oldId), c.dmRoom);
        }
    }

    if (needSave) store->replaceAll(all);
}

void ChatWindow::registerInboxWatches() {
    if (!m_backend || !m_backend->isConnected) return;

    uint8_t my_pk[IDENTITY_PK_BYTES];
    uint8_t my_sk[IDENTITY_SK_BYTES];
    if (identity_load(m_backend->identityFilePath.toUtf8().constData(),
                      my_pk, my_sk) != 0) {
        return;
    }

    for (const auto &c : ContactsStore::instance()->all()) {
        if (c.pk.isEmpty()) continue;
        uint8_t their_pk[IDENTITY_PK_BYTES];
        size_t pkLen = 0;
        const QByteArray pkUtf8 = c.pk.toUtf8();
        if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                              pkUtf8.constData(), pkUtf8.size(), nullptr,
                              &pkLen, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
            || pkLen != IDENTITY_PK_BYTES) {
            continue;
        }

        char roomBuf[IDENTITY_PM_ROOM_ID_LEN];
        uint8_t k_pm[32];
        if (identity_pm_room_key(my_sk, their_pk, k_pm) != 0) continue;
        if (identity_pm_room_id_v2(k_pm, roomBuf) != 0) {
            sodium_memzero(k_pm, sizeof k_pm);
            continue;
        }

        char keyB64[64];
        if (sodium_bin2base64(keyB64, sizeof keyB64, k_pm, sizeof k_pm,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) == nullptr) {
            sodium_memzero(k_pm, sizeof k_pm);
            continue;
        }
        m_backend->sendMessage(QString(),
            QStringLiteral("/inbox-add %1 %2")
                .arg(QString::fromLatin1(roomBuf), QString::fromLatin1(keyB64)));
        sodium_memzero(k_pm, sizeof k_pm);
        sodium_memzero(keyB64, sizeof keyB64);
    }
    sodium_memzero(my_sk, sizeof my_sk);
}

void ChatWindow::openPeerProfile(const QString &senderName) {
    const QString sender = senderName.trimmed();
    if (sender.isEmpty() || sender == "system" || sender == "server") return;

    /* Хранилище доверенных ключей спрашиваем у самой identity, а не
     * складываем путь руками. Раньше здесь стоял "known_keys.tsv" в каталоге
     * настроек Qt - файла с таким именем не существует, консольная часть
     * пишет ~/.fear/known_keys. Из-за этого карточка собеседника не знала
     * ничьего ключа: ни отпечатка показать, ни в контакты добавить. */
    char kkbuf[512];
    if (identity_default_known_keys_path(kkbuf, sizeof kkbuf) != 0) return;
    const QString knownKeysPath = QString::fromUtf8(kkbuf);

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
    bool known = false;
    for (const auto &c : ContactsStore::instance()->all()) {
        if (c.pk == pkB64) { handle = c.handle; server = c.server; known = true; break; }
    }
    PeerProfileDialog dlg(sender, pkB64, fingerprint,
                          handle, server, verified, known, this);
    connect(&dlg, &PeerProfileDialog::addContactRequested, this,
            &ChatWindow::addPeerToContacts);
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
            const QString dm = dmRoomFor(c, my_pk, their_pk);
            if (dm.isEmpty()) continue;
            ChatListEntry e;
            e.id           = dm;
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
            const QString dm = dmRoomFor(c, my_pk, their_pk);
            if (!dm.isEmpty() && dm == id) { peerPkB64 = c.pk; break; }
        }
        if (peerPkB64.isEmpty()) {
            QMessageBox::warning(this, tr("Open chat"),
                tr("No contact found for this PM room."));
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

    /* Здесь секретный ключ уже загружен, так что считаем сразу новый вывод -
     * тот, который ретранслятор повторить не может. */
    uint8_t k_pm_id[32];
    char roomBuf[IDENTITY_PM_ROOM_ID_LEN];
    if (identity_pm_room_key(my_sk, their_pk, k_pm_id) != 0 ||
        identity_pm_room_id_v2(k_pm_id, roomBuf) != 0) {
        sodium_memzero(k_pm_id, sizeof k_pm_id);
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
        /*defaultHost=*/ m_backend->serverHost,
        /*defaultPort=*/ m_backend->serverPort > 0
                            ? static_cast<uint16_t>(m_backend->serverPort) : 8888,
        this);
    dlg.exec();
}

void ChatWindow::onDeleteChatRequested(const QString &roomId) {
    if (roomId.isEmpty()) return;
    const bool isPm = roomId.startsWith("pm:") || roomId.startsWith("dm:");
    QString question;
    if (isPm) {
        question = tr("Delete chat with this contact?\n\n"
                      "Local message history for this PM room will be erased "
                      "and the contact will be removed from your address book. "
                      "This does not delete the conversation on their side.");
    } else {
        question = tr("Delete local history for room '%1'?\n\n"
                      "Messages on the server and on other participants' "
                      "devices remain intact.").arg(roomId);
    }
    if (QMessageBox::question(this, tr("Delete chat"), question,
                              QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    // Если пользователь стирает текущую активную комнату — отключаемся,
    // чтобы не остаться в комнате, которой больше нет в UI.
    if (roomId == m_backend->currentRoom && m_backend->isConnected) {
        m_backend->disconnect();
    }

    // Локальная история — атомарная очистка по roomId.
    if (m_history) m_history->clearRoom(roomId);

    // Для PM — убираем контакт из локального кэша и пушим обновлённый blob.
    if (isPm) {
        // Найдём контакт по совпадению pm room id и удалим его.
        auto cs = ContactsStore::instance();
        auto contacts = cs->all();
        QVector<ContactsStore::Record> kept;
        kept.reserve(contacts.size());

        uint8_t my_pk[IDENTITY_PK_BYTES];
        const bool haveMine =
            (identity_load_pk(m_backend->identityFilePath.toUtf8().constData(),
                              my_pk) == 0);

        for (const auto &c : contacts) {
            bool drop = false;
            if (haveMine && !c.pk.isEmpty()) {
                uint8_t their_pk[IDENTITY_PK_BYTES];
                size_t pkLen = 0;
                QByteArray pkUtf8 = c.pk.toUtf8();
                if (sodium_base642bin(their_pk, IDENTITY_PK_BYTES,
                                      pkUtf8.constData(), pkUtf8.size(),
                                      nullptr, &pkLen, nullptr,
                                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0
                    && pkLen == IDENTITY_PK_BYTES) {
                    const QString dm = dmRoomFor(c, my_pk, their_pk);
                    if (!dm.isEmpty() && dm == roomId) {
                        drop = true;
                    }
                }
            }
            if (!drop) kept.append(c);
        }
        cs->replaceAll(kept);   // пересчитает sidebar через signal
    }

    // Чистим chat area если активная комната была удалённой.
    if (roomId == m_backend->currentRoom) {
        m_chatArea->clearMessages();
        m_chatArea->showEmptyState(tr("Chat deleted. Pick another from the sidebar."));
    }

    rebuildSidebarChats();
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
