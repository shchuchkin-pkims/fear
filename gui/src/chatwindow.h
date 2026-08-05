#ifndef FEAR_CHATWINDOW_H
#define FEAR_CHATWINDOW_H

#include <QMainWindow>
#include <QStringList>
#include <QDateTime>
#include <QSet>
#include "backend.h"

class QSplitter;
class QShowEvent;

namespace fear {

class Sidebar;
class ChatArea;
class History;
class ProfileSettings;

class ChatWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit ChatWindow(QWidget *parent = nullptr);

protected:
    void showEvent(QShowEvent *) override;

private:
    void requestConnect();
    void handleConnected();
    void handleDisconnected();
    void handleNewMessages(const QStringList &lines);
    void handleContactsUpdated(const QStringList &users);
    void handleError(const QString &error);
    void appendParsedLine(const QString &line);

    void onAudioCallRequested();
    void onVideoCallRequested();
    void onAttachRequested();
    void onSidebarMenu(const QPoint &globalPos);
    void openSettings();
    void openTrustedKeys();
    void openIdentityBackup(bool exportMode);
    void toggleTheme();
    void checkForUpdates(bool silent);
    void showAbout();
    void clearActiveHistory();
    void openProfile();
    void openContacts();
    /** Sidebar "+" button → popup menu offering "Add contact",
     *  "Join room…" and "Create new room…". */
    void onAddNewRequested();
    /** Prompt the user for a room name and connect with the chosen mode
     *  (JOIN_ROOM or CREATE_ROOM). Reuses the currently connected
     *  server endpoint or falls back to the saved profile defaults. */
    void promptAndConnectRoom(Backend::ConnectMode mode);
    void openPeerProfile(const QString &senderName);
    /** Письмо из офлайн-ящика - в чат, которому оно адресовано. */
    void handleInboxMessage(const QString &roomId, const QString &sender,
                            const QString &text);
    /** Сообщить клиенту ящики всех контактов. */
    void registerInboxWatches();
    /** Записать собеседника в контакты из его карточки. */
    void addPeerToContacts(const QString &pkB64, const QString &displayName);
    /** «Delete chat» from sidebar context menu. Wipes local history for
     *  `roomId` and, for DMs, also removes the corresponding contact
     *  from ContactsStore + sends a fresh blob to the relay. */
    void onDeleteChatRequested(const QString &roomId);
    /** Тап по заголовку чата (аватар или название). DM → профиль
     *  собеседника; групповая комната → диалог участников. */
    void onChatHeaderClicked();
    /** Возвращает понятное имя текущей комнаты для UI: для pm:..."
     *  ищет имя контакта в ContactsStore, иначе возвращает room id
     *  как есть. Используется для setChat() и headerClicked. */
    QString prettyRoomTitle(const QString &roomId) const;
    void rebuildSidebarChats();
    void onSidebarChatSelected(const QString &id);
    void switchToDmRoom(const QString &peerPkB64);
    void handleFileOffer(const QString &sender, const QString &filename, const QString &sizeStr);
    void updateOnlineStatus();

    QSplitter *m_split;
    Sidebar   *m_sidebar;
    ChatArea  *m_chatArea;
    Backend         *m_backend  = nullptr;
    History         *m_history  = nullptr;
    ProfileSettings *m_profile  = nullptr;
    bool       m_connectShown = false;
    Backend::ConnectMode m_lastMode = Backend::CREATE_ROOM;
    QDateTime  m_connectStarted;
    QSet<QString> m_seenPeers;        // unique non-self senders heard from
    int           m_reportedCount = 0; // last count from server [USERS] broadcast
    QSet<QString> m_keyChangePrompted; // "(peer)/(fp)" pairs already raised modally

    /** A room member announced a call: ask whether to join it. */
    void handleCallInvite(const QString &sender, const QString &callId,
                          const QString &host, quint16 port, bool video);

    /** Modal MITM prompt for a changed peer identity key (audit UX). */
    void promptKeyChanged(const QString &peer, const QString &fp);
};

}

#endif
