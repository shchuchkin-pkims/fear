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
    void handleFileOffer(const QString &sender, const QString &filename, const QString &sizeStr);
    void updateOnlineStatus();

    QSplitter *m_split;
    Sidebar   *m_sidebar;
    ChatArea  *m_chatArea;
    Backend   *m_backend = nullptr;
    bool       m_connectShown = false;
    Backend::ConnectMode m_lastMode = Backend::CREATE_ROOM;
    QDateTime  m_connectStarted;
    QSet<QString> m_seenPeers;        // unique non-self senders heard from
    int           m_reportedCount = 0; // last count from server [USERS] broadcast
};

}

#endif
