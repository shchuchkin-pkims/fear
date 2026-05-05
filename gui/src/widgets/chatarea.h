#ifndef FEAR_CHATAREA_H
#define FEAR_CHATAREA_H

#include <QWidget>
#include <QString>
#include <QDateTime>

class QLabel;
class QTextEdit;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

namespace fear {

class Avatar;

struct Message {
    QString sender;
    QString text;
    QDateTime timestamp;
    bool fromSelf = false;
    bool delivered = false;
    bool isSystem = false;
};

class ChatArea : public QWidget {
    Q_OBJECT
public:
    explicit ChatArea(QWidget *parent = nullptr);

    void setChat(const QString &id, const QString &title, const QString &status);
    void clearMessages();
    void appendMessage(const Message &m);
    void showEmptyState(const QString &hint = QString());

signals:
    void sendRequested(const QString &text);
    void audioCallRequested();
    void videoCallRequested();
    void chatInfoRequested();
    void attachRequested();
    /** Emitted when the user clicks a peer's avatar or name inside a
     *  message bubble — used to open the peer profile dialog. */
    void senderClicked(const QString &senderName);

public:
    /** Forward a click from a bubble's avatar/name area. Internal use. */
    void emitSenderClicked(const QString &senderName) { emit senderClicked(senderName); }

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;
    void paintEvent(QPaintEvent *event) override;

private:
    void onSendClicked();

    QString      m_chatId;

    // Header
    QWidget     *m_header;
    Avatar      *m_headerAvatar;
    QLabel      *m_titleLbl;
    QLabel      *m_statusLbl;
    QPushButton *m_audioCallBtn;
    QPushButton *m_videoCallBtn;
    QPushButton *m_searchBtn;
    QPushButton *m_menuBtn;

    // Body
    QScrollArea *m_scroll;
    QWidget     *m_messagesContainer;
    QVBoxLayout *m_messagesLayout;
    QLabel      *m_emptyHint;

    // Input
    QWidget     *m_inputArea;
    QPushButton *m_attachBtn;
    QTextEdit   *m_input;
    QPushButton *m_emojiBtn;
    QPushButton *m_sendBtn;
};

}

#endif
