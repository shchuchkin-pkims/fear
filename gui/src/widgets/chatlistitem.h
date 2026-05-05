#ifndef FEAR_CHATLISTITEM_H
#define FEAR_CHATLISTITEM_H

#include <QWidget>
#include <QString>
#include <QDateTime>

class QLabel;

namespace fear {

class Avatar;

enum class ChatKind { Group, Dm };

struct ChatListEntry {
    QString id;
    QString title;
    QString preview;
    QDateTime lastActivity;
    int unread = 0;
    ChatKind kind = ChatKind::Group;
    /** For DM entries: contact identity_pk (base64url, no padding). Empty
     *  for group rooms. Lets the sidebar drive a DM open without going
     *  through the contacts dialog. */
    QString peerPkB64;
};

class ChatListItem : public QWidget {
    Q_OBJECT
public:
    explicit ChatListItem(QWidget *parent = nullptr);

    void setEntry(const ChatListEntry &e);
    void setSelected(bool selected);
    QSize sizeHint() const override { return QSize(280, 64); }

protected:
    void paintEvent(QPaintEvent *) override;

private:
    void applyColors();

private:
    Avatar  *m_avatar;
    QLabel  *m_title;
    QLabel  *m_preview;
    QLabel  *m_time;
    QLabel  *m_badge;
    bool     m_selected = false;
};

}

#endif
