#ifndef FEAR_CHATLISTITEM_H
#define FEAR_CHATLISTITEM_H

#include <QWidget>
#include <QString>
#include <QDateTime>

class QLabel;

namespace fear {

class Avatar;

struct ChatListEntry {
    QString id;
    QString title;
    QString preview;
    QDateTime lastActivity;
    int unread = 0;
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
