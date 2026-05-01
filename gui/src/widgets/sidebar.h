#ifndef FEAR_SIDEBAR_H
#define FEAR_SIDEBAR_H

#include <QWidget>
#include <QString>
#include "chatlistitem.h"

class QListWidget;
class QListWidgetItem;
class QLineEdit;
class QPushButton;

namespace fear {

class Sidebar : public QWidget {
    Q_OBJECT
public:
    explicit Sidebar(QWidget *parent = nullptr);

    void addOrUpdateChat(const ChatListEntry &e);
    void clearChats();
    void selectChat(const QString &id);
    QString currentChatId() const { return m_currentId; }

signals:
    void menuRequested(const QPoint &globalPos);
    void chatSelected(const QString &id);
    void searchChanged(const QString &text);

private:
    void onSelectionChanged();

    QPushButton *m_menuBtn;
    QLineEdit   *m_search;
    QListWidget *m_list;
    QString      m_currentId;
};

}

#endif
