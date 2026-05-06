#ifndef FEAR_SIDEBAR_H
#define FEAR_SIDEBAR_H

#include <QHash>
#include <QString>
#include <QVector>
#include <QWidget>
#include "chatlistitem.h"

class QListWidget;
class QListWidgetItem;
class QLineEdit;
class QPushButton;
class QToolButton;
class QLabel;

namespace fear {

class Sidebar : public QWidget {
    Q_OBJECT
public:
    explicit Sidebar(QWidget *parent = nullptr);

    /** Replace the whole list. Splits entries by ChatListEntry::kind into
     *  Контакты (DM) and Группы sections, sorted by lastActivity desc. */
    void setChats(const QVector<ChatListEntry> &chats);

    /** Convenience for incremental updates: merge `e` into the cached list
     *  and re-render. Drops any previous entry with the same id. */
    void addOrUpdateChat(const ChatListEntry &e);

    void clearChats();
    void selectChat(const QString &id);
    QString currentChatId() const { return m_currentId; }

protected:
    void resizeEvent(QResizeEvent *e) override;

signals:
    void menuRequested(const QPoint &globalPos);
    void chatSelected(const QString &id);
    void searchChanged(const QString &text);
    /** Emitted when the user clicks the floating "+" — host opens the
     *  contacts dialog (which also lets the user start a new group). */
    void addNewRequested();
    /** Right-click → "Delete chat" on a sidebar entry. Host removes the
     *  contact (for DMs) and clears the local message history for `id`. */
    void deleteChatRequested(const QString &id);

private:
    void onDmSelectionChanged();
    void onGroupSelectionChanged();
    void rebuildLists();
    void updateSectionHeaders();

    // Header (search + hamburger)
    QPushButton *m_menuBtn;
    QLineEdit   *m_search;

    // Section: Contacts (DMs)
    QToolButton *m_dmToggle;
    QLabel      *m_dmTitle;
    QListWidget *m_dmList;
    bool         m_dmExpanded = true;

    // Section: Groups
    QToolButton *m_groupToggle;
    QLabel      *m_groupTitle;
    QListWidget *m_groupList;
    bool         m_groupExpanded = true;

    // Floating + button (overlay)
    QPushButton *m_addBtn = nullptr;

    // Cache of all entries, keyed by id; the source of truth on every
    // setChats / addOrUpdateChat call.
    QHash<QString, ChatListEntry> m_entries;

    QString m_currentId;
};

}

#endif
