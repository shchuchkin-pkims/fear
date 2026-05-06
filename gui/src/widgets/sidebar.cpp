#include "sidebar.h"
#include "../theme/theme.h"

#include <QAction>
#include <QHBoxLayout>
#include <QMenu>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QPushButton>
#include <QResizeEvent>
#include <QToolButton>
#include <QVBoxLayout>

namespace fear {

namespace {

QToolButton *makeToggle(QWidget *parent) {
    auto *b = new QToolButton(parent);
    b->setCursor(Qt::PointingHandCursor);
    b->setAutoRaise(true);
    b->setFocusPolicy(Qt::NoFocus);
    b->setFixedSize(20, 20);
    b->setText(QStringLiteral("−"));   // expanded → minus, collapsed → plus
    return b;
}

}  // namespace

Sidebar::Sidebar(QWidget *parent) : QWidget(parent) {
    setObjectName("Sidebar");
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);

    // -- Header (hamburger + search) -------------------------------------
    auto *header = new QWidget(this);
    header->setObjectName("SidebarHeader");
    header->setAttribute(Qt::WA_StyledBackground, true);
    header->setAutoFillBackground(true);
    header->setFixedHeight(54);

    m_menuBtn = new QPushButton(header);
    m_menuBtn->setText(QString::fromUtf8("☰"));
    m_menuBtn->setFixedSize(36, 36);
    m_menuBtn->setCursor(Qt::PointingHandCursor);
    m_menuBtn->setToolTip(tr("Menu"));

    m_search = new QLineEdit(header);
    m_search->setObjectName("SearchBox");
    m_search->setPlaceholderText(tr("Search"));
    m_search->setClearButtonEnabled(true);

    auto *headerLay = new QHBoxLayout(header);
    headerLay->setContentsMargins(8, 8, 12, 8);
    headerLay->setSpacing(8);
    headerLay->addWidget(m_menuBtn);
    headerLay->addWidget(m_search, 1);

    // -- Section header builder ------------------------------------------
    auto buildSectionHeader = [this](const QString &label, QToolButton *&toggleOut, QLabel *&titleOut) {
        auto *bar = new QWidget(this);
        bar->setObjectName("SectionHeader");
        bar->setAttribute(Qt::WA_StyledBackground, true);
        bar->setAutoFillBackground(true);
        bar->setFixedHeight(28);
        auto *lay = new QHBoxLayout(bar);
        lay->setContentsMargins(8, 0, 8, 0);
        lay->setSpacing(6);
        toggleOut = makeToggle(bar);
        titleOut = new QLabel(label, bar);
        QFont f = titleOut->font();
        f.setPixelSize(11);
        f.setCapitalization(QFont::AllUppercase);
        f.setLetterSpacing(QFont::PercentageSpacing, 110);
        titleOut->setFont(f);
        titleOut->setStyleSheet("color: gray;");
        lay->addWidget(toggleOut);
        lay->addWidget(titleOut, 1);
        return bar;
    };

    // -- Contacts section -------------------------------------------------
    auto *dmHeader = buildSectionHeader(tr("Contacts"), m_dmToggle, m_dmTitle);
    m_dmList = new QListWidget(this);
    m_dmList->setObjectName("ChatList");
    m_dmList->setFrameShape(QFrame::NoFrame);
    m_dmList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_dmList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_dmList->setUniformItemSizes(true);

    // -- Groups section ---------------------------------------------------
    auto *groupHeader = buildSectionHeader(tr("Groups"), m_groupToggle, m_groupTitle);
    m_groupList = new QListWidget(this);
    m_groupList->setObjectName("ChatList");
    m_groupList->setFrameShape(QFrame::NoFrame);
    m_groupList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_groupList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_groupList->setUniformItemSizes(true);

    // Right-click context menu — «Delete chat». На обоих списках.
    auto installCtx = [this](QListWidget *list) {
        list->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(list, &QListWidget::customContextMenuRequested, this,
                [this, list](const QPoint &pos) {
            QListWidgetItem *it = list->itemAt(pos);
            if (!it) return;
            const QString id = it->data(Qt::UserRole).toString();
            QMenu menu(this);
            QAction *del = menu.addAction(tr("Delete chat"));
            if (menu.exec(list->mapToGlobal(pos)) == del) {
                emit deleteChatRequested(id);
            }
        });
    };
    installCtx(m_dmList);
    installCtx(m_groupList);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(header);
    root->addWidget(dmHeader);
    root->addWidget(m_dmList, 1);
    root->addWidget(groupHeader);
    root->addWidget(m_groupList, 1);

    // -- Floating "+" button (overlay) -----------------------------------
    m_addBtn = new QPushButton(this);
    m_addBtn->setText(QStringLiteral("+"));
    m_addBtn->setCursor(Qt::PointingHandCursor);
    m_addBtn->setFixedSize(44, 44);
    m_addBtn->setToolTip(tr("New chat"));
    m_addBtn->setStyleSheet(
        "QPushButton { background: #2196F3; color: white; border: none;"
        "              border-radius: 22px; font-size: 22px; }"
        "QPushButton:hover { background: #1976D2; }");
    m_addBtn->raise();

    // -- Wiring -----------------------------------------------------------
    connect(m_menuBtn, &QPushButton::clicked, this, [this]() {
        emit menuRequested(m_menuBtn->mapToGlobal(QPoint(0, m_menuBtn->height() + 4)));
    });
    connect(m_search, &QLineEdit::textChanged, this, &Sidebar::searchChanged);
    connect(m_dmList,    &QListWidget::itemSelectionChanged,
            this,        &Sidebar::onDmSelectionChanged);
    connect(m_groupList, &QListWidget::itemSelectionChanged,
            this,        &Sidebar::onGroupSelectionChanged);
    connect(m_addBtn, &QPushButton::clicked, this, &Sidebar::addNewRequested);

    auto toggleSection = [this](bool &flag, QListWidget *list, QToolButton *btn) {
        flag = !flag;
        list->setVisible(flag);
        btn->setText(flag ? QStringLiteral("−") : QStringLiteral("+"));
    };
    connect(m_dmToggle, &QToolButton::clicked, this,
            [this, toggleSection]() { toggleSection(m_dmExpanded,    m_dmList,    m_dmToggle); });
    connect(m_groupToggle, &QToolButton::clicked, this,
            [this, toggleSection]() { toggleSection(m_groupExpanded, m_groupList, m_groupToggle); });

    // Theme application — all containers paint their own background so
    // they need to follow the active palette.
    auto applyTheme = [this, header, dmHeader, groupHeader]() {
        const Theme &th = Theme::instance();
        const QColor bg = th.sidebarBackground();
        const QColor fg = th.textPrimary();
        const QList<QWidget*> all = {
            static_cast<QWidget*>(this), header, dmHeader, groupHeader,
            static_cast<QWidget*>(m_dmList), static_cast<QWidget*>(m_groupList)
        };
        for (QWidget *w : all) {
            QPalette p = w->palette();
            p.setColor(QPalette::Window,     bg);
            p.setColor(QPalette::Base,       bg);
            p.setColor(QPalette::WindowText, fg);
            p.setColor(QPalette::Text,       fg);
            w->setPalette(p);
        }
    };
    applyTheme();
    connect(&Theme::instance(), &Theme::modeChanged, this,
            [applyTheme](Theme::Mode){ applyTheme(); });
}

void Sidebar::resizeEvent(QResizeEvent *e) {
    QWidget::resizeEvent(e);
    if (m_addBtn) {
        const int margin = 16;
        m_addBtn->move(width() - m_addBtn->width() - margin,
                       height() - m_addBtn->height() - margin);
        m_addBtn->raise();
    }
}

void Sidebar::setChats(const QVector<ChatListEntry> &chats) {
    m_entries.clear();
    for (const auto &e : chats) m_entries.insert(e.id, e);
    rebuildLists();
}

void Sidebar::addOrUpdateChat(const ChatListEntry &e) {
    m_entries.insert(e.id, e);
    rebuildLists();
}

void Sidebar::clearChats() {
    m_entries.clear();
    m_currentId.clear();
    rebuildLists();
}

void Sidebar::rebuildLists() {
    m_dmList->clear();
    m_groupList->clear();

    QVector<ChatListEntry> dms, groups;
    for (const auto &e : m_entries) {
        (e.kind == ChatKind::Dm ? dms : groups).append(e);
    }
    auto byActivityDesc = [](const ChatListEntry &a, const ChatListEntry &b) {
        return a.lastActivity > b.lastActivity;
    };
    std::sort(dms.begin(),    dms.end(),    byActivityDesc);
    std::sort(groups.begin(), groups.end(), byActivityDesc);

    auto fill = [](QListWidget *list, const QVector<ChatListEntry> &src) {
        for (const auto &e : src) {
            auto *item = new QListWidgetItem(list);
            item->setData(Qt::UserRole, e.id);
            item->setSizeHint(QSize(280, 64));
            auto *w = new ChatListItem(list);
            list->setItemWidget(item, w);
            w->setEntry(e);
        }
    };
    fill(m_dmList,    dms);
    fill(m_groupList, groups);

    selectChat(m_currentId);
    updateSectionHeaders();
}

void Sidebar::updateSectionHeaders() {
    m_dmTitle->setText(tr("Contacts (%1)").arg(m_dmList->count()));
    m_groupTitle->setText(tr("Groups (%1)").arg(m_groupList->count()));
}

void Sidebar::selectChat(const QString &id) {
    if (id.isEmpty()) return;
    auto pickIn = [id](QListWidget *list) -> bool {
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *it = list->item(i);
            if (it->data(Qt::UserRole).toString() == id) {
                list->setCurrentItem(it);
                return true;
            }
        }
        return false;
    };
    pickIn(m_dmList) || pickIn(m_groupList);
}

void Sidebar::onDmSelectionChanged() {
    QListWidgetItem *current = m_dmList->currentItem();
    // Чистим выделение в другой секции — но БЕЗ повторного триггера
    // selectionChanged, иначе он позовёт onGroupSelectionChanged → тот
    // позовёт нас обратно → бесконечная рекурсия → stack overflow.
    if (current) {
        const bool wasBlocked = m_groupList->blockSignals(true);
        m_groupList->clearSelection();
        m_groupList->blockSignals(wasBlocked);
        // Всё-таки обновим визуал в группах руками.
        for (int i = 0; i < m_groupList->count(); ++i) {
            auto *w = qobject_cast<ChatListItem*>(m_groupList->itemWidget(m_groupList->item(i)));
            if (w) w->setSelected(false);
        }
    }
    for (int i = 0; i < m_dmList->count(); ++i) {
        auto *w = qobject_cast<ChatListItem*>(m_dmList->itemWidget(m_dmList->item(i)));
        if (w) w->setSelected(m_dmList->item(i) == current);
    }
    if (!current) return;
    const QString id = current->data(Qt::UserRole).toString();
    if (id == m_currentId) return;
    m_currentId = id;
    emit chatSelected(id);
}

void Sidebar::onGroupSelectionChanged() {
    QListWidgetItem *current = m_groupList->currentItem();
    if (current) {
        const bool wasBlocked = m_dmList->blockSignals(true);
        m_dmList->clearSelection();
        m_dmList->blockSignals(wasBlocked);
        for (int i = 0; i < m_dmList->count(); ++i) {
            auto *w = qobject_cast<ChatListItem*>(m_dmList->itemWidget(m_dmList->item(i)));
            if (w) w->setSelected(false);
        }
    }
    for (int i = 0; i < m_groupList->count(); ++i) {
        auto *w = qobject_cast<ChatListItem*>(m_groupList->itemWidget(m_groupList->item(i)));
        if (w) w->setSelected(m_groupList->item(i) == current);
    }
    if (!current) return;
    const QString id = current->data(Qt::UserRole).toString();
    if (id == m_currentId) return;
    m_currentId = id;
    emit chatSelected(id);
}

}  // namespace fear
