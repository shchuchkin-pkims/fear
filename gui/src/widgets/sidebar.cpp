#include "sidebar.h"
#include "../theme/theme.h"

#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace fear {

Sidebar::Sidebar(QWidget *parent) : QWidget(parent) {
    setObjectName("Sidebar");
    // Sidebar paints its own bg from QSS — needs both attributes to render
    // properly across themes.
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);

    auto *header = new QWidget(this);
    header->setObjectName("SidebarHeader");
    header->setAttribute(Qt::WA_StyledBackground, true);
    header->setAutoFillBackground(true);
    header->setFixedHeight(54);

    m_menuBtn = new QPushButton(header);
    m_menuBtn->setText(QString::fromUtf8("☰")); // ☰
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

    m_list = new QListWidget(this);
    m_list->setObjectName("ChatList");
    m_list->setFrameShape(QFrame::NoFrame);
    m_list->setSelectionMode(QAbstractItemView::SingleSelection);
    m_list->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_list->setSpacing(0);
    m_list->setUniformItemSizes(true);
    m_list->setAttribute(Qt::WA_MacShowFocusRect, false);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(header);
    root->addWidget(m_list, 1);

    connect(m_menuBtn, &QPushButton::clicked, this, [this]() {
        emit menuRequested(m_menuBtn->mapToGlobal(QPoint(0, m_menuBtn->height() + 4)));
    });
    connect(m_search, &QLineEdit::textChanged, this, &Sidebar::searchChanged);
    connect(m_list, &QListWidget::itemSelectionChanged, this, &Sidebar::onSelectionChanged);

    // Force the sidebar palette to follow the theme: Window for bg, plus the
    // text-role colors so any unstyled child label inherits the right color.
    auto applyTheme = [this, header]() {
        const Theme &th = Theme::instance();
        const QColor bg = th.sidebarBackground();
        const QColor fg = th.textPrimary();
        for (QWidget *w : {static_cast<QWidget*>(this), header,
                           static_cast<QWidget*>(m_list)}) {
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

void Sidebar::addOrUpdateChat(const ChatListEntry &e) {
    QListWidgetItem *existing = nullptr;
    for (int i = 0; i < m_list->count(); ++i) {
        QListWidgetItem *it = m_list->item(i);
        if (it->data(Qt::UserRole).toString() == e.id) { existing = it; break; }
    }

    QListWidgetItem *item = existing;
    if (!item) {
        item = new QListWidgetItem(m_list);
        item->setData(Qt::UserRole, e.id);
        item->setSizeHint(QSize(280, 64));
    }

    auto *widget = qobject_cast<ChatListItem*>(m_list->itemWidget(item));
    if (!widget) {
        widget = new ChatListItem(m_list);
        m_list->setItemWidget(item, widget);
    }
    widget->setEntry(e);
}

void Sidebar::clearChats() {
    m_list->clear();
    m_currentId.clear();
}

void Sidebar::selectChat(const QString &id) {
    for (int i = 0; i < m_list->count(); ++i) {
        QListWidgetItem *it = m_list->item(i);
        if (it->data(Qt::UserRole).toString() == id) {
            m_list->setCurrentItem(it);
            return;
        }
    }
}

void Sidebar::onSelectionChanged() {
    QListWidgetItem *current = m_list->currentItem();

    // Sync selected state on every item widget so its text colors update.
    for (int i = 0; i < m_list->count(); ++i) {
        QListWidgetItem *it = m_list->item(i);
        if (auto *w = qobject_cast<ChatListItem*>(m_list->itemWidget(it))) {
            w->setSelected(it == current);
        }
    }

    if (!current) return;
    const QString id = current->data(Qt::UserRole).toString();
    if (id == m_currentId) return;
    m_currentId = id;
    emit chatSelected(id);
}

}
