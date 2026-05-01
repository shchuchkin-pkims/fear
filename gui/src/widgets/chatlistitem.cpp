#include "chatlistitem.h"
#include "avatar.h"
#include "../theme/theme.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPainter>

namespace fear {

ChatListItem::ChatListItem(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, false);

    m_avatar = new Avatar(this);
    m_avatar->setDiameter(48);

    m_title = new QLabel(this);
    QFont tf = m_title->font();
    tf.setWeight(QFont::DemiBold);
    tf.setPixelSize(14);
    m_title->setFont(tf);

    m_preview = new QLabel(this);
    QFont pf = m_preview->font();
    pf.setPixelSize(12);
    m_preview->setFont(pf);

    m_time = new QLabel(this);
    QFont mf = m_time->font();
    mf.setPixelSize(11);
    m_time->setFont(mf);
    m_time->setAlignment(Qt::AlignRight | Qt::AlignTop);

    applyColors();

    // Keep colors in sync with the active theme.
    connect(&Theme::instance(), &Theme::modeChanged, this,
            [this](Theme::Mode){ applyColors(); update(); });

    m_badge = new QLabel(this);
    m_badge->setAlignment(Qt::AlignCenter);
    m_badge->setMinimumSize(20, 20);
    m_badge->setMaximumHeight(20);
    m_badge->setStyleSheet(QString(
        "background-color: %1; color: white; border-radius: 10px; padding: 0 6px; font-size: 11px; font-weight: 600;"
    ).arg(Theme::instance().unreadBadge().name()));
    m_badge->hide();

    auto *root = new QHBoxLayout(this);
    root->setContentsMargins(12, 8, 12, 8);
    root->setSpacing(10);
    root->addWidget(m_avatar);

    auto *textCol = new QVBoxLayout();
    textCol->setContentsMargins(0, 0, 0, 0);
    textCol->setSpacing(2);

    auto *topRow = new QHBoxLayout();
    topRow->setContentsMargins(0, 0, 0, 0);
    topRow->addWidget(m_title, 1);
    topRow->addWidget(m_time, 0);

    auto *bottomRow = new QHBoxLayout();
    bottomRow->setContentsMargins(0, 0, 0, 0);
    bottomRow->addWidget(m_preview, 1);
    bottomRow->addWidget(m_badge, 0, Qt::AlignRight | Qt::AlignBottom);

    textCol->addLayout(topRow);
    textCol->addLayout(bottomRow);
    root->addLayout(textCol, 1);
}

void ChatListItem::setEntry(const ChatListEntry &e) {
    m_avatar->setSeed(e.title);
    m_title->setText(e.title);
    m_preview->setText(e.preview);

    if (e.lastActivity.isValid()) {
        const QDateTime now = QDateTime::currentDateTime();
        if (e.lastActivity.date() == now.date()) {
            m_time->setText(e.lastActivity.toString("HH:mm"));
        } else if (e.lastActivity.daysTo(now) < 7) {
            m_time->setText(e.lastActivity.toString("ddd"));
        } else {
            m_time->setText(e.lastActivity.toString("dd.MM"));
        }
    } else {
        m_time->clear();
    }

    if (e.unread > 0) {
        m_badge->setText(e.unread > 99 ? "99+" : QString::number(e.unread));
        m_badge->show();
    } else {
        m_badge->hide();
    }
}

void ChatListItem::paintEvent(QPaintEvent *) {
    // QListWidget's QSS ::item:selected isn't applied when the item uses
    // setItemWidget — so we paint the selected/hover bg ourselves.
    if (!m_selected) return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(Theme::instance().selectedItem());
    p.drawRect(rect());
}

void ChatListItem::setSelected(bool selected) {
    if (m_selected == selected) return;
    m_selected = selected;
    applyColors();
    update();   // repaint the bg highlight
}

void ChatListItem::applyColors() {
    const Theme &th = Theme::instance();
    // When the item is selected the row is painted with the accent color
    // (selectedItem) — make all text white-on-accent so it stays readable.
    const QString primary   = m_selected ? "#FFFFFF" : th.textPrimary().name();
    const QString secondary = m_selected ? "rgba(255,255,255,0.78)" : th.textSecondary().name();
    m_title->setStyleSheet  ("color: " + primary   + "; background: transparent;");
    m_preview->setStyleSheet("color: " + secondary + "; background: transparent;");
    m_time->setStyleSheet   ("color: " + secondary + "; background: transparent;");
}

}
