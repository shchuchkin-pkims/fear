#include "groupparticipantsdialog.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

namespace fear {

GroupParticipantsDialog::GroupParticipantsDialog(const QString    &roomTitle,
                                                 const QStringList &participants,
                                                 QWidget          *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Room participants"));
    setModal(true);
    setMinimumWidth(360);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(16, 14, 16, 14);
    root->setSpacing(10);

    auto *title = new QLabel(roomTitle, this);
    QFont tf = title->font();
    tf.setPixelSize(16);
    tf.setBold(true);
    title->setFont(tf);
    root->addWidget(title);

    auto *count = new QLabel(
        tr("%1 participant(s) currently online").arg(participants.size()), this);
    count->setStyleSheet(QStringLiteral("color: gray;"));
    root->addWidget(count);

    m_list = new QListWidget(this);
    m_list->setAlternatingRowColors(true);
    if (participants.isEmpty()) {
        m_list->addItem(tr("The server has not yet sent the participant list."));
        m_list->item(0)->setFlags(Qt::NoItemFlags);
    } else {
        for (const QString &p : participants) {
            if (!p.isEmpty()) m_list->addItem(p);
        }
    }
    root->addWidget(m_list, 1);

    connect(m_list, &QListWidget::itemActivated, this,
            [this](QListWidgetItem *item) {
        if (!item || !(item->flags() & Qt::ItemIsEnabled)) return;
        emit peerSelected(item->text());
        accept();
    });

    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch(1);
    auto *closeBtn = new QPushButton(tr("Close"), this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);
}

}  // namespace fear
