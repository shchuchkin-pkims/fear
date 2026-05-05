#include "peerprofiledialog.h"
#include "widgets/avatar.h"

#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace fear {

namespace {

QLabel *makeMonoValue(const QString &text, QWidget *parent) {
    auto *l = new QLabel(text, parent);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    QFont f = l->font();
    f.setStyleHint(QFont::Monospace);
    f.setFamily("monospace");
    f.setPixelSize(12);
    l->setFont(f);
    l->setWordWrap(true);
    return l;
}

QWidget *makeRow(const QString &label, const QString &value, bool mono, QWidget *parent) {
    auto *row = new QWidget(parent);
    auto *lay = new QHBoxLayout(row);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(8);

    auto *lab = new QLabel(label, row);
    lab->setMinimumWidth(110);
    lab->setStyleSheet("color: gray;");
    lay->addWidget(lab, 0, Qt::AlignTop);

    QLabel *val = mono ? makeMonoValue(value, row) : new QLabel(value, row);
    if (!mono) {
        val->setTextInteractionFlags(Qt::TextSelectableByMouse);
        val->setWordWrap(true);
    }
    lay->addWidget(val, 1);

    auto *copy = new QPushButton(QObject::tr("Copy"), row);
    copy->setFlat(true);
    copy->setCursor(Qt::PointingHandCursor);
    QObject::connect(copy, &QPushButton::clicked, copy, [value]() {
        QApplication::clipboard()->setText(value);
    });
    lay->addWidget(copy, 0, Qt::AlignTop);

    return row;
}

}  // namespace

PeerProfileDialog::PeerProfileDialog(const QString &displayName,
                                     const QString &pkB64,
                                     const QString &fingerprint,
                                     const QString &handle,
                                     const QString &server,
                                     bool verified,
                                     QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Profile"));
    setMinimumWidth(420);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(16, 16, 16, 16);
    root->setSpacing(12);

    // Header row: avatar + display name
    auto *hdr = new QWidget(this);
    auto *hdrLay = new QHBoxLayout(hdr);
    hdrLay->setContentsMargins(0, 0, 0, 0);
    hdrLay->setSpacing(12);

    auto *av = new Avatar(hdr);
    av->setSeed(displayName);
    av->setDiameter(56);
    hdrLay->addWidget(av, 0, Qt::AlignTop);

    auto *nameBox = new QVBoxLayout();
    nameBox->setContentsMargins(0, 0, 0, 0);
    nameBox->setSpacing(2);
    auto *nameLbl = new QLabel(displayName, hdr);
    QFont nf = nameLbl->font();
    nf.setBold(true);
    nf.setPixelSize(18);
    nameLbl->setFont(nf);
    nameBox->addWidget(nameLbl);
    if (!fingerprint.isEmpty()) {
        // Use first 8 hex chars (4 bytes) as the short fp displayed inline.
        QString fpshort = fingerprint;
        fpshort.replace(":", "");
        if (fpshort.size() > 8) fpshort = fpshort.left(8);
        auto *sub = new QLabel(QString("%1#%2").arg(displayName, fpshort), hdr);
        sub->setStyleSheet("color: gray;");
        nameBox->addWidget(sub);
    }
    if (verified) {
        auto *v = new QLabel(tr("✓ verified"), hdr);
        v->setStyleSheet("color: #4CAF50; font-weight: 500;");
        nameBox->addWidget(v);
    }
    nameBox->addStretch(1);
    hdrLay->addLayout(nameBox, 1);
    root->addWidget(hdr);

    // Detail rows
    if (!handle.isEmpty() && !server.isEmpty()) {
        root->addWidget(makeRow(tr("Handle"),
                                QString("%1@%2").arg(handle, server),
                                false, this));
    }
    if (!fingerprint.isEmpty()) {
        root->addWidget(makeRow(tr("Identity"), fingerprint, true, this));
    } else {
        auto *info = new QLabel(
            tr("No signed messages received from this peer yet — "
               "their cryptographic identifier is not known."), this);
        info->setStyleSheet("color: gray;");
        info->setWordWrap(true);
        root->addWidget(info);
    }

    root->addStretch(1);

    // Buttons
    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch(1);
    if (!pkB64.isEmpty()) {
        auto *openBtn = new QPushButton(tr("Open chat"), this);
        connect(openBtn, &QPushButton::clicked, this, [this, pkB64]() {
            emit openChatRequested(pkB64);
            accept();
        });
        btnRow->addWidget(openBtn);
    }
    auto *closeBtn = new QPushButton(tr("Close"), this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);
}

}  // namespace fear
