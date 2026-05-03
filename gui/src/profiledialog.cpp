#include "profiledialog.h"
#include "profilesettings.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

extern "C" {
#include "identity.h"
#include <sodium.h>
}

namespace fear {

ProfileDialog::ProfileDialog(ProfileSettings *settings,
                             const QString &identityPath,
                             std::function<void()> onExport,
                             std::function<void()> onShowQr,
                             QWidget *parent)
    : QDialog(parent),
      m_settings(settings),
      m_identityPath(identityPath),
      m_onExport(std::move(onExport)),
      m_onShowQr(std::move(onShowQr)) {

    setWindowTitle(tr("My Profile"));
    setModal(true);
    setMinimumSize(440, 480);

    auto *layout = new QVBoxLayout(this);
    layout->setSpacing(12);

    // ── Header: monogram + name editor ──────────────────────
    auto *header = new QHBoxLayout;

    m_avatar = new QLabel(this);
    m_avatar->setFixedSize(72, 72);
    m_avatar->setAlignment(Qt::AlignCenter);
    m_avatar->setStyleSheet(
        "QLabel { background:#3A3D42; color:#E8EAED; border-radius:36px; "
        "font-size:30px; font-weight:600; }");
    header->addWidget(m_avatar);

    auto *nameCol = new QVBoxLayout;
    nameCol->setSpacing(2);
    auto *nameRow = new QHBoxLayout;
    m_nameEdit = new QLineEdit(m_settings->displayName(), this);
    m_nameEdit->setPlaceholderText(tr("Display name"));
    m_saveBtn  = new QPushButton(tr("Save"), this);
    m_saveBtn->setEnabled(false);
    nameRow->addWidget(m_nameEdit, 1);
    nameRow->addWidget(m_saveBtn);
    nameCol->addLayout(nameRow);

    m_shortIdLabel = new QLabel(this);
    m_shortIdLabel->setStyleSheet("color: gray; font-size: 12px;");
    nameCol->addWidget(m_shortIdLabel);
    nameCol->addStretch(1);
    header->addLayout(nameCol, 1);
    layout->addLayout(header);

    // ── Handles section ──────────────────────────────────────
    auto *handlesLabel = new QLabel(tr("Handles"), this);
    handlesLabel->setStyleSheet("font-weight: 600; margin-top: 6px;");
    layout->addWidget(handlesLabel);

    m_handlesList = new QListWidget(this);
    m_handlesList->setMaximumHeight(120);
    m_handlesList->setToolTip(
        tr("Click a handle to copy. Phase B-2 will add 'Hold @name on this "
           "server' so handles get reserved server-side."));
    layout->addWidget(m_handlesList);

    // ── Fingerprint ──────────────────────────────────────────
    auto *fpHeader = new QLabel(tr("Cryptographic identity"), this);
    fpHeader->setStyleSheet("font-weight: 600; margin-top: 6px;");
    layout->addWidget(fpHeader);

    m_fpLabel = new QLabel(this);
    m_fpLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_fpLabel->setStyleSheet("font-family: monospace; padding: 4px;");
    layout->addWidget(m_fpLabel);

    // ── Action row ───────────────────────────────────────────
    auto *actionRow = new QHBoxLayout;
    auto *exportBtn = new QPushButton(tr("Export identity…"), this);
    auto *qrBtn     = new QPushButton(tr("Show identity as QR…"), this);
    auto *closeBtn  = new QPushButton(tr("Close"), this);
    closeBtn->setDefault(true);
    actionRow->addWidget(exportBtn);
    actionRow->addWidget(qrBtn);
    actionRow->addStretch(1);
    actionRow->addWidget(closeBtn);
    layout->addStretch(1);
    layout->addLayout(actionRow);

    rebuildIdentityLabels();

    // Connections
    connect(m_nameEdit, &QLineEdit::textChanged, this, [this](const QString &t) {
        m_saveBtn->setEnabled(t.trimmed() != m_settings->displayName());
    });
    connect(m_saveBtn,  &QPushButton::clicked, this, &ProfileDialog::saveDisplayName);
    connect(closeBtn,   &QPushButton::clicked, this, &QDialog::accept);
    connect(exportBtn,  &QPushButton::clicked, this, [this] {
        if (m_onExport) m_onExport();
        accept();   // close profile so the export dialog has the focus
    });
    connect(qrBtn, &QPushButton::clicked, this, [this] {
        if (m_onShowQr) m_onShowQr();
        accept();
    });
    connect(m_handlesList, &QListWidget::itemClicked, this,
            [this](QListWidgetItem *it) { copyToClipboard(it->text()); });
}

void ProfileDialog::saveDisplayName() {
    const QString v = m_nameEdit->text().trimmed();
    if (v.isEmpty()) return;
    m_settings->setDisplayName(v);
    m_saveBtn->setEnabled(false);
    rebuildIdentityLabels();   // refresh monogram + short id + handles preview
}

void ProfileDialog::copyToClipboard(const QString &text) {
    QApplication::clipboard()->setText(text);
}

void ProfileDialog::rebuildIdentityLabels() {
    const QString name = m_settings->displayName();

    // Monogram letter — empty name → "?"
    QString letter = name.isEmpty() ? QStringLiteral("?")
                                    : name.left(1).toUpper();
    m_avatar->setText(letter);

    // Pull identity_pk fingerprint and render name#fpshort + full hex.
    QString shortId, fpFull;
    if (!m_identityPath.isEmpty() && QFile::exists(m_identityPath)) {
        uint8_t pk[IDENTITY_PK_BYTES];
        if (identity_load_pk(m_identityPath.toUtf8().constData(), pk) == 0) {
            uint8_t hash[8];
            crypto_generichash(hash, sizeof(hash), pk, IDENTITY_PK_BYTES, NULL, 0);
            QString fpshort;
            for (int i = 0; i < 4; ++i) fpshort += QString::asprintf("%02x", hash[i]);
            for (int i = 0; i < 8; ++i) {
                fpFull += QString::asprintf("%02x", hash[i]);
                if (i < 7) fpFull += ':';
            }
            shortId = QString("%1#%2").arg(name.isEmpty() ? tr("you") : name, fpshort);
        }
    }
    m_shortIdLabel->setText(shortId.isEmpty() ? tr("(no identity yet)") : shortId);
    m_fpLabel->setText(fpFull.isEmpty()
        ? tr("Connect to a room first to generate your identity.")
        : fpFull);

    // Refresh handles list
    m_handlesList->clear();
    const auto servers = m_settings->registeredServers();
    if (servers.isEmpty()) {
        auto *placeholder = new QListWidgetItem(
            tr("No server handles registered yet. They'll appear here as you "
               "connect to new servers."));
        placeholder->setFlags(Qt::NoItemFlags);
        placeholder->setForeground(Qt::gray);
        m_handlesList->addItem(placeholder);
    } else {
        for (const QString &h : servers) {
            m_handlesList->addItem(QString("@%1@%2").arg(name, h));
        }
    }
}

}  // namespace fear
