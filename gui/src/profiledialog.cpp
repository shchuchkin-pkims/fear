#include "profiledialog.h"
#include "profilesettings.h"
#include "registerhandledialog.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QInputDialog>
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
                             const QString &defaultHost,
                             uint16_t defaultPort,
                             QWidget *parent)
    : QDialog(parent),
      m_settings(settings),
      m_identityPath(identityPath),
      m_onExport(std::move(onExport)),
      m_onShowQr(std::move(onShowQr)),
      m_defaultHost(defaultHost),
      m_defaultPort(defaultPort) {

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
    m_handlesList->setToolTip(tr("Click a handle to copy."));
    layout->addWidget(m_handlesList);

    auto *handleBtnRow = new QHBoxLayout();
    m_removeHandleBtn = new QPushButton(tr("Удалить выбранный"), this);
    m_removeHandleBtn->setEnabled(false);
    m_registerHandleBtn = new QPushButton(tr("Зарегистрировать новый…"), this);
    handleBtnRow->addWidget(m_removeHandleBtn);
    handleBtnRow->addStretch(1);
    handleBtnRow->addWidget(m_registerHandleBtn);
    layout->addLayout(handleBtnRow);

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
    connect(m_handlesList, &QListWidget::itemSelectionChanged, this, [this]() {
        auto *it = m_handlesList->currentItem();
        m_removeHandleBtn->setEnabled(it && (it->flags() & Qt::ItemIsEnabled));
    });
    connect(m_removeHandleBtn,   &QPushButton::clicked, this, &ProfileDialog::onRemoveHandle);
    connect(m_registerHandleBtn, &QPushButton::clicked, this, &ProfileDialog::onRegisterHandle);
}

void ProfileDialog::onRemoveHandle() {
    auto *it = m_handlesList->currentItem();
    if (!it) return;
    /* Каждый item хранит host в Qt::UserRole. */
    const QString host = it->data(Qt::UserRole).toString();
    if (host.isEmpty()) return;
    auto answer = QMessageBox::question(this, tr("Забыть handle"),
        tr("Удалить локальную запись о регистрации @%1@%2?\n\n"
           "На сервере handle останется зарезервированным за вашим ключом.\n"
           "При следующей регистрации того же ключа старый handle будет\n"
           "автоматически освобождён сервером.")
            .arg(m_settings->handleFor(host), host));
    if (answer != QMessageBox::Yes) return;
    m_settings->forgetRegistration(host);
    rebuildIdentityLabels();
}

void ProfileDialog::onRegisterHandle() {
    QString host = m_defaultHost;
    if (host.isEmpty()) {
        bool ok = false;
        host = QInputDialog::getText(this, tr("Сервер"),
            tr("Адрес сервера (host[:port]):"),
            QLineEdit::Normal, QStringLiteral("fear-project.ru"), &ok);
        if (!ok) return;
        host = host.trimmed();
        if (host.isEmpty()) return;
    }
    /* Допускаем формат host:port в строке. */
    uint16_t port = m_defaultPort > 0 ? m_defaultPort : 8888;
    int colon = host.lastIndexOf(':');
    if (colon > 0) {
        bool okp = false;
        const int parsed = host.mid(colon + 1).toInt(&okp);
        if (okp && parsed > 0 && parsed < 65536) {
            port = static_cast<uint16_t>(parsed);
            host = host.left(colon);
        }
    }
    const QString suggest = m_settings->displayName().toLower();
    RegisterHandleDialog dlg(host, port, m_identityPath, suggest, this);
    if (dlg.exec() != QDialog::Accepted) return;
    const QString chosen = dlg.chosenHandle();
    if (chosen.isEmpty()) return;
    m_settings->markRegisteredAs(host, chosen);
    rebuildIdentityLabels();
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

    // Refresh handles list — берём актуальный handle из ProfileSettings
    // для каждого host. Каждому item-у привязываем host через UserRole,
    // чтобы кнопка «Удалить» знала, какую запись чистить.
    m_handlesList->clear();
    const auto servers = m_settings->registeredServers();
    if (servers.isEmpty()) {
        auto *placeholder = new QListWidgetItem(
            tr("Пока нет зарегистрированных handle. Нажмите «Зарегистрировать новый…»."));
        placeholder->setFlags(Qt::NoItemFlags);
        placeholder->setForeground(Qt::gray);
        m_handlesList->addItem(placeholder);
    } else {
        for (const QString &h : servers) {
            const QString full = m_settings->handleAtServer(h);
            auto *item = new QListWidgetItem(full.isEmpty()
                ? QStringLiteral("@?@%1").arg(h) : full);
            item->setData(Qt::UserRole, h);
            m_handlesList->addItem(item);
        }
    }
    if (m_removeHandleBtn) m_removeHandleBtn->setEnabled(false);
}

}  // namespace fear
