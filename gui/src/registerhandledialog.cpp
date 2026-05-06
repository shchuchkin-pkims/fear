#include "registerhandledialog.h"

#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QVBoxLayout>
#include <QtConcurrent>

extern "C" {
#include "identity.h"
#include "server_proto.h"
}

namespace fear {

RegisterHandleDialog::RegisterHandleDialog(const QString &serverHost,
                                           uint16_t       serverPort,
                                           const QString &identityPath,
                                           const QString &suggestedHandle,
                                           QWidget       *parent)
    : QDialog(parent),
      m_host(serverHost),
      m_port(serverPort),
      m_identityPath(identityPath)
{
    setWindowTitle(tr("Register handle"));
    setModal(true);
    setMinimumWidth(420);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(20, 18, 20, 18);
    root->setSpacing(12);

    auto *heading = new QLabel(tr("Register a short name on %1").arg(serverHost), this);
    QFont f = heading->font();
    f.setPixelSize(18);
    f.setWeight(QFont::Medium);
    heading->setFont(f);
    root->addWidget(heading);

    m_intro = new QLabel(this);
    m_intro->setWordWrap(true);
    m_intro->setText(tr(
        "Choose an identifier of the form «@nickname». It is bound to your "
        "cryptographic identity (Ed25519 public key) and lets others find "
        "you on this server as nickname@%1. The handle cannot be reassigned "
        "to another key once registered.").arg(serverHost));
    root->addWidget(m_intro);

    m_handleEdit = new QLineEdit(this);
    m_handleEdit->setPlaceholderText(tr("alice"));
    m_handleEdit->setMaxLength(32);
    /* server allows: 3..32 chars, first alpha, rest alnum / . _ - */
    m_handleEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression(QStringLiteral("[a-z][a-z0-9._-]{0,31}")), this));
    if (!suggestedHandle.isEmpty()) m_handleEdit->setText(suggestedHandle.toLower());
    root->addWidget(m_handleEdit);

    m_errorLbl = new QLabel(this);
    m_errorLbl->setWordWrap(true);
    m_errorLbl->setStyleSheet(QStringLiteral("color: #c62828;"));
    m_errorLbl->setVisible(false);
    root->addWidget(m_errorLbl);

    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch(1);
    m_cancelBtn = new QPushButton(tr("Cancel"), this);
    m_cancelBtn->setFlat(true);
    m_submitBtn = new QPushButton(tr("Register"), this);
    m_submitBtn->setDefault(true);
    btnRow->addWidget(m_cancelBtn);
    btnRow->addWidget(m_submitBtn);
    root->addLayout(btnRow);

    connect(m_cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_submitBtn, &QPushButton::clicked, this, &RegisterHandleDialog::onSubmitClicked);
}

void RegisterHandleDialog::setBusy(bool busy) {
    m_submitBtn->setEnabled(!busy);
    m_cancelBtn->setEnabled(!busy);
    m_handleEdit->setReadOnly(busy);
    m_submitBtn->setText(busy ? tr("Registering…") : tr("Register"));
}

void RegisterHandleDialog::showError(const QString &msg) {
    m_errorLbl->setText(msg);
    m_errorLbl->setVisible(!msg.isEmpty());
}

void RegisterHandleDialog::onSubmitClicked() {
    showError(QString());
    const QString h = m_handleEdit->text().trimmed().toLower();
    if (h.size() < 3) {
        showError(tr("Handle must be at least 3 characters."));
        return;
    }
    runRegister(h);
}

void RegisterHandleDialog::runRegister(const QString &handle) {
    setBusy(true);

    /* Run server round-trip on a worker thread so the UI keeps responding. */
    auto *watcher = new QFutureWatcher<sp_status_t>(this);
    connect(watcher, &QFutureWatcher<sp_status_t>::finished, this,
            [this, watcher, handle]() {
        watcher->deleteLater();
        const sp_status_t st = watcher->result();
        setBusy(false);
        if (st == SP_OK) {
            m_chosen = handle;
            accept();
            return;
        }
        switch (st) {
            case SP_NOT_FOUND:     /* not used by REGISTER, but keep exhaustive */
            case SP_INVALID:       showError(tr("Server rejected the handle as invalid.")); break;
            case SP_SERVER_ERROR:  showError(tr("Handle is already taken on this server.")); break;
            case SP_NETWORK_ERROR: showError(tr("Cannot reach the server. Check connection and retry.")); break;
            case SP_BAD_REPLY:     showError(tr("Malformed server reply.")); break;
            default:               showError(tr("Registration failed.")); break;
        }
    });

    const QByteArray host  = m_host.toUtf8();
    const QByteArray hb    = handle.toUtf8();
    const QByteArray ipath = m_identityPath.toUtf8();
    const uint16_t   port  = m_port;
    auto future = QtConcurrent::run([host, port, hb, ipath]() -> sp_status_t {
        uint8_t pk[IDENTITY_PK_BYTES];
        uint8_t sk[IDENTITY_SK_BYTES];
        if (identity_load(ipath.constData(), pk, sk) != 0) {
            return SP_INVALID;
        }
        const sp_status_t rc = sp_register_handle(
            host.constData(), port, hb.constData(), pk, sk);
        sodium_memzero(sk, sizeof(sk));
        return rc;
    });
    watcher->setFuture(future);
}

}  // namespace fear
