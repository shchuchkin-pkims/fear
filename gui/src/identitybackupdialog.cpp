#include "identitybackupdialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QStandardPaths>
#include <QApplication>
#include <QFile>
#include <QDir>

extern "C" {
#include "identity.h"
#include "identity_backup.h"
#include <sodium.h>
}

IdentityBackupDialog::IdentityBackupDialog(Mode mode, const QString &identityPath, QWidget *parent)
    : QDialog(parent), m_mode(mode), m_identityPath(identityPath)
{
    setWindowTitle(mode == Export ? tr("Export identity") : tr("Import identity"));
    setModal(true);
    setMinimumWidth(420);

    auto *layout = new QVBoxLayout(this);

    auto *intro = new QLabel(this);
    intro->setWordWrap(true);
    if (mode == Export) {
        intro->setText(tr(
            "Save your Ed25519 identity to an encrypted .fbk file.\n"
            "You'll need the password to restore it on another device. "
            "Lose the password and the backup is unrecoverable."));
    } else {
        intro->setText(tr(
            "Restore an Ed25519 identity from an encrypted .fbk file.\n"
            "This will replace your current identity if any."));
    }
    layout->addWidget(intro);

    // File row
    auto *fileRow = new QHBoxLayout;
    m_pathLabel = new QLabel(tr("(no file selected)"), this);
    m_pathLabel->setStyleSheet("color: gray;");
    m_browseBtn = new QPushButton(mode == Export ? tr("Choose…") : tr("Open…"), this);
    fileRow->addWidget(m_pathLabel, 1);
    fileRow->addWidget(m_browseBtn);
    layout->addLayout(fileRow);

    // Password
    auto *form = new QFormLayout;
    m_password = new QLineEdit(this);
    m_password->setEchoMode(QLineEdit::Password);
    m_password->setPlaceholderText(tr("Password"));
    form->addRow(tr("Password:"), m_password);

    m_passwordConfirm = nullptr;
    if (mode == Export) {
        m_passwordConfirm = new QLineEdit(this);
        m_passwordConfirm->setEchoMode(QLineEdit::Password);
        m_passwordConfirm->setPlaceholderText(tr("Repeat password"));
        form->addRow(tr("Confirm:"), m_passwordConfirm);
    }
    layout->addLayout(form);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setStyleSheet("color: #c0392b;");
    layout->addWidget(m_status);

    // Buttons
    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    auto *cancel = new QPushButton(tr("Cancel"), this);
    m_okBtn = new QPushButton(mode == Export ? tr("Export") : tr("Import"), this);
    m_okBtn->setDefault(true);
    btnRow->addWidget(cancel);
    btnRow->addWidget(m_okBtn);
    layout->addLayout(btnRow);

    connect(m_browseBtn, &QPushButton::clicked, this, &IdentityBackupDialog::browseFile);
    connect(m_okBtn,     &QPushButton::clicked, this, &IdentityBackupDialog::onAccept);
    connect(cancel,      &QPushButton::clicked, this, &QDialog::reject);
}

void IdentityBackupDialog::browseFile()
{
    QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (m_mode == Export) {
        QString suggested = defaultDir + "/fear-identity-backup.fbk";
        QString path = QFileDialog::getSaveFileName(this, tr("Save backup to…"),
                                                    suggested, tr("FEAR backup (*.fbk)"));
        if (!path.isEmpty()) {
            if (!path.endsWith(".fbk", Qt::CaseInsensitive)) path += ".fbk";
            m_filePath = path;
            m_pathLabel->setText(QFileInfo(path).fileName());
            m_pathLabel->setStyleSheet("");
        }
    } else {
        QString path = QFileDialog::getOpenFileName(this, tr("Open backup file…"),
                                                    defaultDir, tr("FEAR backup (*.fbk);;All files (*)"));
        if (!path.isEmpty()) {
            m_filePath = path;
            m_pathLabel->setText(QFileInfo(path).fileName());
            m_pathLabel->setStyleSheet("");
        }
    }
}

void IdentityBackupDialog::onAccept()
{
    if (m_filePath.isEmpty()) {
        m_status->setText(tr("Please choose a file first."));
        return;
    }
    if (m_password->text().isEmpty()) {
        m_status->setText(tr("Password cannot be empty."));
        return;
    }
    if (m_mode == Export && m_password->text() != m_passwordConfirm->text()) {
        m_status->setText(tr("Passwords do not match."));
        return;
    }
    if (m_password->text().size() < 6) {
        m_status->setText(tr("Password is too short (minimum 6 characters)."));
        return;
    }

    m_okBtn->setEnabled(false);
    m_status->setStyleSheet("color: gray;");
    m_status->setText(m_mode == Export ? tr("Encrypting…") : tr("Decrypting…"));
    QApplication::processEvents();

    QString err;
    bool ok = (m_mode == Export) ? runExport(&err) : runImport(&err);

    m_okBtn->setEnabled(true);
    if (ok) {
        QMessageBox::information(this,
                                 m_mode == Export ? tr("Export complete") : tr("Import complete"),
                                 m_mode == Export
                                    ? tr("Identity saved to %1.\nKeep the file (and your password) safe.").arg(QFileInfo(m_filePath).fileName())
                                    : tr("Identity restored. Reconnect to apply the change."));
        accept();
    } else {
        m_status->setStyleSheet("color: #c0392b;");
        m_status->setText(err);
    }
}

bool IdentityBackupDialog::runExport(QString *err)
{
    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    if (identity_load(m_identityPath.toUtf8().constData(), pk, sk) != 0) {
        if (err) *err = tr("Could not read current identity from %1").arg(m_identityPath);
        return false;
    }

    QByteArray pwBytes = m_password->text().toUtf8();
    int rc = identity_backup_export(m_filePath.toUtf8().constData(), sk, pk, pwBytes.constData());
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(pwBytes.data(), pwBytes.size());

    if (rc != 0) {
        if (err) *err = tr("Encryption failed (could not write file?).");
        return false;
    }
    return true;
}

bool IdentityBackupDialog::runImport(QString *err)
{
    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];

    QByteArray pwBytes = m_password->text().toUtf8();
    int rc = identity_backup_import(m_filePath.toUtf8().constData(),
                                    pwBytes.constData(), sk, pk);
    sodium_memzero(pwBytes.data(), pwBytes.size());

    if (rc != 0) {
        if (err) *err = tr("Could not decrypt file. Wrong password or corrupt backup.");
        return false;
    }

    // Write to identity file in the same PK/SK format used by identity.c
    char pk_b64[128], sk_b64[256];
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL ||
        sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, IDENTITY_SK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        sodium_memzero(sk, sizeof(sk));
        if (err) *err = tr("Internal error encoding identity.");
        return false;
    }
    sodium_memzero(sk, sizeof(sk));

    QFile f(m_identityPath);
    QFileInfo(m_identityPath).absoluteDir().mkpath(".");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        sodium_memzero(sk_b64, sizeof(sk_b64));
        if (err) *err = tr("Could not write %1").arg(m_identityPath);
        return false;
    }
    QByteArray content = QString("PK:%1\nSK:%2\n").arg(pk_b64, sk_b64).toUtf8();
    f.write(content);
    f.close();
    sodium_memzero(content.data(), content.size());
    sodium_memzero(sk_b64, sizeof(sk_b64));

#ifdef Q_OS_UNIX
    QFile::setPermissions(m_identityPath, QFile::ReadOwner | QFile::WriteOwner);
#endif
    return true;
}
