#include "identitybackupdialog.h"
#include "qrshowdialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QImage>
#include <QMessageBox>
#include <QStandardPaths>
#include <QApplication>
#include <QCheckBox>
#include <QFile>
#include <QDir>

extern "C" {
#include "identity.h"
#include "identity_backup.h"
#include <sodium.h>
}

#include <zbar.h>

namespace {

/**
 * Decode the first QR code found in `image` via libzbar.
 * Returns an empty QByteArray on failure.
 *
 * Pipeline: QImage → 8-bit grayscale → zbar_image_t (Y800 format)
 *   → zbar_image_scanner_scan → first symbol's text payload.
 */
QByteArray decodeQrFromImage(const QImage &image) {
    if (image.isNull()) return {};

    QImage gray = image.convertToFormat(QImage::Format_Grayscale8);
    if (gray.isNull()) return {};

    zbar::ImageScanner scanner;
    scanner.set_config(zbar::ZBAR_QRCODE, zbar::ZBAR_CFG_ENABLE, 1);

    zbar::Image zimg(gray.width(), gray.height(), "Y800",
                     gray.constBits(), gray.sizeInBytes());

    int n = scanner.scan(zimg);
    QByteArray out;
    if (n > 0) {
        for (auto sym = zimg.symbol_begin(); sym != zimg.symbol_end(); ++sym) {
            const std::string s = sym->get_data();
            out = QByteArray(s.data(), int(s.size()));
            break;  // take the first QR
        }
    }
    zimg.set_data(nullptr, 0);  // detach pixel buffer before QImage frees it
    return out;
}

}  // namespace

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

    if (mode == Export) {
        m_alsoQr = new QCheckBox(tr("Also show backup as QR code (for scanning on phone)"), this);
        layout->addWidget(m_alsoQr);
    }

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
        QString path = QFileDialog::getOpenFileName(
            this, tr("Open backup file or QR image…"),
            defaultDir,
            tr("FEAR backup or QR (*.fbk *.png *.jpg *.jpeg);;All files (*)"));
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
        if (m_mode == Export && m_alsoQr && m_alsoQr->isChecked()) {
            showQrAfterExport();
        }
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

/**
 * After a successful file export, re-encrypt the same identity in memory and
 * pop a QR code window. We re-encrypt rather than reading the just-saved file
 * back so the user only types the password once and we never need to re-prompt.
 */
void IdentityBackupDialog::showQrAfterExport()
{
    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    if (identity_load(m_identityPath.toUtf8().constData(), pk, sk) != 0) {
        return;
    }
    QByteArray pwBytes = m_password->text().toUtf8();
    uint8_t *buf = nullptr; size_t buf_len = 0;
    int rc = identity_backup_export_buf(&buf, &buf_len, sk, pk, pwBytes.constData());
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(pwBytes.data(), pwBytes.size());

    if (rc != 0 || !buf) return;

    QByteArray bytes(reinterpret_cast<const char *>(buf), int(buf_len));
    sodium_memzero(buf, buf_len);
    free(buf);

    QrShowDialog *qr = QrShowDialog::fromBinary(
        bytes,
        tr("Identity backup QR"),
        tr("Scan this on another device → Import identity. Password required to decrypt."),
        nullptr  // top-level so it survives this dialog closing
    );
    sodium_memzero(bytes.data(), bytes.size());
    if (qr) {
        qr->setAttribute(Qt::WA_DeleteOnClose);
        qr->show();
    }
}

bool IdentityBackupDialog::runImport(QString *err)
{
    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];

    // Detect input format. .fbk files start with magic 'FBK1'. Otherwise
    // try loading as an image (PNG/JPG) and decoding the first QR code,
    // whose payload is the base64 of the same .fbk blob.
    QFile inputFile(m_filePath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        if (err) *err = tr("Could not read %1").arg(m_filePath);
        return false;
    }
    QByteArray fileBytes = inputFile.readAll();
    inputFile.close();

    QByteArray blob;
    bool looksLikeFbk = fileBytes.size() >= 4 && memcmp(fileBytes.constData(), "FBK1", 4) == 0;
    if (looksLikeFbk) {
        blob = fileBytes;
    } else {
        QImage img;
        if (!img.loadFromData(fileBytes)) {
            if (err) *err = tr("Not a FEAR backup file and not an image with a QR.");
            return false;
        }
        QByteArray qrText = decodeQrFromImage(img);
        if (qrText.isEmpty()) {
            if (err) *err = tr("No QR code found in the image.");
            return false;
        }
        blob = QByteArray::fromBase64(qrText);
        if (blob.size() < 4 || memcmp(blob.constData(), "FBK1", 4) != 0) {
            if (err) *err = tr("Scanned QR is not a FEAR identity backup.");
            return false;
        }
    }

    QByteArray pwBytes = m_password->text().toUtf8();
    int rc = identity_backup_import_buf(reinterpret_cast<const uint8_t *>(blob.constData()),
                                        size_t(blob.size()),
                                        pwBytes.constData(), sk, pk);
    sodium_memzero(pwBytes.data(), pwBytes.size());
    sodium_memzero(blob.data(), blob.size());

    if (rc != 0) {
        if (err) *err = tr("Could not decrypt. Wrong password or corrupt backup.");
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
