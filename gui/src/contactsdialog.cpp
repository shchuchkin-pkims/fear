#include "contactsdialog.h"

#include <QApplication>
#include <QDateTime>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

extern "C" {
#include "identity.h"
#include "server_proto.h"
#include "contacts_cipher.h"
#include <sodium.h>
}

namespace fear {

ContactsDialog::ContactsDialog(const QString &identityPath,
                               const QString &serverHost,
                               uint16_t       serverPort,
                               QWidget       *parent)
    : QDialog(parent),
      m_identityPath(identityPath),
      m_serverHost(serverHost),
      m_serverPort(serverPort) {

    setWindowTitle(tr("Contacts"));
    setModal(true);
    resize(560, 420);

    auto *layout = new QVBoxLayout(this);

    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("Contacts on %1:%2").arg(serverHost).arg(serverPort), this);
    QFont f = title->font(); f.setPixelSize(14); f.setWeight(QFont::DemiBold); title->setFont(f);
    header->addWidget(title);
    header->addStretch(1);
    m_refreshBtn = new QPushButton(tr("Refresh from server"), this);
    header->addWidget(m_refreshBtn);
    layout->addLayout(header);

    m_status = new QLabel(this);
    m_status->setStyleSheet("color: gray;");
    layout->addWidget(m_status);

    m_list = new QListWidget(this);
    layout->addWidget(m_list, /*stretch=*/1);

    auto *btnRow = new QHBoxLayout;
    m_addBtn = new QPushButton(tr("Add contact…"), this);
    auto *closeBtn = new QPushButton(tr("Close"), this);
    closeBtn->setDefault(true);
    btnRow->addWidget(m_addBtn);
    btnRow->addStretch(1);
    btnRow->addWidget(closeBtn);
    layout->addLayout(btnRow);

    connect(m_refreshBtn, &QPushButton::clicked, this, &ContactsDialog::refreshFromServer);
    connect(m_addBtn,     &QPushButton::clicked, this, &ContactsDialog::addContact);
    connect(closeBtn,     &QPushButton::clicked, this, &QDialog::accept);

    /* Auto-pull on open so the user doesn't have to click. */
    QMetaObject::invokeMethod(this, &ContactsDialog::refreshFromServer,
                              Qt::QueuedConnection);
}

void ContactsDialog::refreshFromServer() {
    m_status->setText(tr("Pulling…"));
    m_refreshBtn->setEnabled(false);
    QApplication::processEvents();

    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    if (identity_load(m_identityPath.toUtf8().constData(), pk, sk) != 0) {
        m_status->setText(tr("No identity yet — connect to a room first."));
        m_refreshBtn->setEnabled(true);
        return;
    }

    uint8_t *blob = nullptr;
    size_t   blob_len = 0;
    sp_status_t st = sp_blob_get(m_serverHost.toUtf8().constData(),
                                 m_serverPort, pk,
                                 CONTACTS_CIPHER_BLOB_TYPE, &blob, &blob_len);
    m_refreshBtn->setEnabled(true);
    if (st == SP_NOT_FOUND) {
        sodium_memzero(sk, sizeof(sk));
        m_list->clear();
        m_status->setText(tr("Server has no contacts blob for this identity yet."));
        return;
    }
    if (st != SP_OK || !blob) {
        sodium_memzero(sk, sizeof(sk));
        free(blob);
        m_status->setText(tr("Pull failed (status=%1).").arg((int)st));
        return;
    }

    uint8_t key[CONTACTS_CIPHER_KEY_BYTES];
    if (contacts_cipher_derive_key(sk, key) != 0) {
        sodium_memzero(sk, sizeof(sk));
        free(blob);
        m_status->setText(tr("Could not derive contacts key."));
        return;
    }
    sodium_memzero(sk, sizeof(sk));

    char *json = nullptr;
    int rc = contacts_cipher_decrypt(blob, blob_len, key, &json);
    sodium_memzero(key, sizeof(key));
    sodium_memzero(blob, blob_len);
    free(blob);
    if (rc != 0 || !json) {
        m_status->setText(tr("Decrypt failed — different identity, or tampered blob."));
        free(json);
        return;
    }
    renderJson(QString::fromUtf8(json));
    sodium_memzero(json, strlen(json));
    free(json);
}

void ContactsDialog::addContact() {
    bool ok = false;
    const QString nick = QInputDialog::getText(this, tr("Add contact"),
        tr("Nickname on %1:").arg(m_serverHost), QLineEdit::Normal,
        QString(), &ok).trimmed();
    if (!ok || nick.isEmpty()) return;

    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    if (identity_load(m_identityPath.toUtf8().constData(), pk, sk) != 0) {
        QMessageBox::warning(this, tr("Add contact"),
            tr("No identity yet — connect to a room first to generate one."));
        return;
    }

    /* 1) Look up nickname → owner pk on the relay. */
    uint8_t target_pk[32];
    sp_status_t lk = sp_lookup_handle(m_serverHost.toUtf8().constData(),
                                      m_serverPort,
                                      nick.toUtf8().constData(), target_pk);
    if (lk == SP_NOT_FOUND) {
        sodium_memzero(sk, sizeof(sk));
        QMessageBox::information(this, tr("Add contact"),
            tr("'%1' not registered on %2.").arg(nick, m_serverHost));
        return;
    }
    if (lk != SP_OK) {
        sodium_memzero(sk, sizeof(sk));
        QMessageBox::warning(this, tr("Add contact"),
            tr("Lookup failed (status=%1).").arg((int)lk));
        return;
    }

    /* 2) Pull existing blob, decrypt, append, re-encrypt, push. */
    uint8_t key[CONTACTS_CIPHER_KEY_BYTES];
    if (contacts_cipher_derive_key(sk, key) != 0) {
        sodium_memzero(sk, sizeof(sk));
        return;
    }

    uint8_t *blob = nullptr; size_t blob_len = 0;
    sp_status_t gst = sp_blob_get(m_serverHost.toUtf8().constData(),
                                  m_serverPort, pk,
                                  CONTACTS_CIPHER_BLOB_TYPE, &blob, &blob_len);

    QJsonArray arr;
    if (gst == SP_OK && blob) {
        char *prev = nullptr;
        if (contacts_cipher_decrypt(blob, blob_len, key, &prev) == 0 && prev) {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray(prev));
            if (doc.isObject()) arr = doc.object().value("contacts").toArray();
            sodium_memzero(prev, strlen(prev));
            free(prev);
        }
        sodium_memzero(blob, blob_len);
        free(blob);
    }

    /* base64url-no-padding for pk, matching Android Common.base64Encode. */
    char pk_b64[64];
    sodium_bin2base64(pk_b64, sizeof(pk_b64), target_pk, 32,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    QJsonObject newContact;
    newContact["pk"]      = QString::fromUtf8(pk_b64);
    newContact["name"]    = nick;
    newContact["handle"]  = nick;
    newContact["server"]  = m_serverHost;
    newContact["ts"]      = (qint64)QDateTime::currentMSecsSinceEpoch();
    newContact["verified"] = false;

    /* Skip duplicates. */
    bool exists = false;
    for (const auto &v : arr) {
        if (v.toObject().value("pk").toString() == newContact["pk"].toString()) {
            exists = true; break;
        }
    }
    if (!exists) arr.append(newContact);

    QJsonObject root;
    root["v"] = 1;
    root["contacts"] = arr;
    QByteArray jsonOut = QJsonDocument(root).toJson(QJsonDocument::Compact);

    uint8_t *out_blob = nullptr; size_t out_len = 0;
    int enc = contacts_cipher_encrypt(jsonOut.constData(),
                                      (size_t)jsonOut.size(), key, &out_blob, &out_len);
    sodium_memzero(key, sizeof(key));
    if (enc != 0 || !out_blob) {
        sodium_memzero(sk, sizeof(sk));
        QMessageBox::warning(this, tr("Add contact"), tr("Encrypt failed."));
        return;
    }

    sp_status_t put = sp_blob_put(m_serverHost.toUtf8().constData(),
                                  m_serverPort, pk, sk,
                                  CONTACTS_CIPHER_BLOB_TYPE, out_blob, out_len);
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(out_blob, out_len);
    free(out_blob);

    if (put != SP_OK) {
        QMessageBox::warning(this, tr("Add contact"),
            tr("Push to server failed (status=%1).").arg((int)put));
        return;
    }
    refreshFromServer();
}

void ContactsDialog::renderJson(const QString &json) {
    m_list->clear();
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) {
        m_status->setText(tr("Decrypted, but JSON is not an object."));
        return;
    }
    const QJsonArray arr = doc.object().value("contacts").toArray();
    if (arr.isEmpty()) {
        m_status->setText(tr("No contacts yet."));
        return;
    }
    for (const auto &v : arr) {
        const auto o = v.toObject();
        QString name = o.value("name").toString();
        QString handle = o.value("handle").toString();
        QString server = o.value("server").toString();
        QString line = !handle.isEmpty() && !server.isEmpty()
                       ? QString("%1   %2@%3").arg(name, handle, server)
                       : name;
        if (!line.isEmpty()) m_list->addItem(line);
    }
    m_status->setText(tr("%1 contacts").arg(arr.count()));
}

}  // namespace fear
