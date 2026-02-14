/**
 * @file knownkeysdialog.cpp
 * @brief Implementation of Known Keys management dialog
 */

#include "knownkeysdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <sodium.h>

/* We re-implement the identity module functions in C++ here
 * since the GUI links against libsodium directly.
 * The known_keys format: name\tpk_base64\tverified\n */

#ifdef Q_OS_WIN
#define FEAR_DIR (QDir::homePath() + "/AppData/Roaming/fear")
#else
#define FEAR_DIR (QDir::homePath() + "/.fear")
#endif

KnownKeysDialog::KnownKeysDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Manage Trusted Keys");
    setMinimumSize(700, 400);
    setupUI();
    refreshTable();
}

QString KnownKeysDialog::knownKeysPath() {
    return FEAR_DIR + "/known_keys";
}

void KnownKeysDialog::setupUI() {
    QVBoxLayout *layout = new QVBoxLayout(this);

    infoLabel = new QLabel("Known identity keys (TOFU database):");
    layout->addWidget(infoLabel);

    table = new QTableWidget(this);
    table->setColumnCount(4);
    table->setHorizontalHeaderLabels({"Name", "Fingerprint", "Public Key", "Status"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table);

    QHBoxLayout *btnLayout = new QHBoxLayout();

    verifyBtn = new QPushButton("Mark as Verified");
    removeBtn = new QPushButton("Remove");
    importBtn = new QPushButton("Import Key...");
    QPushButton *refreshBtn = new QPushButton("Refresh");
    QPushButton *closeBtn = new QPushButton("Close");

    btnLayout->addWidget(verifyBtn);
    btnLayout->addWidget(removeBtn);
    btnLayout->addWidget(importBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(refreshBtn);
    btnLayout->addWidget(closeBtn);
    layout->addLayout(btnLayout);

    connect(verifyBtn, &QPushButton::clicked, this, &KnownKeysDialog::onVerify);
    connect(removeBtn, &QPushButton::clicked, this, &KnownKeysDialog::onRemove);
    connect(importBtn, &QPushButton::clicked, this, &KnownKeysDialog::onImportKey);
    connect(refreshBtn, &QPushButton::clicked, this, &KnownKeysDialog::refreshTable);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
}

void KnownKeysDialog::refreshTable() {
    table->setRowCount(0);

    QFile file(knownKeysPath());
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        infoLabel->setText("No known keys file found.");
        return;
    }

    int count = 0;
    while (!file.atEnd()) {
        QByteArray lineData = file.readLine();
        QString line = QString::fromUtf8(lineData).trimmed();
        if (line.isEmpty()) continue;

        QStringList parts = line.split('\t');
        if (parts.size() < 2) continue;

        QString name = parts[0];
        QString pkB64 = parts[1];
        int verified = (parts.size() >= 3) ? parts[2].toInt() : 0;

        /* Compute fingerprint from pk */
        QString fingerprint = "?";
        QByteArray pkBytes(crypto_sign_PUBLICKEYBYTES, 0);
        size_t bin_len = 0;
        if (sodium_base642bin(
                reinterpret_cast<unsigned char*>(pkBytes.data()),
                crypto_sign_PUBLICKEYBYTES,
                pkB64.toUtf8().constData(), pkB64.toUtf8().size(),
                nullptr, &bin_len, nullptr,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0 &&
            bin_len == crypto_sign_PUBLICKEYBYTES) {

            unsigned char hash[32];
            crypto_generichash(hash, sizeof(hash),
                               reinterpret_cast<const unsigned char*>(pkBytes.constData()),
                               crypto_sign_PUBLICKEYBYTES, nullptr, 0);
            QString fp;
            for (int i = 0; i < 8; i++) {
                if (i > 0) fp += ":";
                fp += QString("%1").arg(hash[i], 2, 16, QChar('0'));
            }
            fingerprint = fp;
        }

        int row = table->rowCount();
        table->insertRow(row);
        table->setItem(row, 0, new QTableWidgetItem(name));
        table->setItem(row, 1, new QTableWidgetItem(fingerprint));
        table->setItem(row, 2, new QTableWidgetItem(pkB64));

        QTableWidgetItem *statusItem = new QTableWidgetItem(
            verified ? "Verified" : "TOFU trusted");
        if (verified) {
            statusItem->setForeground(QColor("#2ecc71"));
        } else {
            statusItem->setForeground(QColor("#f39c12"));
        }
        table->setItem(row, 3, statusItem);

        count++;
    }
    file.close();

    infoLabel->setText(QString("Known identity keys: %1").arg(count));
}

void KnownKeysDialog::onVerify() {
    int row = table->currentRow();
    if (row < 0) {
        QMessageBox::information(this, "Verify", "Select a key to verify.");
        return;
    }

    QString name = table->item(row, 0)->text();
    QString fingerprint = table->item(row, 1)->text();
    QString status = table->item(row, 3)->text();

    if (status == "Verified") {
        QMessageBox::information(this, "Verify",
            QString("Key for \"%1\" is already verified.").arg(name));
        return;
    }

    if (QMessageBox::question(this, "Verify Key",
        QString("Mark key for \"%1\" as verified?\n\n"
                "Fingerprint: %2\n\n"
                "Only do this if you have confirmed the fingerprint\n"
                "through a separate secure channel (in person, phone, etc.).")
            .arg(name, fingerprint),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    /* Rewrite known_keys file with verified=1 for this name */
    QFile file(knownKeysPath());
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QByteArray allData = file.readAll();
    file.close();

    QStringList lines = QString::fromUtf8(allData).split('\n', Qt::SkipEmptyParts);
    QStringList newLines;
    bool found = false;
    for (const QString &line : lines) {
        QStringList parts = line.split('\t');
        if (parts.size() >= 2 && parts[0] == name) {
            newLines.append(parts[0] + "\t" + parts[1] + "\t1");
            found = true;
        } else {
            newLines.append(line);
        }
    }

    if (!found) {
        QMessageBox::warning(this, "Error", "Key not found in database.");
        return;
    }

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) return;
    for (const QString &line : newLines) {
        file.write((line + "\n").toUtf8());
    }
    file.close();

    refreshTable();
    QMessageBox::information(this, "Verified",
        QString("Key for \"%1\" marked as verified.").arg(name));
}

void KnownKeysDialog::onRemove() {
    int row = table->currentRow();
    if (row < 0) {
        QMessageBox::information(this, "Remove", "Select a key to remove.");
        return;
    }

    QString name = table->item(row, 0)->text();

    if (QMessageBox::question(this, "Remove Key",
        QString("Remove trusted key for \"%1\"?\n\n"
                "Next time this user sends a signed message,\n"
                "their key will be re-learned via TOFU.").arg(name),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    QFile file(knownKeysPath());
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QByteArray allData = file.readAll();
    file.close();

    QStringList lines = QString::fromUtf8(allData).split('\n', Qt::SkipEmptyParts);
    QStringList newLines;
    for (const QString &line : lines) {
        QStringList parts = line.split('\t');
        if (parts.size() >= 2 && parts[0] == name) continue; /* skip = delete */
        newLines.append(line);
    }

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) return;
    for (const QString &line : newLines) {
        file.write((line + "\n").toUtf8());
    }
    file.close();

    refreshTable();
}

void KnownKeysDialog::onImportKey() {
    QStringList options;
    options << "Paste base64 public key" << "Import from file";

    bool ok;
    QString choice = QInputDialog::getItem(this, "Import Key",
        "Import method:", options, 0, false, &ok);
    if (!ok) return;

    QString name;
    QByteArray pkBytes;

    if (choice == options[0]) {
        /* Paste base64 */
        name = QInputDialog::getText(this, "Import Key",
            "Peer display name:", QLineEdit::Normal, "", &ok);
        if (!ok || name.isEmpty()) return;

        QString pkB64 = QInputDialog::getText(this, "Import Key",
            "Public key (base64url):", QLineEdit::Normal, "", &ok);
        if (!ok || pkB64.isEmpty()) return;

        pkBytes.resize(crypto_sign_PUBLICKEYBYTES);
        size_t bin_len = 0;
        if (sodium_base642bin(
                reinterpret_cast<unsigned char*>(pkBytes.data()),
                crypto_sign_PUBLICKEYBYTES,
                pkB64.toUtf8().constData(), pkB64.toUtf8().size(),
                nullptr, &bin_len, nullptr,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
            bin_len != crypto_sign_PUBLICKEYBYTES) {
            QMessageBox::warning(this, "Import Error",
                "Invalid public key. Must be base64url-encoded Ed25519 key (32 bytes).");
            return;
        }
    } else {
        /* From file */
        name = QInputDialog::getText(this, "Import Key",
            "Peer display name:", QLineEdit::Normal, "", &ok);
        if (!ok || name.isEmpty()) return;

        QString filePath = QFileDialog::getOpenFileName(this, "Select public key file");
        if (filePath.isEmpty()) return;

        QFile f(filePath);
        if (!f.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "Import Error", "Cannot open file.");
            return;
        }
        QByteArray content = f.readAll().trimmed();
        f.close();

        /* Try base64 decode */
        pkBytes.resize(crypto_sign_PUBLICKEYBYTES);
        size_t bin_len = 0;
        if (sodium_base642bin(
                reinterpret_cast<unsigned char*>(pkBytes.data()),
                crypto_sign_PUBLICKEYBYTES,
                content.constData(), content.size(),
                nullptr, &bin_len, nullptr,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
            bin_len != crypto_sign_PUBLICKEYBYTES) {
            /* Maybe raw binary? */
            if (content.size() == crypto_sign_PUBLICKEYBYTES) {
                pkBytes = content;
            } else {
                QMessageBox::warning(this, "Import Error",
                    "File does not contain a valid Ed25519 public key.");
                return;
            }
        }
    }

    /* Ask if they want to mark as verified */
    int verified = 0;
    if (QMessageBox::question(this, "Import Key",
        "Mark this key as verified?\n\n"
        "Select Yes only if you confirmed the key via a secure channel.",
        QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        verified = 1;
    }

    /* Encode pk to base64 */
    char pkB64Buf[128];
    sodium_bin2base64(pkB64Buf, sizeof(pkB64Buf),
                      reinterpret_cast<const unsigned char*>(pkBytes.constData()),
                      crypto_sign_PUBLICKEYBYTES,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    /* Remove existing entry for same name, then append */
    QString dbPath = knownKeysPath();

    /* Ensure directory exists */
    QDir().mkpath(FEAR_DIR);

    QFile dbFile(dbPath);
    QStringList existingLines;
    if (dbFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!dbFile.atEnd()) {
            QString line = QString::fromUtf8(dbFile.readLine()).trimmed();
            if (line.isEmpty()) continue;
            QStringList parts = line.split('\t');
            if (parts.size() >= 2 && parts[0] == name) continue; /* remove old */
            existingLines.append(line);
        }
        dbFile.close();
    }

    /* Write back + new entry */
    if (!dbFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, "Error", "Cannot write to known_keys file.");
        return;
    }
    for (const QString &line : existingLines) {
        dbFile.write((line + "\n").toUtf8());
    }
    dbFile.write(QString("%1\t%2\t%3\n").arg(name, QString(pkB64Buf),
                 QString::number(verified)).toUtf8());
    dbFile.close();

    refreshTable();

    /* Show fingerprint */
    unsigned char hash[32];
    crypto_generichash(hash, sizeof(hash),
                       reinterpret_cast<const unsigned char*>(pkBytes.constData()),
                       crypto_sign_PUBLICKEYBYTES, nullptr, 0);
    QString fp;
    for (int i = 0; i < 8; i++) {
        if (i > 0) fp += ":";
        fp += QString("%1").arg(hash[i], 2, 16, QChar('0'));
    }

    QMessageBox::information(this, "Imported",
        QString("Key imported for \"%1\"\nFingerprint: %2\nStatus: %3")
            .arg(name, fp, verified ? "Verified" : "TOFU trusted"));
}
