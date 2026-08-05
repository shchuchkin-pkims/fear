#include "adminwindow.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString humanBytes(qint64 n) {
    if (n < 1024) return QObject::tr("%1 B").arg(n);
    if (n < 1024 * 1024) return QObject::tr("%1 KB").arg(n / 1024.0, 0, 'f', 1);
    return QObject::tr("%1 MB").arg(n / (1024.0 * 1024.0), 0, 'f', 1);
}

QString whenText(const QDateTime &t) {
    return t.isValid() ? t.toString(QStringLiteral("yyyy-MM-dd HH:mm")) : QStringLiteral("-");
}

QTableWidget *makeTable(const QStringList &headers) {
    auto *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setAlternatingRowColors(true);
    t->verticalHeader()->setVisible(false);
    t->horizontalHeader()->setStretchLastSection(true);
    t->setSortingEnabled(true);
    return t;
}

/** Ячейка, в первой колонке которой спрятан ключ строки. */
QTableWidgetItem *keyedItem(const QString &text, const QByteArray &pk) {
    auto *item = new QTableWidgetItem(text);
    item->setData(Qt::UserRole, pk);
    return item;
}

} // namespace

AdminWindow::AdminWindow(QWidget *parent) : QMainWindow(parent) {
    buildUi();

    m_sessionTimer = new QTimer(this);
    m_sessionTimer->setInterval(5000);
    connect(m_sessionTimer, &QTimer::timeout, this, &AdminWindow::refreshSessions);
    m_sessionTimer->start();
}

void AdminWindow::buildUi() {
    setWindowTitle(tr("F.E.A.R. - relay administration"));
    resize(1000, 640);

    auto *fileMenu = menuBar()->addMenu(tr("&Database"));
    fileMenu->addAction(tr("&Open..."), this, &AdminWindow::chooseDatabase);
    fileMenu->addAction(tr("&Refresh"), this, &AdminWindow::refreshAll,
                        QKeySequence(QKeySequence::Refresh));
    fileMenu->addSeparator();
    fileMenu->addAction(tr("&Quit"), qApp, &QApplication::quit);

    auto *tabs = new QTabWidget;
    setCentralWidget(tabs);

    /* --- Пользователи --------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);

        auto *top = new QHBoxLayout;
        m_filter = new QLineEdit;
        m_filter->setPlaceholderText(tr("search by handle or fingerprint"));
        connect(m_filter, &QLineEdit::textChanged, this, [this] { fillHandles(); });
        top->addWidget(new QLabel(tr("Find:")));
        top->addWidget(m_filter, 1);
        v->addLayout(top);

        m_handles = makeTable({ tr("Handle"), tr("Key fingerprint"), tr("Claimed"),
                                tr("Blobs"), tr("Blocked") });
        v->addWidget(m_handles, 1);

        auto *row = new QHBoxLayout;
        auto *del = new QPushButton(tr("Release handle"));
        auto *blk = new QPushButton(tr("Block key"));
        auto *exp = new QPushButton(tr("Export..."));
        connect(del, &QPushButton::clicked, this, &AdminWindow::deleteSelectedHandles);
        connect(blk, &QPushButton::clicked, this, &AdminWindow::blockSelectedHandles);
        connect(exp, &QPushButton::clicked, this, &AdminWindow::exportHandles);
        row->addWidget(del);
        row->addWidget(blk);
        row->addStretch(1);
        row->addWidget(exp);
        v->addLayout(row);

        tabs->addTab(page, tr("Users"));
    }

    /* --- Блобы ----------------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        v->addWidget(new QLabel(tr(
            "The contents are encrypted by the client - neither the server nor "
            "this utility can read them. Only metadata is shown.")));
        m_blobs = makeTable({ tr("Key fingerprint"), tr("Handle"), tr("Type"),
                              tr("Size"), tr("Updated") });
        v->addWidget(m_blobs, 1);

        auto *row = new QHBoxLayout;
        auto *del = new QPushButton(tr("Delete blob"));
        connect(del, &QPushButton::clicked, this, &AdminWindow::deleteSelectedBlobs);
        row->addWidget(del);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Blobs"));
    }

    /* --- Блокировки ------------------------------------------------------ */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        auto *note = new QLabel(tr(
            "A block bites where the relay actually sees a key: the key cannot "
            "claim a handle, be found by one, or keep anything in the blob "
            "store. It does not stop whoever holds it from joining a room - on "
            "an ordinary connection the relay never sees an identity key, and "
            "that is a property of the design rather than something missing."));
        note->setWordWrap(true);
        v->addWidget(note);

        m_blocks = makeTable({ tr("Key fingerprint"), tr("Handle"), tr("Reason"),
                               tr("Blocked at") });
        v->addWidget(m_blocks, 1);

        auto *row = new QHBoxLayout;
        auto *add = new QPushButton(tr("Block by key..."));
        auto *rm  = new QPushButton(tr("Unblock"));
        connect(add, &QPushButton::clicked, this, &AdminWindow::blockByFingerprint);
        connect(rm,  &QPushButton::clicked, this, &AdminWindow::unblockSelected);
        row->addWidget(add);
        row->addWidget(rm);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Blocked keys"));
    }

    /* --- Сейчас в сети ---------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        m_serverState = new QLabel;
        m_serverState->setWordWrap(true);
        v->addWidget(m_serverState);

        m_sessions = makeTable({ tr("Name"), tr("Room"), tr("Address"),
                                 tr("Since"), tr("Media") });
        v->addWidget(m_sessions, 1);
        tabs->addTab(page, tr("Connected now"));
    }

    /* --- Сводка ----------------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        m_overview = new QLabel;
        m_overview->setWordWrap(true);
        m_overview->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->addWidget(m_overview);
        v->addStretch(1);

        auto *row = new QHBoxLayout;
        auto *vac = new QPushButton(tr("Compact database (VACUUM)"));
        connect(vac, &QPushButton::clicked, this, &AdminWindow::compactDatabase);
        row->addWidget(vac);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Overview"));
    }

    statusBar()->showMessage(tr("no database open"));
}

bool AdminWindow::openDatabase(const QString &path) {
    QString err;
    if (!m_db.open(path, &err)) {
        showError(tr("Could not open the database"), err);
        return false;
    }
    statusBar()->showMessage(path);
    refreshAll();
    return true;
}

void AdminWindow::chooseDatabase() {
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Relay database"), QString(),
        tr("SQLite (*.sqlite *.db);;All files (*)"));
    if (!path.isEmpty()) openDatabase(path);
}

void AdminWindow::refreshAll() {
    if (!m_db.isOpen()) return;
    fillHandles();
    fillBlobs();
    fillBlocked();
    refreshSessions();
    fillOverview();
}

void AdminWindow::fillHandles() {
    QString err;
    const auto rows = m_db.handles(&err);
    if (!err.isEmpty()) { showError(tr("Could not read the handles"), err); return; }

    const QString needle = m_filter ? m_filter->text().trimmed() : QString();

    m_handles->setSortingEnabled(false);
    m_handles->setRowCount(0);
    for (const HandleRow &r : rows) {
        const QString fp = ServerDb::fingerprint(r.pk);
        if (!needle.isEmpty() &&
            !r.handle.contains(needle, Qt::CaseInsensitive) &&
            !fp.contains(needle, Qt::CaseInsensitive)) {
            continue;
        }
        const int row = m_handles->rowCount();
        m_handles->insertRow(row);
        m_handles->setItem(row, 0, keyedItem(r.handle, r.pk));
        m_handles->setItem(row, 1, new QTableWidgetItem(fp));
        m_handles->setItem(row, 2, new QTableWidgetItem(whenText(r.claimedAt)));
        m_handles->setItem(row, 3, new QTableWidgetItem(QString::number(r.blobCount)));
        m_handles->setItem(row, 4, new QTableWidgetItem(
            r.blocked ? tr("blocked") : QString()));
    }
    m_handles->setSortingEnabled(true);
    m_handles->resizeColumnsToContents();
}

void AdminWindow::fillBlobs() {
    QString err;
    const auto rows = m_db.blobs(&err);
    if (!err.isEmpty()) { showError(tr("Could not read the blobs"), err); return; }

    m_blobs->setSortingEnabled(false);
    m_blobs->setRowCount(0);
    for (const BlobRow &r : rows) {
        const int row = m_blobs->rowCount();
        m_blobs->insertRow(row);
        auto *first = keyedItem(ServerDb::fingerprint(r.pk), r.pk);
        /* Тип нужен вместе с ключом: пара из них и есть первичный ключ. */
        first->setData(Qt::UserRole + 1, r.type);
        m_blobs->setItem(row, 0, first);
        m_blobs->setItem(row, 1, new QTableWidgetItem(r.handle));
        m_blobs->setItem(row, 2, new QTableWidgetItem(r.type));
        m_blobs->setItem(row, 3, new QTableWidgetItem(humanBytes(r.size)));
        m_blobs->setItem(row, 4, new QTableWidgetItem(whenText(r.updatedAt)));
    }
    m_blobs->setSortingEnabled(true);
    m_blobs->resizeColumnsToContents();
}

void AdminWindow::fillBlocked() {
    QString err;
    const auto rows = m_db.blocked(&err);
    if (!err.isEmpty()) { showError(tr("Could not read the blocked keys"), err); return; }

    m_blocks->setSortingEnabled(false);
    m_blocks->setRowCount(0);
    for (const BlockRow &r : rows) {
        const int row = m_blocks->rowCount();
        m_blocks->insertRow(row);
        m_blocks->setItem(row, 0, keyedItem(ServerDb::fingerprint(r.pk), r.pk));
        m_blocks->setItem(row, 1, new QTableWidgetItem(r.handle));
        m_blocks->setItem(row, 2, new QTableWidgetItem(r.reason));
        m_blocks->setItem(row, 3, new QTableWidgetItem(whenText(r.blockedAt)));
    }
    m_blocks->setSortingEnabled(true);
    m_blocks->resizeColumnsToContents();
}

void AdminWindow::refreshSessions() {
    if (!m_db.isOpen()) return;

    const ServerState st = m_db.state();
    if (!st.known) {
        m_serverState->setText(tr(
            "The relay has never run against this database, or it ran a build "
            "that does not yet keep a list of connections."));
    } else if (st.alive()) {
        m_serverState->setText(tr("The relay is running (pid %1), started %2.")
                                   .arg(st.pid)
                                   .arg(whenText(st.startedAt)));
    } else {
        m_serverState->setText(tr(
            "The relay is not answering: last heartbeat %1. The rows below are "
            "left over from an earlier run and describe nobody.")
                                   .arg(whenText(st.heartbeatAt)));
    }

    const auto rows = m_db.sessions();
    m_sessions->setSortingEnabled(false);
    m_sessions->setRowCount(0);
    for (const SessionRow &r : rows) {
        const int row = m_sessions->rowCount();
        m_sessions->insertRow(row);
        m_sessions->setItem(row, 0, new QTableWidgetItem(r.name));
        m_sessions->setItem(row, 1, new QTableWidgetItem(r.room));
        m_sessions->setItem(row, 2, new QTableWidgetItem(r.addr));
        m_sessions->setItem(row, 3, new QTableWidgetItem(whenText(r.connectedAt)));
        m_sessions->setItem(row, 4, new QTableWidgetItem(r.isMedia ? tr("yes") : QString()));
    }
    m_sessions->setSortingEnabled(true);
    m_sessions->resizeColumnsToContents();
}

/**
 * Строка про ящик для сводки.
 *
 * Показываем счётчики и действующую политику - её сервер записывает в базу
 * сам, так что администратор видит, что на самом деле настроено, а не то,
 * что он помнит про строку запуска.
 */
QString AdminWindow::inboxLine() const {
    const InboxStats st = m_db.inbox();
    if (st.ttlSeconds < 0) {
        return tr("this relay does not report an inbox (older build)");
    }
    if (st.ttlSeconds == 0) {
        return st.items > 0
            ? tr("storage is off, %1 leftover item(s) still to be swept")
                  .arg(st.items)
            : tr("storage is off - nothing is kept");
    }
    return tr("%1 item(s), %2, for %3 mailbox(es); kept up to %4 days")
        .arg(st.items)
        .arg(humanBytes(st.bytes))
        .arg(st.addresses)
        .arg(st.ttlSeconds / 86400.0, 0, 'g', 3);
}

void AdminWindow::fillOverview() {
    const auto handles = m_db.handles();
    const auto blobs   = m_db.blobs();
    const auto blocks  = m_db.blocked();

    qint64 blobBytes = 0;
    for (const BlobRow &b : blobs) blobBytes += b.size;

    QDateTime oldest, newest;
    for (const HandleRow &h : handles) {
        if (!h.claimedAt.isValid()) continue;
        if (!oldest.isValid() || h.claimedAt < oldest) oldest = h.claimedAt;
        if (!newest.isValid() || h.claimedAt > newest) newest = h.claimedAt;
    }

    m_overview->setText(tr(
        "<b>File:</b> %1<br>"
        "<b>On disk:</b> %2 (including the WAL journal)<br><br>"
        "<b>Handles claimed:</b> %3<br>"
        "<b>Oldest:</b> %4<br>"
        "<b>Newest:</b> %5<br><br>"
        "<b>Blobs:</b> %6, %7 in total<br>"
        "<b>Blocked keys:</b> %8<br><br>"
        "<b>Offline inbox:</b> %9<br><br>"
        "Delivered messages are not here: the relay forwards them live and "
        "keeps neither bodies nor who wrote to whom. What it may hold is "
        "undelivered mail - sealed by the sender, addressed to a blind label "
        "rather than to anyone's key, deleted the moment it is collected, and "
        "only when the operator enabled it. Beyond that: claimed handles with "
        "their public keys, and blobs the client encrypted itself.")
        .arg(m_db.path())
        .arg(humanBytes(m_db.fileBytes()))
        .arg(handles.size())
        .arg(whenText(oldest))
        .arg(whenText(newest))
        .arg(blobs.size())
        .arg(humanBytes(blobBytes))
        .arg(blocks.size())
        .arg(inboxLine()));
}

QList<QByteArray> AdminWindow::selectedKeys(QTableWidget *table) const {
    QList<QByteArray> keys;
    const auto ranges = table->selectedRanges();
    for (const QTableWidgetSelectionRange &range : ranges) {
        for (int row = range.topRow(); row <= range.bottomRow(); ++row) {
            QTableWidgetItem *item = table->item(row, 0);
            if (item) keys.append(item->data(Qt::UserRole).toByteArray());
        }
    }
    return keys;
}

void AdminWindow::deleteSelectedHandles() {
    QStringList names;
    const auto ranges = m_handles->selectedRanges();
    for (const QTableWidgetSelectionRange &range : ranges) {
        for (int row = range.topRow(); row <= range.bottomRow(); ++row) {
            if (QTableWidgetItem *item = m_handles->item(row, 0)) names << item->text();
        }
    }
    if (names.isEmpty()) return;

    /* Освободить имя - это не то же самое, что удалить пользователя: имя
     * тут же может занять кто угодно другой, и собеседники увидят прежний
     * @ник за новым ключом. Сказать об этом до, а не после. */
    const auto answer = QMessageBox::warning(
        this, tr("Release handles"),
        tr("These handles will be released: %1.\n\n"
           "A handle can be claimed by another key straight away, and contacts "
           "will see the familiar @handle behind a different key. The owner's "
           "key is not touched - it keeps working, just without a handle.\n\n"
           "Go ahead?").arg(names.join(QStringLiteral(", "))),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    for (const QString &name : names) {
        QString err;
        if (!m_db.deleteHandle(name, &err)) {
            showError(tr("Could not release the handle %1").arg(name), err);
            break;
        }
    }
    refreshAll();
}

void AdminWindow::blockSelectedHandles() {
    const auto keys = selectedKeys(m_handles);
    if (keys.isEmpty()) return;

    bool ok = false;
    const QString reason = QInputDialog::getText(
        this, tr("Block key"),
        tr("Reason (stays in this database only):"), QLineEdit::Normal,
        QString(), &ok);
    if (!ok) return;

    for (const QByteArray &pk : keys) {
        QString err;
        if (!m_db.blockKey(pk, reason, &err)) {
            showError(tr("Could not block the key"), err);
            break;
        }
    }
    refreshAll();
}

void AdminWindow::deleteSelectedBlobs() {
    QList<QPair<QByteArray, QString>> targets;
    const auto ranges = m_blobs->selectedRanges();
    for (const QTableWidgetSelectionRange &range : ranges) {
        for (int row = range.topRow(); row <= range.bottomRow(); ++row) {
            QTableWidgetItem *item = m_blobs->item(row, 0);
            if (!item) continue;
            targets.append({ item->data(Qt::UserRole).toByteArray(),
                             item->data(Qt::UserRole + 1).toString() });
        }
    }
    if (targets.isEmpty()) return;

    const auto answer = QMessageBox::warning(
        this, tr("Delete blobs"),
        tr("%1 record(s) will be deleted.\n\n"
           "This is the user's data, not the server's: the contact list the "
           "client keeps here encrypted. The server cannot restore it - only "
           "the client can, and only from a local copy.\n\n"
           "Go ahead?").arg(targets.size()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    for (const auto &t : targets) {
        QString err;
        if (!m_db.deleteBlob(t.first, t.second, &err)) {
            showError(tr("Could not delete the blob"), err);
            break;
        }
    }
    refreshAll();
}

void AdminWindow::unblockSelected() {
    const auto keys = selectedKeys(m_blocks);
    for (const QByteArray &pk : keys) {
        QString err;
        if (!m_db.unblockKey(pk, &err)) {
            showError(tr("Could not unblock the key"), err);
            break;
        }
    }
    refreshAll();
}

void AdminWindow::blockByFingerprint() {
    bool ok = false;
    const QString b64 = QInputDialog::getText(
        this, tr("Block key"),
        tr("Public key in base64url (no padding), 32 bytes:"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || b64.trimmed().isEmpty()) return;

    const QByteArray pk = QByteArray::fromBase64(
        b64.trimmed().toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    if (pk.size() != 32) {
        showError(tr("That does not look like a key"),
                  tr("Got %1 bytes instead of 32. The key is expected in the "
                     "form the client shows it - base64url without "
                     "padding.").arg(pk.size()));
        return;
    }

    const QString reason = QInputDialog::getText(
        this, tr("Block key"), tr("Reason:"), QLineEdit::Normal,
        QString(), &ok);
    if (!ok) return;

    QString err;
    if (!m_db.blockKey(pk, reason, &err)) {
        showError(tr("Could not block the key"), err);
        return;
    }
    refreshAll();
}

void AdminWindow::exportHandles() {
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Export the list"), QStringLiteral("handles.csv"),
        tr("CSV (*.csv);;JSON (*.json)"));
    if (path.isEmpty()) return;

    const auto rows = m_db.handles();
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        showError(tr("Could not write the file"), f.errorString());
        return;
    }

    if (path.endsWith(QLatin1String(".json"), Qt::CaseInsensitive)) {
        QJsonArray arr;
        for (const HandleRow &r : rows) {
            QJsonObject o;
            o["handle"] = r.handle;
            o["fingerprint"] = ServerDb::fingerprint(r.pk);
            o["identity_pk"] = QString::fromLatin1(
                r.pk.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
            o["claimed_at"] = r.claimedAt.isValid() ? r.claimedAt.toString(Qt::ISODate) : QString();
            o["blobs"] = r.blobCount;
            o["blocked"] = r.blocked;
            arr.append(o);
        }
        f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    } else {
        QTextStream out(&f);
        out << "handle,fingerprint,identity_pk,claimed_at,blobs,blocked\n";
        for (const HandleRow &r : rows) {
            /* Имя проходит проверку сервера и запятых содержать не может, но
             * кавычки всё равно ставим: файл потом откроют в чём угодно. */
            out << '"' << r.handle << "\","
                << ServerDb::fingerprint(r.pk) << ','
                << QString::fromLatin1(r.pk.toBase64(
                       QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)) << ','
                << (r.claimedAt.isValid() ? r.claimedAt.toString(Qt::ISODate) : QString()) << ','
                << r.blobCount << ','
                << (r.blocked ? "yes" : "no") << '\n';
        }
    }
    f.close();
    statusBar()->showMessage(tr("%1 record(s) exported").arg(rows.size()), 5000);
}

void AdminWindow::compactDatabase() {
    const auto answer = QMessageBox::question(
        this, tr("Compact the database"),
        tr("VACUUM rewrites the whole file. That is safe against a running "
           "relay, but while it writes, everything else waits on the "
           "database.\n\n"
           "Go ahead?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    const qint64 before = m_db.fileBytes();
    QString err;
    if (!m_db.vacuum(&err)) {
        showError(tr("Could not compact the database"), err);
        return;
    }
    fillOverview();
    statusBar()->showMessage(
        tr("was %1, now %2").arg(humanBytes(before), humanBytes(m_db.fileBytes())), 8000);
}

void AdminWindow::showError(const QString &what, const QString &detail) {
    QMessageBox::critical(this, what, detail.isEmpty() ? what : detail);
}
