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
    if (n < 1024) return QObject::tr("%1 Б").arg(n);
    if (n < 1024 * 1024) return QObject::tr("%1 КБ").arg(n / 1024.0, 0, 'f', 1);
    return QObject::tr("%1 МБ").arg(n / (1024.0 * 1024.0), 0, 'f', 1);
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
    setWindowTitle(tr("F.E.A.R. - администрирование ретранслятора"));
    resize(1000, 640);

    auto *fileMenu = menuBar()->addMenu(tr("&База"));
    fileMenu->addAction(tr("&Открыть..."), this, &AdminWindow::chooseDatabase);
    fileMenu->addAction(tr("О&бновить"), this, &AdminWindow::refreshAll,
                        QKeySequence(QKeySequence::Refresh));
    fileMenu->addSeparator();
    fileMenu->addAction(tr("&Выход"), qApp, &QApplication::quit);

    auto *tabs = new QTabWidget;
    setCentralWidget(tabs);

    /* --- Пользователи --------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);

        auto *top = new QHBoxLayout;
        m_filter = new QLineEdit;
        m_filter->setPlaceholderText(tr("поиск по имени или отпечатку"));
        connect(m_filter, &QLineEdit::textChanged, this, [this] { fillHandles(); });
        top->addWidget(new QLabel(tr("Найти:")));
        top->addWidget(m_filter, 1);
        v->addLayout(top);

        m_handles = makeTable({ tr("Имя"), tr("Отпечаток ключа"), tr("Зарегистрировано"),
                                tr("Блобов"), tr("Блокировка") });
        v->addWidget(m_handles, 1);

        auto *row = new QHBoxLayout;
        auto *del = new QPushButton(tr("Удалить имя"));
        auto *blk = new QPushButton(tr("Заблокировать ключ"));
        auto *exp = new QPushButton(tr("Экспорт..."));
        connect(del, &QPushButton::clicked, this, &AdminWindow::deleteSelectedHandles);
        connect(blk, &QPushButton::clicked, this, &AdminWindow::blockSelectedHandles);
        connect(exp, &QPushButton::clicked, this, &AdminWindow::exportHandles);
        row->addWidget(del);
        row->addWidget(blk);
        row->addStretch(1);
        row->addWidget(exp);
        v->addLayout(row);

        tabs->addTab(page, tr("Пользователи"));
    }

    /* --- Блобы ----------------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        v->addWidget(new QLabel(tr(
            "Содержимое зашифровано клиентом - ни сервер, ни эта утилита его "
            "прочитать не могут. Видны только метаданные.")));
        m_blobs = makeTable({ tr("Отпечаток ключа"), tr("Имя"), tr("Тип"),
                              tr("Размер"), tr("Обновлён") });
        v->addWidget(m_blobs, 1);

        auto *row = new QHBoxLayout;
        auto *del = new QPushButton(tr("Удалить блоб"));
        connect(del, &QPushButton::clicked, this, &AdminWindow::deleteSelectedBlobs);
        row->addWidget(del);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Блобы"));
    }

    /* --- Блокировки ------------------------------------------------------ */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        auto *note = new QLabel(tr(
            "Блокировка действует там, где сервер вообще видит ключ: имя "
            "нельзя занять, найти по ключу и хранить блобы. Войти в комнату "
            "она не мешает - при обычном подключении сервер личного ключа не "
            "видит, и это свойство самой схемы, а не недоделка."));
        note->setWordWrap(true);
        v->addWidget(note);

        m_blocks = makeTable({ tr("Отпечаток ключа"), tr("Имя"), tr("Причина"),
                               tr("Когда") });
        v->addWidget(m_blocks, 1);

        auto *row = new QHBoxLayout;
        auto *add = new QPushButton(tr("Заблокировать по ключу..."));
        auto *rm  = new QPushButton(tr("Снять блокировку"));
        connect(add, &QPushButton::clicked, this, &AdminWindow::blockByFingerprint);
        connect(rm,  &QPushButton::clicked, this, &AdminWindow::unblockSelected);
        row->addWidget(add);
        row->addWidget(rm);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Блокировки"));
    }

    /* --- Сейчас в сети ---------------------------------------------------- */
    {
        auto *page = new QWidget;
        auto *v = new QVBoxLayout(page);
        m_serverState = new QLabel;
        m_serverState->setWordWrap(true);
        v->addWidget(m_serverState);

        m_sessions = makeTable({ tr("Имя"), tr("Комната"), tr("Адрес"),
                                 tr("С"), tr("Медиа") });
        v->addWidget(m_sessions, 1);
        tabs->addTab(page, tr("Сейчас в сети"));
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
        auto *vac = new QPushButton(tr("Сжать базу (VACUUM)"));
        connect(vac, &QPushButton::clicked, this, &AdminWindow::compactDatabase);
        row->addWidget(vac);
        row->addStretch(1);
        v->addLayout(row);

        tabs->addTab(page, tr("Сводка"));
    }

    statusBar()->showMessage(tr("база не открыта"));
}

bool AdminWindow::openDatabase(const QString &path) {
    QString err;
    if (!m_db.open(path, &err)) {
        showError(tr("Не удалось открыть базу"), err);
        return false;
    }
    statusBar()->showMessage(path);
    refreshAll();
    return true;
}

void AdminWindow::chooseDatabase() {
    const QString path = QFileDialog::getOpenFileName(
        this, tr("База ретранслятора"), QString(),
        tr("SQLite (*.sqlite *.db);;Все файлы (*)"));
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
    if (!err.isEmpty()) { showError(tr("Не удалось прочитать имена"), err); return; }

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
            r.blocked ? tr("заблокирован") : QString()));
    }
    m_handles->setSortingEnabled(true);
    m_handles->resizeColumnsToContents();
}

void AdminWindow::fillBlobs() {
    QString err;
    const auto rows = m_db.blobs(&err);
    if (!err.isEmpty()) { showError(tr("Не удалось прочитать блобы"), err); return; }

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
    if (!err.isEmpty()) { showError(tr("Не удалось прочитать блокировки"), err); return; }

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
            "Сервер ни разу не запускался с этой базой, либо запускался "
            "сборкой, которая ещё не умеет вести список подключений."));
    } else if (st.alive()) {
        m_serverState->setText(tr("Сервер работает (pid %1), запущен %2.")
                                   .arg(st.pid)
                                   .arg(whenText(st.startedAt)));
    } else {
        m_serverState->setText(tr(
            "Сервер не отвечает: последнее биение %1. Строки ниже остались от "
            "прошлого запуска и никого не описывают.")
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
        m_sessions->setItem(row, 4, new QTableWidgetItem(r.isMedia ? tr("да") : QString()));
    }
    m_sessions->setSortingEnabled(true);
    m_sessions->resizeColumnsToContents();
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
        "<b>Файл:</b> %1<br>"
        "<b>Занимает:</b> %2 (вместе с журналом WAL)<br><br>"
        "<b>Занятых имён:</b> %3<br>"
        "<b>Самое старое:</b> %4<br>"
        "<b>Самое новое:</b> %5<br><br>"
        "<b>Блобов:</b> %6, суммарно %7<br>"
        "<b>Заблокированных ключей:</b> %8<br><br>"
        "Переписки в базе нет и не появится: ретранслятор пересылает "
        "сообщения на лету и не хранит ни тел, ни того, кто кому писал. "
        "Здесь только занятые имена с открытыми ключами и зашифрованные "
        "клиентом блобы.")
        .arg(m_db.path())
        .arg(humanBytes(m_db.fileBytes()))
        .arg(handles.size())
        .arg(whenText(oldest))
        .arg(whenText(newest))
        .arg(blobs.size())
        .arg(humanBytes(blobBytes))
        .arg(blocks.size()));
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
        this, tr("Освободить имена"),
        tr("Будут освобождены имена: %1.\n\n"
           "Имя сразу сможет занять другой ключ, и собеседники увидят "
           "привычный @ник за чужим ключом. Ключ владельца при этом не "
           "трогается - он продолжит работать без имени.\n\n"
           "Продолжить?").arg(names.join(QStringLiteral(", "))),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    for (const QString &name : names) {
        QString err;
        if (!m_db.deleteHandle(name, &err)) {
            showError(tr("Не удалось освободить имя %1").arg(name), err);
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
        this, tr("Заблокировать ключ"),
        tr("Причина (попадёт только в эту базу):"), QLineEdit::Normal,
        QString(), &ok);
    if (!ok) return;

    for (const QByteArray &pk : keys) {
        QString err;
        if (!m_db.blockKey(pk, reason, &err)) {
            showError(tr("Не удалось заблокировать ключ"), err);
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
        this, tr("Удалить блобы"),
        tr("Будет удалено записей: %1.\n\n"
           "Это данные пользователя, а не сервера: список контактов, который "
           "клиент хранит здесь зашифрованным. Восстановить его сервер не "
           "сможет - только сам клиент, если у него есть локальная копия.\n\n"
           "Продолжить?").arg(targets.size()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    for (const auto &t : targets) {
        QString err;
        if (!m_db.deleteBlob(t.first, t.second, &err)) {
            showError(tr("Не удалось удалить блоб"), err);
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
            showError(tr("Не удалось снять блокировку"), err);
            break;
        }
    }
    refreshAll();
}

void AdminWindow::blockByFingerprint() {
    bool ok = false;
    const QString b64 = QInputDialog::getText(
        this, tr("Заблокировать ключ"),
        tr("Открытый ключ в base64url (без выравнивания), 32 байта:"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || b64.trimmed().isEmpty()) return;

    const QByteArray pk = QByteArray::fromBase64(
        b64.trimmed().toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    if (pk.size() != 32) {
        showError(tr("Не похоже на ключ"),
                  tr("Получилось %1 байт вместо 32. Ключ ожидается в том же "
                     "виде, в каком его показывает клиент - base64url без "
                     "выравнивания.").arg(pk.size()));
        return;
    }

    const QString reason = QInputDialog::getText(
        this, tr("Заблокировать ключ"), tr("Причина:"), QLineEdit::Normal,
        QString(), &ok);
    if (!ok) return;

    QString err;
    if (!m_db.blockKey(pk, reason, &err)) {
        showError(tr("Не удалось заблокировать ключ"), err);
        return;
    }
    refreshAll();
}

void AdminWindow::exportHandles() {
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Выгрузить список"), QStringLiteral("handles.csv"),
        tr("CSV (*.csv);;JSON (*.json)"));
    if (path.isEmpty()) return;

    const auto rows = m_db.handles();
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        showError(tr("Не удалось записать файл"), f.errorString());
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
    statusBar()->showMessage(tr("выгружено записей: %1").arg(rows.size()), 5000);
}

void AdminWindow::compactDatabase() {
    const auto answer = QMessageBox::question(
        this, tr("Сжать базу"),
        tr("VACUUM переписывает файл целиком. На работающем сервере это "
           "безопасно, но пока идёт запись, обращения к базе будут ждать.\n\n"
           "Продолжить?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    const qint64 before = m_db.fileBytes();
    QString err;
    if (!m_db.vacuum(&err)) {
        showError(tr("Не удалось сжать базу"), err);
        return;
    }
    fillOverview();
    statusBar()->showMessage(
        tr("было %1, стало %2").arg(humanBytes(before), humanBytes(m_db.fileBytes())), 8000);
}

void AdminWindow::showError(const QString &what, const QString &detail) {
    QMessageBox::critical(this, what, detail.isEmpty() ? what : detail);
}
