#include "serverdb.h"

#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

extern "C" {
#include "identity.h"
}

bool ServerState::alive() const {
    if (!known || !heartbeatAt.isValid()) return false;
    /* Три пропущенных удара - это уже не задержка планировщика, а
     * остановленный процесс. Период берётся из базы: своё число здесь
     * однажды разошлось бы с серверным и объявило бы живой сервер мёртвым. */
    const qint64 silent = heartbeatAt.secsTo(QDateTime::currentDateTime());
    return silent < 3LL * qMax(1, heartbeatPeriod);
}

ServerDb::~ServerDb() { close(); }

bool ServerDb::open(const QString &path, QString *error) {
    close();

    m_conn = QStringLiteral("fear-admin-%1").arg((quintptr)this, 0, 16);
    m_db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_conn);
    m_db.setDatabaseName(path);
    /* Открываем как обычную (не read-only) базу: удаление и блокировка -
     * это записи. Журнал не трогаем - режимом владеет сервер. */
    if (!m_db.open()) {
        if (error) *error = m_db.lastError().text();
        close();
        return false;
    }

    QSqlQuery q(m_db);
    /* Сервер пишет короткими транзакциями, так что ждать почти никогда не
     * приходится, но три секунды - разница между «занято» и потерянным
     * действием администратора. */
    q.exec(QStringLiteral("PRAGMA busy_timeout=3000"));

    if (!q.exec(QStringLiteral("SELECT 1 FROM handles LIMIT 1"))) {
        if (error) {
            *error = QObject::tr("это не похоже на базу ретранслятора: %1")
                         .arg(q.lastError().text());
        }
        close();
        return false;
    }

    m_path = path;
    return true;
}

void ServerDb::close() {
    if (m_db.isOpen()) m_db.close();
    m_db = QSqlDatabase();
    if (!m_conn.isEmpty()) {
        QSqlDatabase::removeDatabase(m_conn);
        m_conn.clear();
    }
    m_path.clear();
}

QString ServerDb::fingerprint(const QByteArray &pk) {
    if (pk.size() != IDENTITY_PK_BYTES) return QStringLiteral("(ключ не 32 байта)");
    char buf[IDENTITY_FINGERPRINT_LEN];
    identity_pk_fingerprint(reinterpret_cast<const uint8_t *>(pk.constData()), buf);
    return QString::fromLatin1(buf);
}

static QDateTime fromUnix(const QVariant &v) {
    return v.isNull() ? QDateTime() : QDateTime::fromSecsSinceEpoch(v.toLongLong());
}

QList<HandleRow> ServerDb::handles(QString *error) const {
    QList<HandleRow> out;
    if (!isOpen()) return out;

    QSqlQuery q(m_db);
    /* Один запрос вместо запроса на строку: считать блобы и блокировку
     * отдельно для каждого имени - это N+1 обращений там, где хватает
     * одного соединения. */
    const bool ok = q.exec(QStringLiteral(
        "SELECT h.handle, h.identity_pk, h.claimed_at,"
        "       (SELECT COUNT(*) FROM user_blobs b WHERE b.identity_pk = h.identity_pk),"
        "       (SELECT COUNT(*) FROM blocked_keys k WHERE k.identity_pk = h.identity_pk)"
        "  FROM handles h ORDER BY h.handle"));
    if (!ok) {
        if (error) *error = q.lastError().text();
        return out;
    }
    while (q.next()) {
        HandleRow r;
        r.handle    = q.value(0).toString();
        r.pk        = q.value(1).toByteArray();
        r.claimedAt = fromUnix(q.value(2));
        r.blobCount = q.value(3).toInt();
        r.blocked   = q.value(4).toInt() > 0;
        out.append(r);
    }
    return out;
}

QList<BlobRow> ServerDb::blobs(QString *error) const {
    QList<BlobRow> out;
    if (!isOpen()) return out;

    QSqlQuery q(m_db);
    const bool ok = q.exec(QStringLiteral(
        "SELECT b.identity_pk, b.blob_type, length(b.ciphertext), b.updated_at,"
        "       (SELECT h.handle FROM handles h WHERE h.identity_pk = b.identity_pk)"
        "  FROM user_blobs b ORDER BY b.updated_at DESC"));
    if (!ok) {
        if (error) *error = q.lastError().text();
        return out;
    }
    while (q.next()) {
        BlobRow r;
        r.pk        = q.value(0).toByteArray();
        r.type      = q.value(1).toString();
        r.size      = q.value(2).toLongLong();
        r.updatedAt = fromUnix(q.value(3));
        r.handle    = q.value(4).toString();
        out.append(r);
    }
    return out;
}

QList<BlockRow> ServerDb::blocked(QString *error) const {
    QList<BlockRow> out;
    if (!isOpen()) return out;

    QSqlQuery q(m_db);
    const bool ok = q.exec(QStringLiteral(
        "SELECT k.identity_pk, k.reason, k.blocked_at,"
        "       (SELECT h.handle FROM handles h WHERE h.identity_pk = k.identity_pk)"
        "  FROM blocked_keys k ORDER BY k.blocked_at DESC"));
    if (!ok) {
        if (error) *error = q.lastError().text();
        return out;
    }
    while (q.next()) {
        BlockRow r;
        r.pk        = q.value(0).toByteArray();
        r.reason    = q.value(1).toString();
        r.blockedAt = fromUnix(q.value(2));
        r.handle    = q.value(3).toString();
        out.append(r);
    }
    return out;
}

QList<SessionRow> ServerDb::sessions(QString *error) const {
    QList<SessionRow> out;
    if (!isOpen()) return out;

    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral(
            "SELECT fd, name, room, addr, is_media, connected_at"
            "  FROM live_sessions ORDER BY room, name"))) {
        if (error) *error = q.lastError().text();
        return out;
    }
    while (q.next()) {
        SessionRow r;
        r.fd          = q.value(0).toInt();
        r.name        = q.value(1).toString();
        r.room        = q.value(2).toString();
        r.addr        = q.value(3).toString();
        r.isMedia     = q.value(4).toInt() != 0;
        r.connectedAt = fromUnix(q.value(5));
        out.append(r);
    }
    return out;
}

ServerState ServerDb::state() const {
    ServerState s;
    if (!isOpen()) return s;

    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("SELECT key, value FROM server_state"))) return s;
    while (q.next()) {
        const QString k = q.value(0).toString();
        const QString v = q.value(1).toString();
        if (k == QLatin1String("pid"))          { s.pid = v.toLongLong(); s.known = true; }
        else if (k == QLatin1String("started_at"))   s.startedAt   = QDateTime::fromSecsSinceEpoch(v.toLongLong());
        else if (k == QLatin1String("heartbeat_at")) s.heartbeatAt = QDateTime::fromSecsSinceEpoch(v.toLongLong());
        else if (k == QLatin1String("heartbeat_period")) s.heartbeatPeriod = v.toInt();
    }
    return s;
}

bool ServerDb::deleteHandle(const QString &handle, QString *error) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("DELETE FROM handles WHERE handle = ?"));
    q.addBindValue(handle);
    if (!q.exec()) {
        if (error) *error = q.lastError().text();
        return false;
    }
    return true;
}

bool ServerDb::deleteBlob(const QByteArray &pk, const QString &type, QString *error) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "DELETE FROM user_blobs WHERE identity_pk = ? AND blob_type = ?"));
    q.addBindValue(pk);
    q.addBindValue(type);
    if (!q.exec()) {
        if (error) *error = q.lastError().text();
        return false;
    }
    return true;
}

bool ServerDb::blockKey(const QByteArray &pk, const QString &reason, QString *error) {
    if (pk.size() != IDENTITY_PK_BYTES) {
        if (error) *error = QObject::tr("ключ должен быть длиной 32 байта");
        return false;
    }
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO blocked_keys(identity_pk, reason, blocked_at)"
        " VALUES (?, ?, ?)"));
    q.addBindValue(pk);
    q.addBindValue(reason.isEmpty() ? QVariant(QMetaType(QMetaType::QString)) : QVariant(reason));
    q.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!q.exec()) {
        if (error) *error = q.lastError().text();
        return false;
    }
    return true;
}

bool ServerDb::unblockKey(const QByteArray &pk, QString *error) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("DELETE FROM blocked_keys WHERE identity_pk = ?"));
    q.addBindValue(pk);
    if (!q.exec()) {
        if (error) *error = q.lastError().text();
        return false;
    }
    return true;
}

bool ServerDb::vacuum(QString *error) {
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("VACUUM"))) {
        if (error) *error = q.lastError().text();
        return false;
    }
    return true;
}

qint64 ServerDb::fileBytes() const {
    if (m_path.isEmpty()) return 0;
    qint64 total = QFileInfo(m_path).size();
    /* Журнал WAL - тоже часть занятого места, и в работающем сервере он
     * бывает больше самой базы. */
    for (const char *suffix : { "-wal", "-shm" }) {
        QFileInfo fi(m_path + QLatin1String(suffix));
        if (fi.exists()) total += fi.size();
    }
    return total;
}
