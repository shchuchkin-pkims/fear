#include "history.h"

#include <QDir>
#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QDebug>
#include <QDateTime>

namespace fear {

History::History(QObject *parent) : QObject(parent) {
    // Pick a stable per-user path. Works on Linux (~/.local/share/fear/), macOS,
    // Windows (AppData/Roaming/fear/). QStandardPaths handles the OS detail.
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + "/.fear";
    QDir().mkpath(dir);

    const QString dbPath = dir + "/history.sqlite";

    // Use a unique connection name so multiple Backend instances (tests, etc.)
    // don't clobber each other.
    m_db = QSqlDatabase::addDatabase("QSQLITE", QStringLiteral("fear_history"));
    m_db.setDatabaseName(dbPath);

    if (!m_db.open()) {
        qWarning() << "History: cannot open" << dbPath << ":" << m_db.lastError().text();
        return;
    }
    if (!ensureSchema()) {
        qWarning() << "History: schema setup failed:" << m_db.lastError().text();
        m_db.close();
        return;
    }
    m_open = true;
}

History::~History() {
    if (m_db.isOpen()) m_db.close();
    QSqlDatabase::removeDatabase(QStringLiteral("fear_history"));
}

bool History::ensureSchema() {
    QSqlQuery q(m_db);
    if (!q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  roomId   TEXT    NOT NULL,"
        "  sender   TEXT    NOT NULL,"
        "  text     TEXT    NOT NULL,"
        "  ts       INTEGER NOT NULL,"   // unix millis
        "  fromSelf INTEGER NOT NULL DEFAULT 0,"
        "  isSystem INTEGER NOT NULL DEFAULT 0"
        ")")) return false;
    if (!q.exec("CREATE INDEX IF NOT EXISTS idx_messages_room_ts "
                "ON messages(roomId, ts)")) return false;
    return true;
}

bool History::insert(const QString &roomId, const QString &sender,
                     const QString &text, qint64 tsUnixMs,
                     bool fromSelf, bool isSystem) {
    if (!m_open) return false;
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO messages (roomId, sender, text, ts, fromSelf, isSystem) "
              "VALUES (?, ?, ?, ?, ?, ?)");
    q.addBindValue(roomId);
    q.addBindValue(sender);
    q.addBindValue(text);
    q.addBindValue(tsUnixMs);
    q.addBindValue(fromSelf ? 1 : 0);
    q.addBindValue(isSystem ? 1 : 0);
    if (!q.exec()) {
        qWarning() << "History::insert failed:" << q.lastError().text();
        return false;
    }
    return true;
}

QVector<Message> History::loadRecent(const QString &roomId, int limit) {
    QVector<Message> out;
    if (!m_open) return out;

    QSqlQuery q(m_db);
    q.prepare("SELECT sender, text, ts, fromSelf FROM messages "
              "WHERE roomId = ? ORDER BY ts ASC LIMIT ?");
    q.addBindValue(roomId);
    q.addBindValue(limit);
    if (!q.exec()) {
        qWarning() << "History::loadRecent failed:" << q.lastError().text();
        return out;
    }
    out.reserve(q.size() > 0 ? q.size() : 64);
    while (q.next()) {
        Message m;
        m.sender    = q.value(0).toString();
        m.text      = q.value(1).toString();
        m.timestamp = QDateTime::fromMSecsSinceEpoch(q.value(2).toLongLong());
        m.fromSelf  = q.value(3).toBool();
        m.delivered = true;
        out.append(m);
    }
    return out;
}

bool History::clearRoom(const QString &roomId) {
    if (!m_open) return false;
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM messages WHERE roomId = ?");
    q.addBindValue(roomId);
    return q.exec();
}

bool History::clearAll() {
    if (!m_open) return false;
    QSqlQuery q(m_db);
    return q.exec("DELETE FROM messages");
}

QVector<History::SearchHit> History::search(const QString &needle, int limit) {
    QVector<SearchHit> out;
    if (!m_open || needle.isEmpty()) return out;

    QSqlQuery q(m_db);
    q.prepare("SELECT roomId, sender, text, ts, fromSelf FROM messages "
              "WHERE text LIKE ? ESCAPE '\\' "
              "ORDER BY ts DESC LIMIT ?");
    // Escape SQL LIKE wildcards in user input (% _ \) so "50%" doesn't match
    // everything containing "50".
    QString escaped = needle;
    escaped.replace('\\', QStringLiteral("\\\\"))
           .replace('%',  QStringLiteral("\\%"))
           .replace('_',  QStringLiteral("\\_"));
    q.addBindValue("%" + escaped + "%");
    q.addBindValue(limit);
    if (!q.exec()) {
        qWarning() << "History::search failed:" << q.lastError().text();
        return out;
    }
    while (q.next()) {
        out.append(SearchHit{
            q.value(0).toString(),
            q.value(1).toString(),
            q.value(2).toString(),
            q.value(3).toLongLong(),
            q.value(4).toBool(),
        });
    }
    return out;
}

QVector<History::RoomSummary> History::allRoomSummaries() {
    QVector<RoomSummary> out;
    if (!m_open) return out;
    QSqlQuery q(m_db);
    if (!q.exec("SELECT roomId, MAX(ts) AS lastTs FROM messages "
                "GROUP BY roomId ORDER BY lastTs DESC")) {
        qWarning() << "History::allRoomSummaries failed:" << q.lastError().text();
        return out;
    }
    while (q.next()) {
        out.append(RoomSummary{ q.value(0).toString(), q.value(1).toLongLong() });
    }
    return out;
}

}  // namespace fear
