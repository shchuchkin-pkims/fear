#ifndef FEAR_HISTORY_H
#define FEAR_HISTORY_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QSqlDatabase>
#include "widgets/chatarea.h"   // for fear::Message struct

namespace fear {

/**
 * Local-only message store backed by a SQLite file in the GUI config dir.
 * Persists every text message the user sees so chat history survives
 * disconnect / app restart (Phase A §9a — see doc/architecture-decisions.md).
 *
 * Singleton-style by convention: one instance lives off ChatWindow. Schema
 * is created on first open if missing.
 *
 * Schema v1: messages(roomId TEXT, senderName TEXT, text TEXT, ts INTEGER,
 *                     fromSelf INTEGER, isSystem INTEGER)
 *           INDEX (roomId, ts)
 */
class History : public QObject {
    Q_OBJECT
public:
    explicit History(QObject *parent = nullptr);
    ~History() override;

    /** True iff the SQLite file opened cleanly. */
    bool isOpen() const { return m_open; }

    /** Append a single message. Returns true on success. */
    bool insert(const QString &roomId, const QString &sender,
                const QString &text, qint64 tsUnixMs,
                bool fromSelf, bool isSystem);

    /** Newest `limit` messages for `roomId`, oldest-first for chronological UI. */
    QVector<Message> loadRecent(const QString &roomId, int limit = 500);

    /** Drop all messages for `roomId`. */
    bool clearRoom(const QString &roomId);

    /** Drop the entire history table. */
    bool clearAll();

    /** One row of a search result (parallel to MessageEntity on Android). */
    struct SearchHit {
        QString roomId;
        QString sender;
        QString text;
        qint64  ts;        // unix millis
        bool    fromSelf;
    };

    /** Case-insensitive substring search (LIKE %needle%). */
    QVector<SearchHit> search(const QString &needle, int limit = 200);

    /** One distinct room id with the timestamp of its newest message. */
    struct RoomSummary {
        QString roomId;
        qint64  lastTs;        // unix millis
    };

    /** All rooms we have any history for, newest first. Used to populate
     *  the unified chat list (Phase B-5) so a room the user has visited
     *  stays in the sidebar even after they switch away. */
    QVector<RoomSummary> allRoomSummaries();

private:
    QSqlDatabase m_db;
    bool m_open = false;

    bool ensureSchema();
};

}  // namespace fear

#endif
