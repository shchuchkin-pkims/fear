/**
 * @file serverdb.h
 * @brief Чтение и правка базы ретранслятора, пока он работает.
 *
 * Утилита открывает тот же файл SQLite, что и сервер, а не копию: править
 * копию живой базы значит однажды потерять запись, сделанную в тот же
 * момент. Сервер держит базу в режиме WAL, так что читатель ему не мешает,
 * а короткие записи отсюда ждут своей очереди по busy_timeout.
 *
 * Того, что здесь нет, стоит сказать вслух: переписки. Ретранслятор
 * пересылает сообщения на лету и не хранит их - ни тела, ни того, кто кому
 * писал. В базе лежат только занятые имена с открытыми ключами и
 * зашифрованные клиентом блобы, содержимое которых сервер прочитать не
 * может.
 */
#ifndef FEAR_ADMIN_SERVERDB_H
#define FEAR_ADMIN_SERVERDB_H

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QSqlDatabase>
#include <QString>

/** Занятое имя. */
struct HandleRow {
    QString    handle;
    QByteArray pk;
    QDateTime  claimedAt;
    int        blobCount = 0;
    bool       blocked   = false;
};

/** Зашифрованный блоб. Содержимое утилите недоступно - только метаданные. */
struct BlobRow {
    QByteArray pk;
    QString    handle;      ///< если у ключа есть имя
    QString    type;
    qint64     size = 0;
    QDateTime  updatedAt;
};

/** Заблокированный ключ. */
struct BlockRow {
    QByteArray pk;
    QString    handle;
    QString    reason;
    QDateTime  blockedAt;
};

/** Подключение, о котором сервер сообщил, что оно живо. */
struct SessionRow {
    int       fd = 0;
    QString   name;
    QString   room;
    QString   addr;
    bool      isMedia = false;
    QDateTime connectedAt;
};

/** Сводка по офлайн-ящику. Содержимое писем недоступно - только счётчики. */
struct InboxStats {
    qint64 items = 0;
    qint64 bytes = 0;
    qint64 addresses = 0;
    /** Срок хранения в секундах; 0 - оператор выключил хранение, -1 - сервер
     *  старой сборки и о ящике ничего не сообщает. */
    qint64 ttlSeconds = -1;
};

/** Что сервер сообщает о себе. */
struct ServerState {
    bool      known = false;   ///< есть ли вообще запись
    qint64    pid = 0;
    int       heartbeatPeriod = 10;  ///< как часто сервер отмечается, из базы
    QDateTime startedAt;
    QDateTime heartbeatAt;
    /** Живым считаем, пока биение свежее: период сервер сообщает сам. */
    bool alive() const;
};

class ServerDb {
public:
    ~ServerDb();

    bool open(const QString &path, QString *error);
    void close();
    bool isOpen() const { return m_db.isValid() && m_db.isOpen(); }
    QString path() const { return m_path; }

    QList<HandleRow>  handles(QString *error = nullptr) const;
    QList<BlobRow>    blobs(QString *error = nullptr) const;
    QList<BlockRow>   blocked(QString *error = nullptr) const;
    QList<SessionRow> sessions(QString *error = nullptr) const;
    ServerState       state() const;
    InboxStats        inbox() const;

    bool deleteHandle(const QString &handle, QString *error);
    bool deleteBlob(const QByteArray &pk, const QString &type, QString *error);
    bool blockKey(const QByteArray &pk, const QString &reason, QString *error);
    bool unblockKey(const QByteArray &pk, QString *error);
    bool vacuum(QString *error);

    qint64 fileBytes() const;

    /** Отпечаток, как его показывают клиенты: BLAKE2b(pk), первые 8 байт. */
    static QString fingerprint(const QByteArray &pk);

private:
    QSqlDatabase m_db;
    QString      m_path;
    QString      m_conn;
};

#endif
