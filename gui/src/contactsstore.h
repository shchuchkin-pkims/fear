#ifndef FEAR_CONTACTSSTORE_H
#define FEAR_CONTACTSSTORE_H

#include <QObject>
#include <QString>
#include <QVector>

namespace fear {

/**
 * Local cache of the decrypted contacts blob. Persists the parsed
 * `contacts: [...]` array to a JSON file in the GUI config directory so
 * the sidebar can populate Contacts entries at startup without waiting
 * for an explicit ContactsDialog::refreshFromServer() round-trip.
 *
 * Written by ContactsDialog whenever it successfully decrypts a fresh
 * blob; read by ChatWindow at start and on contactsChanged() signal.
 *
 * The file is plaintext: the contacts list is local-only metadata
 * (display name + handle@server + pk fingerprint) and the user's
 * cryptographic identity already lives unencrypted in the same dir.
 * Switching to platform secret-store is left to a later phase.
 */
class ContactsStore : public QObject {
    Q_OBJECT
public:
    struct Record {
        QString name;
        QString handle;
        QString server;
        QString pk;        // base64url, no padding
        bool    verified = false;
        /**
         * Идентификатор личной комнаты, выведенный под ключом пары.
         *
         * Хранится, а не вычисляется на месте: новый вывод требует секретного
         * ключа, а половина мест, которым нужен этот идентификатор, знает
         * только открытый - им нечего делать в связке ключей ради того, чтобы
         * найти чат. Пусто у контактов, добавленных до перехода: тогда в ход
         * идёт старый вывод, а поле заполняется при первой возможности.
         */
        QString dmRoom;
    };

    static ContactsStore *instance();

    /** All cached contacts, in stored order. Empty if nothing cached yet. */
    QVector<Record> all() const { return m_cache; }

    /** Replace the cache with `records` and persist to disk. Emits
     *  contactsChanged(). */
    void replaceAll(const QVector<Record> &records);

    /** Load whatever's on disk into the in-memory cache. Returns the
     *  loaded list; subsequent all() calls return the same data. */
    QVector<Record> reload();

signals:
    void contactsChanged();

private:
    explicit ContactsStore(QObject *parent = nullptr);
    QString filePath() const;

    QVector<Record> m_cache;
};

}  // namespace fear

#endif
