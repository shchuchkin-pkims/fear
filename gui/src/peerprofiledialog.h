#ifndef FEAR_PEERPROFILEDIALOG_H
#define FEAR_PEERPROFILEDIALOG_H

#include <QDialog>
#include <QString>

namespace fear {

/**
 * Read-only profile of another chat participant. Opened by clicking their
 * avatar or name in a message bubble.
 *
 * Shows the wire-frame display name, the cryptographic fingerprint when we
 * have a TOFU pk for them, and an optional handle@server when they're a
 * known contact. Offers an "Open chat" action that derives the deterministic
 * DM room id from the peer's pk and asks the host to switch rooms.
 */
class PeerProfileDialog : public QDialog {
    Q_OBJECT
public:
    PeerProfileDialog(const QString &displayName,
                      const QString &pkB64,        // empty if unknown (no TOFU)
                      const QString &fingerprint,  // empty when pkB64 empty
                      const QString &handle,       // empty when not a contact
                      const QString &server,       // empty when not a contact
                      bool verified,
                      bool alreadyContact,
                      QWidget *parent = nullptr);

signals:
    /** User clicked 'Open chat' — host should derive DM room id from pkB64
     *  and reconnect to that room. Only emitted when pkB64 is non-empty. */
    void openChatRequested(const QString &pkB64);

    /**
     * Пользователь нажал «Add to contacts».
     *
     * Карточка знает открытый ключ собеседника и его отображаемое имя - для
     * записи в контакты этого достаточно. Всё остальное (поиск ника по
     * ключу, запись на диск) делает хозяин: диалог не должен ходить в сеть.
     */
    void addContactRequested(const QString &pkB64, const QString &displayName);
};

}  // namespace fear

#endif
