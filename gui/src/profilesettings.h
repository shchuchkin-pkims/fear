#ifndef FEAR_PROFILE_SETTINGS_H
#define FEAR_PROFILE_SETTINGS_H

#include <QObject>
#include <QString>
#include <QStringList>

namespace fear {

/**
 * Mirror of Android com.fear.data.ProfileStore: persists the user's global
 * display name plus the set of server hosts where they've already claimed
 * `@displayName@host`.
 *
 * Storage: QSettings under group `profile/`. Distinct from `connect/` which
 * holds throwaway connection settings (port, room, etc).
 *
 * Phase B-1 leaves `markRegistered(...)` as a local marker. Phase B-2 will
 * tie it to a real REGISTER_HANDLE round-trip with the server.
 */
class ProfileSettings : public QObject {
    Q_OBJECT
public:
    explicit ProfileSettings(QObject *parent = nullptr);

    QString displayName() const;
    void setDisplayName(const QString &name);

    QStringList registeredServers() const;
    bool isRegistered(const QString &host) const;
    void markRegistered(const QString &host);
    void forgetRegistration(const QString &host);

    /**
     * Bind a specific handle string to a host. Used by ConnectScreen after
     * successful REGISTER_HANDLE or LOOKUP_HANDLE_BY_PK round-trip.
     * Persists the (host, handle) pair so the «@nick@host» label can be
     * shown without further server queries.
     */
    void markRegisteredAs(const QString &host, const QString &handle);

    /** Return the stored handle for `host` (lowercase nickname, no «@»);
     *  empty string when host has no registration. */
    QString handleFor(const QString &host) const;

    /** "@evgenii@fear-project.ru" — full identifier including the «@»
     *  prefix and host, or empty if the host has no registration.
     *  Falls back to displayName() when the host is registered but no
     *  explicit handle has been recorded (legacy entries). */
    QString handleAtServer(const QString &host) const;

signals:
    void displayNameChanged(const QString &name);
    void registrationsChanged();
};

}  // namespace fear

#endif
