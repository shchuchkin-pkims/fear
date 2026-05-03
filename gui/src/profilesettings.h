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

    /** "@evgenii@fear-project.ru" or empty if name/registration missing. */
    QString handleAtServer(const QString &host) const;

signals:
    void displayNameChanged(const QString &name);
    void registrationsChanged();
};

}  // namespace fear

#endif
