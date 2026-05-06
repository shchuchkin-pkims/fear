#include "profilesettings.h"

#include <QSettings>

namespace fear {

namespace {
constexpr const char *kGroup    = "profile";
constexpr const char *kName     = "displayName";
constexpr const char *kServers  = "registeredServers";
constexpr const char *kHandles  = "handlesByHost"; /* QVariantMap host→handle */
constexpr const char *kLegacyRoot = "connect";
constexpr const char *kLegacyName = "name";
}

ProfileSettings::ProfileSettings(QObject *parent) : QObject(parent) {
    // One-shot migration from the legacy connect/name slot so existing GUI
    // installs keep their picked display name.
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    bool hasNew = s.contains(kName);
    s.endGroup();
    if (!hasNew) {
        s.beginGroup(kLegacyRoot);
        const QString legacy = s.value(kLegacyName).toString();
        s.endGroup();
        if (!legacy.isEmpty()) {
            s.beginGroup(kGroup);
            s.setValue(kName, legacy);
            s.endGroup();
        }
    }
}

QString ProfileSettings::displayName() const {
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    return s.value(kName).toString();
}

void ProfileSettings::setDisplayName(const QString &name) {
    const QString trimmed = name.trimmed();
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    s.setValue(kName, trimmed);
    s.endGroup();
    emit displayNameChanged(trimmed);
}

QStringList ProfileSettings::registeredServers() const {
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    return s.value(kServers).toStringList();
}

bool ProfileSettings::isRegistered(const QString &host) const {
    return registeredServers().contains(host);
}

void ProfileSettings::markRegistered(const QString &host) {
    auto set = registeredServers();
    if (set.contains(host)) return;
    set.append(host);
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    s.setValue(kServers, set);
    s.endGroup();
    emit registrationsChanged();
}

void ProfileSettings::forgetRegistration(const QString &host) {
    auto set = registeredServers();
    if (!set.removeAll(host)) return;
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    s.setValue(kServers, set);
    s.endGroup();
    emit registrationsChanged();
}

void ProfileSettings::markRegisteredAs(const QString &host, const QString &handle) {
    const QString h = handle.trimmed().toLower();
    if (host.isEmpty() || h.isEmpty()) return;
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    QVariantMap map = s.value(kHandles).toMap();
    map.insert(host, h);
    s.setValue(kHandles, map);
    s.endGroup();
    markRegistered(host);   /* also adds to legacy hosts list — covers UIs reading either */
}

QString ProfileSettings::handleFor(const QString &host) const {
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup(kGroup);
    return s.value(kHandles).toMap().value(host).toString();
}

QString ProfileSettings::handleAtServer(const QString &host) const {
    const QString h = handleFor(host);
    if (!h.isEmpty()) return QStringLiteral("@%1@%2").arg(h, host);
    /* Legacy fallback: no recorded handle but host is in the registered set —
     * display name was used as handle (Phase B-1 behaviour). */
    if (isRegistered(host)) {
        const QString name = displayName();
        if (!name.isEmpty()) return QStringLiteral("@%1@%2").arg(name.toLower(), host);
    }
    return QString();
}

}  // namespace fear
